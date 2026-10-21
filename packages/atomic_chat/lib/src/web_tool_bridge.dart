import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'assistant_api.dart';
import 'resource_view.dart';
import 'warm_resource_web_view.dart';

/// A tool the web app offers its AI chat: what the model is told of it.
class ToolDef {
  final String name;
  final String description;

  /// The JSON Schema of its input.
  final Map<String, dynamic> parameters;

  const ToolDef({
    required this.name,
    required this.description,
    required this.parameters,
  });

  /// `{name, description, parameters}`, as the web page lists its tools;
  /// null when [json] is no tool.
  static ToolDef? fromJson(Object? json) {
    if (json is! Map) return null;
    final name = json['name'];
    if (name is! String || name.isEmpty) return null;
    final parameters = json['parameters'];
    return ToolDef(
      name: name,
      description:
          json['description'] is String ? json['description'] as String : '',
      parameters: parameters is Map
          ? Map<String, dynamic>.from(parameters)
          : {'type': 'object', 'properties': <String, dynamic>{}},
    );
  }
}

/// The web app's AI tools, run by the web app: the tool list and the system
/// prompt come from the page, and every call is `{name, args}` sent to it
/// (the page runs `useAtomicTools`, so a tool does what it does in the web
/// chat; its writes go through the page's store to this device's).
abstract class WebToolBridge {
  /// The tools the model may be given.
  Future<List<ToolDef>> listTools();

  /// The web chat's system prompt for the current drive.
  Future<String> systemPrompt();

  /// Runs [name] with [args]; the result as the web chat gives it to the
  /// model (text, usually JSON). A failing tool answers `{"error": …}`; a
  /// page that cannot be reached throws.
  Future<String> run(String name, Map<String, dynamic> args);
}

/// Async calls to the page over its JavaScript channel, as the page's
/// `atomicEmbed.aiCall(id, method, args)` answers them: a message
/// `{method: 'aiResult', callId, ok, payload}` on the channel. (A script run
/// in a web view does not wait for a promise, so the answer comes back as a
/// message.)
class AiCallChannel {
  /// [runScript] runs a script in the page; [ready] completes when the page
  /// is up (calls wait for it).
  AiCallChannel({required this.runScript, Future<void>? ready})
      : _ready = ready ?? Future.value();

  final Future<void> Function(String script) runScript;
  final Future<void> _ready;
  final _pending = <int, Completer<String>>{};
  int _next = 0;

  /// Calls [method] (`tools`, `prompt` or `run`) of the page with [args]; the
  /// answer's payload. Throws what the page threw, or a [TimeoutException].
  Future<String> call(
    String method,
    List<Object?> args, {
    Duration timeout = const Duration(seconds: 60),
  }) async {
    final id = ++_next;
    final done = _pending[id] = Completer<String>();
    try {
      await _ready.timeout(timeout);
      await runScript('window.atomicEmbed.aiCall($id,${jsonEncode(method)},'
          '${jsonEncode(args)})');
      return await done.future.timeout(timeout);
    } finally {
      _pending.remove(id);
    }
  }

  /// Hands a message of the page's channel over; true when it was an answer
  /// of this channel.
  bool handleMessage(String message) {
    if (!message.contains('"aiResult"')) return false;
    final Object? json;
    try {
      json = jsonDecode(message);
    } catch (_) {
      return false;
    }
    if (json is! Map || json['method'] != 'aiResult') return false;
    final done = _pending[json['callId']];
    if (done == null || done.isCompleted) return true;
    final payload = json['payload'];
    if (json['ok'] == true) {
      done.complete(payload is String ? payload : jsonEncode(payload));
    } else {
      done.completeError(StateError('$payload'));
    }
    return true;
  }

  /// Fails every call still waiting (the page is gone).
  void close([Object error = 'closed']) {
    for (final c in _pending.values) {
      if (!c.isCompleted) c.completeError(StateError('$error'));
    }
    _pending.clear();
  }
}

/// A [WebToolBridge] over an [AiCallChannel]. The tool list is kept for the
/// session ([invalidate] when the drive changes).
class ChannelToolBridge implements WebToolBridge {
  ChannelToolBridge(this.channel);

  final AiCallChannel channel;
  Future<List<ToolDef>>? _tools;

  void invalidate() => _tools = null;

  @override
  Future<List<ToolDef>> listTools() {
    final cached = _tools;
    if (cached != null) return cached;
    final fresh = _tools = () async {
      final json = jsonDecode(await channel.call('tools', const []));
      final defs = <ToolDef>[];
      if (json is List) {
        for (final t in json) {
          final def = ToolDef.fromJson(t);
          if (def != null) defs.add(def);
        }
      }
      return defs;
    }();
    // A failure is not kept: the next run asks again.
    fresh.catchError((Object _) {
      if (identical(_tools, fresh)) _tools = null;
      return <ToolDef>[];
    });
    return fresh;
  }

  @override
  Future<String> systemPrompt() => channel.call('prompt', const []);

  @override
  Future<String> run(String name, Map<String, dynamic> args) =>
      channel.call('run', [name, jsonEncode(args)]);
}

/// The web app's tools in a hidden web view: the embedded page loaded as
/// `?ai=1&drive=…`, which shows nothing and only offers its tools. It reads
/// and writes this device's store through [api], like any embedded page. The
/// page loads on the first use.
class WebViewToolBridge implements WebToolBridge {
  WebViewToolBridge({required this.api, required this.drive});

  final AssistantApi api;

  /// The drive the tools work on (its subject); empty while unknown.
  final Future<String> Function() drive;

  ChannelToolBridge? _bridge;
  WarmPage? _page;
  bool _closed = false;

  /// Makes the page for [url]. A test swaps it.
  @visibleForTesting
  static Future<WarmPage> Function(
      Uri url, void Function(String message) onMessage)? pageFactory;

  Future<ChannelToolBridge> _open() async {
    final started = _bridge;
    if (started != null) return started;
    final driveSubject = await drive();
    final factory = pageFactory;
    final Uri url;
    if (factory == null) {
      final server = await ResourceView.serverFactory();
      url = server.page.replace(queryParameters: {
        'ai': '1',
        if (driveSubject.isNotEmpty) 'drive': driveSubject,
      });
    } else {
      url = Uri(path: '/embed.html', queryParameters: {
        'ai': '1',
        if (driveSubject.isNotEmpty) 'drive': driveSubject,
      });
    }
    late final AiCallChannel channel;
    late final WarmPage page;
    void onMessage(String message) {
      if (channel.handleMessage(message)) return;
      unawaited(_answer(page, message));
    }

    page = factory != null
        ? await factory(url, onMessage)
        : await WebViewEmbedPage.create(url,
            onMessage: onMessage, pollReady: true);
    if (_closed) {
      page.release();
      throw StateError('closed');
    }
    channel =
        AiCallChannel(runScript: page.runJavaScript, ready: page.whenReady);
    _page = page;
    return _bridge = ChannelToolBridge(channel);
  }

  /// A call of the page to the store: read or written through [api].
  Future<void> _answer(WarmPage page, String message) async {
    final Map<String, dynamic> request;
    try {
      request = jsonDecode(message) as Map<String, dynamic>;
    } catch (_) {
      return;
    }
    final id = request['id'];
    final method = request['method'];
    if (id is! int || method is! String) return;
    String reply;
    try {
      // Nothing here is shown or opened: the page's reports are acknowledged.
      final answer = const {'opened', 'theme', 'sidebarIcons', 'openNative'}
              .contains(method)
          ? 'false'
          : await api.embedCall(
              method, jsonEncode(request['args'] ?? const []));
      reply = 'true,${jsonEncode(answer)}';
    } catch (e) {
      reply = 'false,${jsonEncode('$e')}';
    }
    try {
      await page.runJavaScript('window.__atomicReply($id,$reply)');
    } catch (_) {}
  }

  @override
  Future<List<ToolDef>> listTools() async => (await _open()).listTools();

  @override
  Future<String> systemPrompt() async => (await _open()).systemPrompt();

  @override
  Future<String> run(String name, Map<String, dynamic> args) async =>
      (await _open()).run(name, args);

  /// Drops the page.
  void close() {
    _closed = true;
    _bridge?.channel.close();
    _page?.release();
    _page = null;
    _bridge = null;
  }
}
