import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import 'assistant_api.dart';
import 'resource_view.dart';
import 'app_theme.dart';

/// A page that can be released once nobody needs it any more (its web view
/// dropped). Cold pages and warm pages are both released.
abstract interface class ReleasablePage {
  void release();
}

/// An embedded page that is loaded without a screen: whoever takes it
/// becomes the one the page's messages go to.
abstract class WarmPage implements EmbedPage, ReleasablePage {
  /// True once the page said it is up (`window.atomicEmbed` exists).
  bool get isReady;

  /// Completes when [isReady]; completes with an error when the load fails.
  Future<void> get whenReady;

  /// Where the page's calls go. Set by whoever holds the page.
  set onMessage(void Function(String message)? handler);

  /// Called each time the page finished loading.
  set onLoaded(VoidCallback? handler);
}

/// Makes a [WarmPage] that sends its messages to [onMessage] from the start
/// (the page asks the store for the agent while it boots).
typedef WarmPageBuilder = Future<WarmPage> Function(
    void Function(String message) onMessage);

/// The embedded renderer in a real web view. [create] starts the load; the
/// cold path of a [ResourceView] and the [WarmResourceWebView] both use it.
class WebViewEmbedPage implements WarmPage {
  WebViewEmbedPage._(this.controller);

  final WebViewController controller;
  final _ready = Completer<void>();
  final _created = Stopwatch()..start();
  void Function(String message)? _onMessage;
  VoidCallback? _onLoaded;
  bool _released = false;

  @override
  set onMessage(void Function(String message)? handler) => _onMessage = handler;

  @override
  set onLoaded(VoidCallback? handler) => _onLoaded = handler;

  @override
  bool get isReady => _ready.isCompleted && !_released;

  @override
  Future<void> get whenReady => _ready.future;

  /// Milliseconds since the load started.
  int get age => _created.elapsedMilliseconds;

  /// Loads [url] (the bundled page) into a new web view. Only pages of
  /// [url]'s own origin are ever shown in it.
  static Future<WebViewEmbedPage> create(
    Uri url, {
    void Function(String message)? onMessage,
    VoidCallback? onLoaded,
    bool pollReady = false,
  }) async {
    late final WebViewEmbedPage page;
    final origin = url.origin;
    final controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setBackgroundColor(Colors.transparent)
      ..addJavaScriptChannel('AtomicFlutter', onMessageReceived: (m) {
        // The page's own "I am up" is not a call.
        if (m.message.contains('"method":"ready"') && m.message.length < 40) {
          page._markReady();
          return;
        }
        page._onMessage?.call(m.message);
      })
      ..setOnConsoleMessage((m) => debugPrint('[embed:js] ${m.message}'))
      ..setNavigationDelegate(NavigationDelegate(
        onNavigationRequest: (request) => request.url.startsWith(origin)
            ? NavigationDecision.navigate
            : NavigationDecision.prevent,
        onPageFinished: (_) {
          debugPrint('[embed] page loaded after ${page.age} ms');
          page._onLoaded?.call();
          if (pollReady) unawaited(page._pollReady());
        },
        onWebResourceError: (e) {
          if (e.isForMainFrame ?? true) page._fail(e.description);
        },
      ));
    page = WebViewEmbedPage._(controller)
      .._onMessage = onMessage
      .._onLoaded = onLoaded;
    // Debug builds can be inspected from chrome://inspect.
    if (kDebugMode && controller.platform is AndroidWebViewController) {
      await AndroidWebViewController.enableDebugging(true);
    }
    unawaited(controller.loadRequest(url));
    return page;
  }

  void _markReady() {
    if (!_ready.isCompleted) _ready.complete();
  }

  void _fail(Object error) {
    if (!_ready.isCompleted) {
      _ready.future.ignore();
      _ready.completeError(error);
    }
  }

  /// A bundle without the `ready` message: look for `window.atomicEmbed`.
  Future<void> _pollReady() async {
    for (var i = 0; i < 100 && !_ready.isCompleted && !_released; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 200));
      try {
        final r = await controller
            .runJavaScriptReturningResult("typeof window.atomicEmbed");
        if ('$r'.contains('object')) {
          _markReady();
          return;
        }
      } catch (_) {}
    }
  }

  @override
  Future<void> runJavaScript(String script) => controller.runJavaScript(script);

  @override
  Future<Object> runJavaScriptReturningResult(String script) =>
      controller.runJavaScriptReturningResult(script);

  // The page owns every touch on it (scrolling a long menu or document must
  // not be taken over by the swipe back when a finger drifts sideways).
  @override
  Widget build() => WebViewWidget(
        controller: controller,
        gestureRecognizers: const {
          Factory<OneSequenceGestureRecognizer>(EagerGestureRecognizer.new),
        },
      );

  @override
  void release() {
    if (_released) return;
    _released = true;
    _onMessage = null;
    _onLoaded = null;
    _fail('released');
    // webview_flutter has no dispose: leave the page empty so its memory
    // (the store, the WASM) can go.
    unawaited(controller
        .setNavigationDelegate(NavigationDelegate())
        .then((_) => controller.loadHtmlString(''))
        .catchError((_) {}));
  }
}

/// Keeps one embedded page loaded and hidden (booted, Loro compiled), so
/// opening a resource is a `show(subject)` instead of a 13 MB page load.
///
/// - [warmUp] starts the spare (once; a second call does nothing).
/// - [take] hands it over when it is ready and starts the next one, so there
///   is always one spare and never more than one (memory). A page that is not
///   ready yet is left alone and [take] returns null: the caller opens cold.
/// - The spare is dropped when the app has been in the background for
///   [backgroundGrace] and warmed again on return.
///
/// Until it is taken the pool answers the page's own calls (the agent, the
/// store's init) from [api].
class WarmResourceWebView with WidgetsBindingObserver {
  WarmResourceWebView({
    required this.api,
    WarmPageBuilder? builder,
    this.rewarmDelay = const Duration(milliseconds: 600),
    this.backgroundGrace = const Duration(minutes: 5),
  }) : _builder = builder ?? _defaultBuilder {
    WidgetsBinding.instance.addObserver(this);
  }

  /// The pool for this device, or null where there is no web view the app
  /// can warm (tests on the host, desktop).
  static WarmResourceWebView? forPlatform(AssistantApi api) =>
      !kIsWeb && (Platform.isAndroid || Platform.isIOS)
          ? WarmResourceWebView(api: api)
          : null;

  final AssistantApi api;
  final WarmPageBuilder _builder;

  /// Wait before the next spare starts loading after one was taken, so the
  /// open animation of the resource is not competing with a 13 MB load.
  final Duration rewarmDelay;

  /// How long the app may stay in the background before the spare goes.
  final Duration backgroundGrace;

  WarmPage? _warm;
  bool _starting = false;
  bool _disposed = false;
  int _generation = 0;
  Timer? _rewarm;
  Timer? _trim;

  /// Spares started over the pool's life, and failures (for tests and logs).
  int started = 0;
  int failures = 0;

  /// A spare exists (loading or ready).
  bool get hasSpare => _warm != null || _starting;

  /// The spare is loaded and can be taken.
  bool get isReady => _warm?.isReady ?? false;

  static Future<WarmPage> _defaultBuilder(
      void Function(String message) onMessage) async {
    final server = await ResourceView.serverFactory();
    return WebViewEmbedPage.create(server.page,
        onMessage: onMessage, pollReady: true);
  }

  /// Starts loading the spare, unless there is one.
  void warmUp() {
    if (_disposed || hasSpare) return;
    _starting = true;
    final generation = ++_generation;
    started++;
    final clock = Stopwatch()..start();
    unawaited(() async {
      WarmPage? page;
      try {
        page = await _builder((m) => _answer(page, m));
        if (_disposed || generation != _generation) {
          page.release();
          return;
        }
        _warm = page;
        _starting = false;
        await page.whenReady;
        debugPrint('[warm] spare ready after ${clock.elapsedMilliseconds} ms');
      } catch (e) {
        failures++;
        debugPrint('[warm] spare failed: $e');
        if (generation == _generation) {
          _starting = false;
          if (identical(_warm, page)) _warm = null;
        }
        page?.release();
      }
    }());
  }

  /// The ready spare, now owned by the caller (it must [ReleasablePage.release]
  /// it), or null when there is none or it is not ready: open cold then.
  /// Starts the next spare.
  WarmPage? take() {
    final page = _warm;
    if (_disposed || page == null || !page.isReady) {
      debugPrint('[warm] not ready (spare: ${page != null}), opening cold');
      return null;
    }
    _warm = null;
    _generation++;
    _scheduleRewarm();
    return page;
  }

  void _scheduleRewarm() {
    _rewarm?.cancel();
    if (rewarmDelay == Duration.zero) {
      warmUp();
    } else {
      _rewarm = Timer(rewarmDelay, warmUp);
    }
  }

  /// Drops the spare (the app left, or memory is short).
  void release() {
    _rewarm?.cancel();
    _generation++;
    _starting = false;
    _warm?.release();
    _warm = null;
  }

  void dispose() {
    _disposed = true;
    _trim?.cancel();
    release();
    WidgetsBinding.instance.removeObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden) {
      _trim ??= Timer(backgroundGrace, () {
        _trim = null;
        debugPrint('[warm] long in the background, dropping the spare');
        release();
      });
    } else if (state == AppLifecycleState.resumed) {
      _trim?.cancel();
      _trim = null;
      warmUp();
    }
  }

  @override
  void didHaveMemoryPressure() {
    if (!_disposed) release();
  }

  /// A call from the spare while nobody holds it: read through the API like
  /// a screen would; edits cannot happen on a page nobody sees.
  Future<void> _answer(WarmPage? page, String message) async {
    if (page == null) return;
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
      final args = request['args'];
      // The page reports the saved theme as it boots, before anyone holds it.
      final answer = method == 'theme'
          ? await AppThemeMode.choose(
                  args is List && args.isNotEmpty ? '${args.first}' : '')
              .then((_) => 'true')
          : await api.embedCall(method, jsonEncode(args ?? const []));
      reply = 'true,${jsonEncode(answer)}';
    } catch (e) {
      reply = 'false,${jsonEncode('$e')}';
    }
    try {
      await page.runJavaScript('window.__atomicReply($id,$reply)');
    } catch (_) {}
  }
}
