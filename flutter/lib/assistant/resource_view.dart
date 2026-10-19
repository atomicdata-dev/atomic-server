import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../atomic/atomic_client.dart';
import '../theme.dart';
import 'embed_server.dart';

/// A resource as the web app draws it, without the web app around it: the
/// bundled renderer (`assets/embed`) in a web view, reading from this device's
/// store through a JavaScript channel. No server, no sign-in, no second copy of
/// the data in the page.
class ResourceView extends StatefulWidget {
  final String subject;
  final String title;

  /// Answers one call of the page. Replaceable in a test.
  final Future<String> Function(String method, String argsJson)? call;

  const ResourceView({
    super.key,
    required this.subject,
    this.title = '',
    this.call,
  });

  @override
  State<ResourceView> createState() => _ResourceViewState();
}

class _ResourceViewState extends State<ResourceView> {
  WebViewController? _controller;
  Object? _error;
  final _clock = Stopwatch()..start();
  bool _firstRead = true;

  @override
  void initState() {
    super.initState();
    _start();
  }

  Future<void> _start() async {
    try {
      final server = await EmbedServer.instance();
      final origin = server.page.origin;
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..setBackgroundColor(Colors.transparent)
        ..addJavaScriptChannel('AtomicFlutter', onMessageReceived: _onMessage)
        ..setOnConsoleMessage((m) => debugPrint('[embed:js] ${m.message}'))
        ..setNavigationDelegate(NavigationDelegate(
          // The page only ever shows its own files; nothing else is opened in it.
          onNavigationRequest: (request) => request.url.startsWith(origin)
              ? NavigationDecision.navigate
              : NavigationDecision.prevent,
          onPageFinished: (_) => debugPrint(
              '[embed] page loaded after ${_clock.elapsedMilliseconds} ms'),
        ))
        ..loadRequest(
            server.page.replace(queryParameters: {'subject': widget.subject}));
      if (mounted) setState(() => _controller = controller);
    } catch (e) {
      if (mounted) setState(() => _error = e);
    }
  }

  /// A call from the page: `{id, method, args}`. Answered with
  /// `window.__atomicReply(id, ok, payload)`.
  Future<void> _onMessage(JavaScriptMessage message) async {
    final request = jsonDecode(message.message) as Map<String, dynamic>;
    final id = request['id'] as int;
    final method = request['method'] as String;
    final started = _clock.elapsedMilliseconds;
    String reply;
    try {
      final answer = await (widget.call ?? AtomicClient.embedCall)(
          method, jsonEncode(request['args'] ?? const []));
      reply = 'true,${jsonEncode(answer)}';
      if (_firstRead && method == 'getResourcesWithSnapshots') {
        _firstRead = false;
        debugPrint('[embed] first read at $started ms, answered in '
            '${_clock.elapsedMilliseconds - started} ms');
      }
    } catch (e) {
      reply = 'false,${jsonEncode('$e')}';
    }
    if (!mounted) return;
    await _controller?.runJavaScript('window.__atomicReply($id,$reply)');
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final controller = _controller;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppBar(
        backgroundColor: c.bgBody,
        title: Text(widget.title.isEmpty ? widget.subject : widget.title,
            maxLines: 1, overflow: TextOverflow.ellipsis),
      ),
      body: _error != null
          ? Center(child: Text('$_error', style: TextStyle(color: c.alert)))
          : controller == null
              ? const Center(child: CircularProgressIndicator())
              : WebViewWidget(controller: controller),
    );
  }
}
