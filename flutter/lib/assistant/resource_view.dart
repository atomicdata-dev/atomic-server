import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import '../atomic/atomic_client.dart';
import '../theme.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'embed_server.dart';

/// A resource as the web app draws it, without the web app around it: the
/// bundled renderer (`assets/embed`) in a web view, reading from this device's
/// store through a JavaScript channel. No server, no sign-in, no second copy of
/// the data in the page.
class ResourceView extends StatefulWidget {
  final AssistantApi api;
  final String drive;
  final String subject;
  final String title;

  /// A route of the web app to show instead of a resource (`/app/settings`).
  /// Then [subject] may be empty.
  final String? path;

  /// Where the bundled page comes from. A test swaps it for one that fails
  /// fast instead of starting a real server.
  @visibleForTesting
  static Future<EmbedServer> Function() serverFactory = EmbedServer.instance;

  /// Answers one call of the page. Replaceable in a test.
  final Future<String> Function(String method, String argsJson)? call;

  const ResourceView({
    super.key,
    required this.api,
    required this.drive,
    this.subject = '',
    this.title = '',
    this.path,
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
  ShellController? _shell;
  Route<dynamic>? _route;

  @override
  void initState() {
    super.initState();
    _start();
    // The route is known once this is in the tree.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _registerMenu();
    });
  }

  Future<void> _start() async {
    try {
      final server = await ResourceView.serverFactory();
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
        ..loadRequest(server.page.replace(queryParameters: {
          if (widget.path != null)
            'path': widget.path!
          else
            'subject': widget.subject,
        }));
      // Debug builds can be inspected from chrome://inspect.
      if (kDebugMode && controller.platform is AndroidWebViewController) {
        await AndroidWebViewController.enableDebugging(true);
      }
      if (mounted) setState(() => _controller = controller);
    } catch (e) {
      if (mounted) setState(() => _error = e);
    }
  }

  /// The bar's last button becomes this resource's "more" menu (the web app's
  /// navbar menu, drawn by the page) while this page is the one on top. A
  /// `path` page (settings) has no resource and no menu.
  void _registerMenu() {
    if (widget.path != null) return;
    final shell = ShellScope.maybeOf(context);
    final route = ModalRoute.of(context);
    if (shell == null || route == null) return;
    _shell = shell;
    _route = route;
    // Until the page has loaded there is nothing to open: the tap does
    // nothing.
    shell.registerMenu(route,
        () => _controller?.runJavaScript('window.atomicEmbed?.openMenu()'));
  }

  @override
  void dispose() {
    final route = _route;
    if (route != null) _shell?.unregisterMenu(route);
    super.dispose();
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

  /// Back goes one page back inside the page first (after an action opened
  /// its form, say), and leaves the resource when there is none.
  Future<void> _back() async {
    final controller = _controller;
    if (controller != null) {
      final went = await controller
          .runJavaScriptReturningResult('window.atomicEmbed?.back() === true');
      if ('$went' == 'true' || went == true) return;
    }
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final controller = _controller;
    return PopScope(
        canPop: false,
        onPopInvokedWithResult: (didPop, _) {
          if (!didPop) _back();
        },
        child: Scaffold(
          backgroundColor: c.bgBody,
          body: SafeArea(
            bottom: false,
            child: _error != null
                ? Center(
                    child: Text('$_error', style: TextStyle(color: c.alert)))
                : controller == null
                    ? const Center(child: CircularProgressIndicator())
                    : Stack(children: [
                        // The page owns every touch on it (scrolling a long menu
                        // or document must not be taken over by the swipe back
                        // when a finger drifts sideways); swipe back starts at the
                        // left edge.
                        WebViewWidget(
                          controller: controller,
                          gestureRecognizers: const {
                            Factory<OneSequenceGestureRecognizer>(
                                EagerGestureRecognizer.new),
                          },
                        ),
                        const Positioned(
                          left: 0,
                          top: 0,
                          bottom: 0,
                          width: 24,
                          child: _EdgeStrip(),
                        ),
                      ]),
          ),
        ));
  }
}

/// Catches touches at the screen's left edge so the swipe back works over the
/// page.
class _EdgeStrip extends StatelessWidget {
  const _EdgeStrip();

  @override
  Widget build(BuildContext context) => const Listener(
      behavior: HitTestBehavior.opaque, child: SizedBox.expand());
}
