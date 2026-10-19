import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/material.dart';
import 'app_top_bar.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:webview_flutter/webview_flutter.dart';

import 'assistant_api.dart';

/// Shows a resource in the connected server's web app, or any page [url].
class ResourceWebView extends StatefulWidget {
  final AssistantApi api;
  final String subject;
  final String title;
  final String? url;

  /// Cookies set before the page loads, e.g. a portal `session_token` so the
  /// page opens already signed in.
  final List<WebViewCookie> cookies;

  /// Keep navigation to [url]'s own host in the view and send every other
  /// page to the system browser.
  final bool keepOnHost;

  /// Test seams: how cookies are stored, the controller made, and the view
  /// shown for it.
  @visibleForTesting
  final Future<void> Function(WebViewCookie cookie)? setCookie;
  @visibleForTesting
  final WebViewController Function()? controllerFactory;
  @visibleForTesting
  final Widget Function(WebViewController controller)? viewBuilder;

  const ResourceWebView({
    super.key,
    required this.api,
    required this.subject,
    this.title = '',
    this.url,
    this.cookies = const [],
    this.keepOnHost = false,
    this.setCookie,
    this.controllerFactory,
    this.viewBuilder,
  });

  @override
  State<ResourceWebView> createState() => _ResourceWebViewState();
}

class _ResourceWebViewState extends State<ResourceWebView> {
  WebViewController? _controller;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _start();
  }

  Future<void> _start() async {
    try {
      final target = Uri.parse(widget.url ?? widget.api.webUrl(widget.subject));
      final controller = (widget.controllerFactory ?? WebViewController.new)()
        ..setJavaScriptMode(JavaScriptMode.unrestricted);
      if (widget.keepOnHost) {
        controller.setNavigationDelegate(NavigationDelegate(
          onNavigationRequest: (request) {
            final next = Uri.tryParse(request.url);
            final web = next != null && next.scheme.startsWith('http');
            if (!request.isMainFrame || !web || next.host == target.host) {
              return NavigationDecision.navigate;
            }
            launchUrl(next, mode: LaunchMode.externalApplication);
            return NavigationDecision.prevent;
          },
        ));
      }
      // Cookies first, so the very first request is already signed in.
      final set = widget.setCookie ?? WebViewCookieManager().setCookie;
      for (final cookie in widget.cookies) {
        await set(cookie);
      }
      await controller.loadRequest(target);
      if (mounted) setState(() => _controller = controller);
    } catch (e) {
      if (mounted) setState(() => _error = e);
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppTopBar(
          title: widget.title.isEmpty ? widget.subject : widget.title),
      body: _error != null
          ? Center(
              child: Text('$_error', style: TextStyle(color: c.alert)),
            )
          : _controller == null
              ? const Center(child: CircularProgressIndicator())
              : (widget.viewBuilder ??
                  (c) => WebViewWidget(controller: c))(_controller!),
    );
  }
}
