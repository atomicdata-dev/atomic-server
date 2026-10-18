import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../theme.dart';
import 'assistant_api.dart';

/// Shows a resource in the connected server's web app.
class ResourceWebView extends StatefulWidget {
  final AssistantApi api;
  final String subject;
  final String title;

  const ResourceWebView({
    super.key,
    required this.api,
    required this.subject,
    this.title = '',
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
    try {
      _controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..loadRequest(Uri.parse(widget.api.webUrl(widget.subject)));
    } catch (e) {
      _error = e;
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppBar(
        backgroundColor: c.bgBody,
        title: Text(widget.title.isEmpty ? widget.subject : widget.title,
            maxLines: 1, overflow: TextOverflow.ellipsis),
      ),
      body: _controller == null
          ? Center(child: Text('$_error', style: TextStyle(color: c.alert)))
          : WebViewWidget(controller: _controller!),
    );
  }
}
