import 'dart:typed_data';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:webview_flutter/webview_flutter.dart';

import 'unimplemented_api.dart';

class _Controller implements WebViewController {
  _Controller(this.log);
  final List<String> log;

  @override
  Future<void> setJavaScriptMode(JavaScriptMode mode) async {}
  @override
  Future<void> setNavigationDelegate(NavigationDelegate delegate) async {}
  @override
  Future<void> loadRequest(Uri uri,
      {LoadRequestMethod method = LoadRequestMethod.get,
      Map<String, String> headers = const {},
      Uint8List? body}) async {
    log.add('load ${uri.host}');
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  testWidgets('cookies are set before the page loads', (tester) async {
    final log = <String>[];
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.dark]),
      home: ResourceWebView(
        api: const UnimplementedApi(),
        subject: 'https://portal.example',
        url: 'https://portal.example',
        cookies: const [
          WebViewCookie(
              name: 'session_token', value: 'abc', domain: 'portal.example'),
        ],
        setCookie: (c) async => log.add('cookie ${c.name}=${c.value}'),
        controllerFactory: () => _Controller(log),
        viewBuilder: (_) => const Text('view'),
      ),
    ));
    await tester.pumpAndSettle();
    expect(log, ['cookie session_token=abc', 'load portal.example']);
    expect(find.text('view'), findsOneWidget);
  });
}
