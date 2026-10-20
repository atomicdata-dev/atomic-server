import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

class _Page implements EmbedPage {
  _Page(this.send);
  final void Function(String message) send;

  @override
  Future<void> runJavaScript(String script) async {}

  @override
  Future<Object> runJavaScriptReturningResult(String script) async => false;

  @override
  Widget build() => const SizedBox.expand(key: Key('the-page'));
}

void main() {
  tearDown(() => ResourceView.pageFactory = null);

  testWidgets('a form page is a reading column, the resource it made is not',
      (tester) async {
    tester.view.physicalSize = const Size(2000, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    late _Page page;
    ResourceView.pageFactory = (send) => page = _Page(send);

    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: ResourceView(
          api: const UnimplementedApi(),
          drive: 'd',
          path: '/app/new',
          call: (method, args) async => 'null'),
    ));
    await tester.pumpAndSettle();
    expect(tester.getSize(find.byKey(const Key('the-page'))).width, 720);

    page.send(jsonEncode({
      'id': 1,
      'method': 'opened',
      'args': ['did:ad:made'],
    }));
    await tester.pumpAndSettle();
    expect(tester.getSize(find.byKey(const Key('the-page'))).width, 2000);

    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 6));
  });

  test('the list pane and its divider end on a whole physical pixel', () {
    const dpr = 2.125;
    for (final w in [304.0, 320.0, 400.0, 411.3, 520.0]) {
      final px = (snapPaneWidth(w, dpr) + 1) * dpr;
      expect((px - px.round()).abs(), lessThan(1e-9), reason: '$w');
      expect((snapPaneWidth(w, dpr) - w).abs(), lessThan(0.5 / dpr + 1e-9));
    }
    expect(snapPaneWidth(0, dpr), 0);
    expect(snapPaneWidth(400, 1), 400);
  });
}
