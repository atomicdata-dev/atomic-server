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

  testWidgets('a page opened by path fills the pane, with no frame',
      (tester) async {
    tester.view.physicalSize = const Size(2000, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    ResourceView.pageFactory = (send) => _Page(send);

    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: ResourceView(
          api: const UnimplementedApi(),
          drive: 'd',
          path: '/app/new-drive',
          call: (method, args) async => 'null'),
    ));
    await tester.pumpAndSettle();
    final page = find.byKey(const Key('the-page'));
    expect(tester.getSize(page), const Size(2000, 1000));
    expect(find.ancestor(of: page, matching: find.byType(ReadableWidth)),
        findsNothing);
    for (final e in find
        .ancestor(of: page, matching: find.byType(ConstrainedBox))
        .evaluate()) {
      expect((e.widget as ConstrainedBox).constraints.maxWidth,
          greaterThanOrEqualTo(2000));
    }
    for (final framed in [
      find.ancestor(of: page, matching: find.byType(Card)),
      find.ancestor(of: page, matching: find.byType(ClipRRect)),
      find.ancestor(of: page, matching: find.byType(Padding)),
    ]) {
      // The Scaffold's own padding wrappers are zero; none may inset the page.
      for (final e in framed.evaluate()) {
        final w = e.widget;
        if (w is Padding) {
          expect(w.padding.resolve(TextDirection.ltr), EdgeInsets.zero);
        } else {
          fail('framed by $w');
        }
      }
    }
    for (final e in find
        .ancestor(of: page, matching: find.byType(DecoratedBox))
        .evaluate()) {
      final d = (e.widget as DecoratedBox).decoration;
      if (d is BoxDecoration) {
        expect(d.border, isNull);
        expect(d.boxShadow, isNull);
        expect(d.borderRadius, isNull);
      }
    }

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
