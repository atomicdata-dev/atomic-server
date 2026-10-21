import 'package:atomic_chat/atomic_chat.dart';
import 'package:atomic_chat/src/chat_bubbles.dart' show ChatComposerFrame;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// Desktop width: the pane divider is a quiet line on an opaque strip, and
/// full-bleed hairlines run from the pane's left edge to its right edge.
void main() {
  for (final b in Brightness.values) {
    testWidgets('${b.name}: divider is quiet over an opaque page strip',
        (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
      try {
        tester.view.devicePixelRatio = 2;
        tester.view.physicalSize = const Size(1400, 900) * 2;
        final api = FakeApi();
        await tester.pumpWidget(app(
            AppShell(
              api: api,
              drive: 'did:ad:drive',
              warmPool: (_) => null,
              profile: (_) => const Scaffold(body: Text('profile page')),
              home: ChatsScreen(drive: 'did:ad:drive', api: api),
            ),
            brightness: b));
        await tester.pumpAndSettle();
        final key = find.byKey(const Key('pane-divider'));
        final ink = tester.widget<ColoredBox>(key);
        expect(ink.color.a, lessThanOrEqualTo(0.12));
        expect(tester.getSize(key).width, lessThanOrEqualTo(1));
        // Nothing solid and dark in the path: the strip under the ink is
        // the page colour, opaque.
        final strip = tester.widget<ColoredBox>(
            find.ancestor(of: key, matching: find.byType(ColoredBox)).first);
        expect(strip.color.a, 1);
        expect(strip.color,
            (b == Brightness.light ? AppColors.light : AppColors.dark).bgBody);
        if (b == Brightness.light) expect(strip.color.computeLuminance(), greaterThan(0.8));
        final grab = tester.widget<Container>(find
            .descendant(
                of: find.byKey(const Key('pane-grabber')),
                matching: find.byType(Container))
            .first);
        final border = (grab.decoration! as BoxDecoration).border!;
        expect(border.top.color.a, lessThanOrEqualTo(0.12));
        await tester.pumpWidget(const SizedBox());
        await tester.pump(const Duration(seconds: 1));
      } finally {
        debugDefaultTargetPlatformOverride = null;
        tester.view.reset();
      }
    });

    testWidgets('${b.name}: composer top border spans the whole pane',
        (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
      try {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = const Size(1400, 900);
        await tester.pumpWidget(app(
            Scaffold(
                body: ListAndField(
                    fullWidthField: true,
                    list: const SizedBox.expand(),
                    field: ChatComposerFrame(
                        child: const TextField(key: Key('field'))))),
            brightness: b));
        await tester.pumpAndSettle();
        final frame = find.byType(ChatComposerFrame);
        final border = find
            .descendant(of: frame, matching: find.byType(DecoratedBox))
            .first;
        final rect = tester.getRect(border);
        expect(rect.left, 0);
        expect(rect.right, 1400);
        expect(rect, tester.getRect(frame));
        final deco =
            tester.widget<DecoratedBox>(border).decoration as BoxDecoration;
        expect(deco.border!.top.width, 1);
        // The row keeps to the readable column inside.
        final field = tester.getRect(find.byKey(const Key('field')));
        expect(field.width, lessThanOrEqualTo(720));
      } finally {
        debugDefaultTargetPlatformOverride = null;
        tester.view.reset();
      }
    });
  }
}
