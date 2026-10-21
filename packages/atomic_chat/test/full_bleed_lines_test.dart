import 'package:atomic_chat/atomic_chat.dart';
import 'package:atomic_chat/src/chat_bubbles.dart' show ChatComposerFrame;
import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart' show PointerDeviceKind;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart' show RendererBinding;
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
        if (b == Brightness.light) {
          expect(strip.color.computeLuminance(), greaterThan(0.8));
        }
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

  group('desktop: the divider is the handle', () {
    Future<ShellController> open(WidgetTester tester) async {
      tester.view.devicePixelRatio = 2;
      tester.view.physicalSize = const Size(1400, 900) * 2;
      final api = FakeApi();
      await tester.pumpWidget(app(AppShell(
        api: api,
        drive: 'did:ad:drive',
        warmPool: (_) => null,
        profile: (_) => const Scaffold(body: Text('profile page')),
        home: ChatsScreen(drive: 'did:ad:drive', api: api),
      )));
      await tester.pumpAndSettle();
      return tester
          .widget<ShellScope>(find.byType(ShellScope).first)
          .controller;
    }

    Future<void> done(WidgetTester tester) async {
      await tester.pumpWidget(const SizedBox());
      await tester.pump(const Duration(seconds: 1));
    }

    double listWidth(WidgetTester tester) =>
        tester.getSize(find.byType(ChatsScreen)).width;

    testWidgets('no grabber, a strip along the whole line, resize cursor',
        (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
      try {
        await open(tester);
        expect(find.byKey(const Key('pane-grabber')), findsNothing);
        expect(find.byTooltip('Hide list'), findsNothing);
        final strip = find.byKey(const Key('pane-resize-strip'));
        final r = tester.getRect(strip);
        expect(r.width, 8);
        expect(r.top, 0);
        expect(r.bottom, 900);
        final line = tester.getRect(find.byKey(const Key('pane-divider')));
        expect((r.center.dx - line.center.dx).abs(), lessThan(0.1));
        final mouse = TestPointer(1, PointerDeviceKind.mouse);
        await tester.sendEventToBinding(mouse.hover(Offset.zero));
        for (final y in [2.0, 450.0, 898.0]) {
          await tester
              .sendEventToBinding(mouse.hover(Offset(line.center.dx + 3, y)));
          await tester.pump();
          expect(
              RendererBinding.instance.mouseTracker
                  .debugDeviceActiveCursor(mouse.device),
              SystemMouseCursors.resizeColumn);
        }
        await done(tester);
      } finally {
        debugDefaultTargetPlatformOverride = null;
        tester.view.reset();
      }
    });

    for (final y in [2.0, 450.0, 898.0]) {
      testWidgets('a drag 3 dp from the line at y=$y resizes', (tester) async {
        debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
        try {
          await open(tester);
          final before = listWidth(tester);
          final line = tester.getRect(find.byKey(const Key('pane-divider')));
          await tester.dragFrom(
              Offset(line.center.dx + 3, y), const Offset(60, 0));
          await tester.pumpAndSettle();
          expect(listWidth(tester), closeTo(before + 60, 20));
          await done(tester);
        } finally {
          debugDefaultTargetPlatformOverride = null;
          tester.view.reset();
        }
      });
    }

    testWidgets('double click folds, again unfolds; the edge strip reveals',
        (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
      try {
        final shell = await open(tester);
        final before = listWidth(tester);
        final at = Offset(
            tester.getRect(find.byKey(const Key('pane-divider'))).center.dx,
            400);
        Future<void> doubleClick(Offset o) async {
          await tester.tapAt(o);
          await tester.pump(const Duration(milliseconds: 50));
          await tester.tapAt(o);
          await tester.pumpAndSettle();
        }

        await doubleClick(at);
        expect(shell.listCollapsed.value, isTrue);
        expect(find.byKey(const Key('pane-reveal-strip')), findsOneWidget);
        expect(tester.getRect(find.byKey(const Key('pane-reveal-strip'))).width,
            6);
        expect(find.byKey(const Key('list-toggle')), findsNothing);
        await tester.tapAt(const Offset(3, 400));
        await tester.pumpAndSettle();
        expect(shell.listCollapsed.value, isFalse);
        expect(listWidth(tester), closeTo(before, 1));
        await doubleClick(Offset(
            tester.getRect(find.byKey(const Key('pane-divider'))).center.dx,
            400));
        expect(shell.listCollapsed.value, isTrue);
        await done(tester);
      } finally {
        debugDefaultTargetPlatformOverride = null;
        tester.view.reset();
      }
    });

    testWidgets('touch (android) still has the grabber', (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      try {
        await open(tester);
        expect(find.byKey(const Key('pane-grabber')), findsOneWidget);
        expect(find.byKey(const Key('pane-resize-strip')), findsNothing);
        final grab = tester.widget<Container>(find
            .descendant(
                of: find.byKey(const Key('pane-grabber')),
                matching: find.byType(Container))
            .first);
        final border = (grab.decoration! as BoxDecoration).border!;
        expect(border.top.color.a, lessThanOrEqualTo(0.12));

        await done(tester);
      } finally {
        debugDefaultTargetPlatformOverride = null;
        tester.view.reset();
      }
    });
  });
}
