import 'dart:math' as math;

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ToastController', () {
    test('same key is one toast and refreshes the revision', () {
      final c = ToastController();
      c.show('a', 'one');
      c.show('a', 'one');
      expect(c.toasts, hasLength(1));
      expect(c.toasts.single.revision, 1);
    });

    test('keeps at most three', () {
      final c = ToastController();
      for (final k in ['a', 'b', 'c', 'd']) {
        c.show(k, k);
      }
      expect(c.toasts.map((t) => t.key), ['b', 'c', 'd']);
    });

    test('a dismissed key stays quiet for the cool-down, resolve resets', () {
      var now = DateTime(2026);
      final c = ToastController(
          cooldown: const Duration(seconds: 30), now: () => now);
      c.show('sync', 'x');
      c.dismiss('sync');
      expect(c.show('sync', 'x'), isFalse);
      expect(c.toasts, isEmpty);
      now = now.add(const Duration(seconds: 31));
      expect(c.show('sync', 'x'), isTrue);
      c.dismiss('sync');
      c.resolve('sync');
      expect(c.show('sync', 'x'), isTrue);
    });
  });

  group('ToastPalette contrast', () {
    double lum(Color c) => c.computeLuminance();
    double ratio(Color a, Color b) {
      final l1 = math.max(lum(a), lum(b)), l2 = math.min(lum(a), lum(b));
      return (l1 + 0.05) / (l2 + 0.05);
    }

    for (final (name, pal, colors) in [
      ('light', ToastPalette.light, AppColors.light),
      ('dark', ToastPalette.dark, AppColors.dark),
    ]) {
      test('$name: text, icons and card edge are legible', () {
        expect(ToastPalette.of(colors), same(pal));
        expect(ratio(pal.text, pal.card), greaterThanOrEqualTo(4.5));
        for (final s in ToastSeverity.values) {
          // Icon (and action label) on the card.
          expect(ratio(pal.accent(s), pal.card), greaterThanOrEqualTo(4.5),
              reason: '$name ${s.name}');
        }
        // Calm card: set apart by hairline border and shadow, not colour.
        expect(pal.border.a, inInclusiveRange(0.12, 0.2));
        expect(pal.shadow.a, greaterThanOrEqualTo(0.1));
        // Never a red-filled card.
        expect(pal.card.r - pal.card.b, closeTo(0, 0.05));
        // The border edge itself is visible against the page.
        for (final page in [colors.bgBody, colors.bg1]) {
          final edge = Color.alphaBlend(pal.border, page);
          expect(ratio(edge, page), greaterThan(1.1), reason: '$name edge');
        }
      });
    }
  });

  group('ToastHost', () {
    Widget app(ToastController c, Size size) => MediaQuery(
          data: MediaQueryData(size: size),
          child: MaterialApp(
            theme: ThemeData(extensions: const [AppColors.light]),
            home: Scaffold(
              body: ToastHost(
                controller: c,
                child: const Align(
                  alignment: Alignment.topRight,
                  child: SizedBox(key: Key('content'), width: 100, height: 50),
                ),
              ),
            ),
          ),
        );

    testWidgets('top-right on a tablet, content does not move', (tester) async {
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      final c = ToastController();
      await tester.pumpWidget(app(c, const Size(1200, 800)));
      final before = tester.getRect(find.byKey(const Key('content')));

      c.show('sync:error', 'Sync timed out', actionLabel: 'Retry');
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 300));

      expect(tester.getRect(find.byKey(const Key('content'))), before);
      final card =
          tester.getRect(find.byKey(const ValueKey('toast-sync:error')));
      expect(card.right, 1200 - ToastHost.margin);
      expect(card.width, 320);
      expect(card.top, lessThan(80));
      expect(find.text('Retry'), findsOneWidget);

      // Outside the toast, touches reach the content below.
      await tester.pump(const Duration(seconds: 5));
      expect(find.text('Sync timed out'), findsNothing);
    });

    testWidgets('card has border, shadow, radius, icon and 48dp action',
        (tester) async {
      final c = ToastController();
      await tester.pumpWidget(app(c, const Size(800, 600)));
      c.show('e', 'Boom',
          severity: ToastSeverity.error, actionLabel: 'Retry');
      await tester.pump(const Duration(milliseconds: 300));
      final box = tester.widget<Container>(find
          .descendant(
              of: find.byKey(const ValueKey('toast-e')),
              matching: find.byType(Container))
          .first);
      final d = box.decoration! as BoxDecoration;
      expect(d.color, ToastPalette.light.card);
      expect(d.border, isNotNull);
      expect(d.boxShadow!.single.blurRadius, 16);
      expect(d.borderRadius, BorderRadius.circular(12));
      expect(find.byKey(const Key('toast-accent')), findsNothing);
      expect(tester.getSize(find.byKey(const Key('toast-icon'))), const Size(20, 20));
      expect(tester.getSize(find.byType(TextButton)).height,
          greaterThanOrEqualTo(48));
      await tester.pump(const Duration(seconds: 5));
    });

    testWidgets('two identical notices give one toast', (tester) async {
      final c = ToastController();
      await tester.pumpWidget(app(c, const Size(800, 600)));
      c.show('k', 'Same');
      c.show('k', 'Same');
      await tester.pump(const Duration(milliseconds: 300));
      expect(find.text('Same'), findsOneWidget);
      await tester.pump(const Duration(seconds: 5));
    });

    testWidgets('swiping right dismisses', (tester) async {
      final c = ToastController();
      await tester.pumpWidget(app(c, const Size(800, 600)));
      c.show('k', 'Swipe me');
      await tester.pump(const Duration(milliseconds: 300));
      await tester.drag(find.text('Swipe me'), const Offset(400, 0));
      await tester.pumpAndSettle();
      expect(find.text('Swipe me'), findsNothing);
      expect(c.toasts, isEmpty);
    });

    testWidgets('swiping up dismisses', (tester) async {
      final c = ToastController();
      await tester.pumpWidget(app(c, const Size(800, 600)));
      c.show('k', 'Up');
      await tester.pump(const Duration(milliseconds: 300));
      await tester.drag(find.text('Up'), const Offset(0, -60));
      await tester.pumpAndSettle();
      expect(c.toasts, isEmpty);
    });

    testWidgets('re-raising restarts the timer', (tester) async {
      final c = ToastController();
      await tester.pumpWidget(app(c, const Size(800, 600)));
      c.show('k', 'Again');
      await tester.pump(const Duration(seconds: 3));
      c.show('k', 'Again');
      await tester.pump();
      await tester.pump(const Duration(seconds: 3));
      expect(find.text('Again'), findsOneWidget);
      await tester.pump(const Duration(seconds: 2));
      await tester.pump();
      expect(find.text('Again'), findsNothing);
    });
  });
}
