import 'dart:ui' show AccessibilityFeatures;

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// Search opens with a short fade (+ rise, + scale) and closes the same way
/// reversed; reduced motion shows it at once.

Widget _shell() => app(AppShell(
      api: FakeApi(recent: const [], hits: const []),
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      home: ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(recent: const [], hits: const [])),
    ));

Finder _button() => find.byTooltip('Search').first;

/// The product of every fade above [f].
double _opacity(WidgetTester tester, Finder f) {
  var o = 1.0;
  for (final w in tester.widgetList<FadeTransition>(
      find.ancestor(of: f, matching: find.byType(FadeTransition)))) {
    o *= w.opacity.value;
  }
  return o;
}

class _Reduced implements AccessibilityFeatures {
  const _Reduced();
  @override
  bool get disableAnimations => true;
  @override
  dynamic noSuchMethod(Invocation i) => false;
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  group('phone', () {
    testWidgets('fades in, is focused after, back leaves nothing',
        (tester) async {
      await tester.pumpWidget(_shell());
      await tester.pumpAndSettle();
      await tester.tap(_button());
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 60));
      final mid = _opacity(tester, find.byType(TextField));
      expect(mid, greaterThan(0));
      expect(mid, lessThan(1));
      // The focus is asked for at the start, not at the end.
      expect(FocusManager.instance.primaryFocus?.context, isNotNull);

      await tester.pumpAndSettle();
      expect(_opacity(tester, find.byType(TextField)), 1);
      expect(tester.widget<TextField>(find.byType(TextField)).focusNode!.hasFocus,
          isTrue);

      await tester.pageBack();
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 60));
      expect(find.byType(SearchScreen), findsOneWidget, reason: 'still going');
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen), findsNothing);
    });

    testWidgets('reduced motion: there at once', (tester) async {
      tester.platformDispatcher.accessibilityFeaturesTestValue =
          const _Reduced();
      addTearDown(
          tester.platformDispatcher.clearAccessibilityFeaturesTestValue);
      await tester.pumpWidget(_shell());
      await tester.pumpAndSettle();
      await tester.tap(_button());
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 1));
      expect(find.byType(SearchScreen), findsOneWidget);
      expect(_opacity(tester, find.byType(TextField)), 1);
    });
  });

  group('tablet palette', () {
    void landscape(WidgetTester tester) {
      tester.view.physicalSize = const Size(1280, 800) * 2;
      tester.view.devicePixelRatio = 2;
      addTearDown(tester.view.reset);
    }

    testWidgets('card fades in, focused, scrim tap closes', (tester) async {
      landscape(tester);
      await tester.pumpWidget(_shell());
      await tester.pumpAndSettle();
      await tester.tap(_button());
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 60));
      final card = find.byKey(const Key('search-palette'));
      final mid = _opacity(tester, card);
      expect(mid, greaterThan(0));
      expect(mid, lessThan(1));

      await tester.pumpAndSettle();
      expect(_opacity(tester, card), 1);
      expect(
          tester
              .widget<TextField>(find.descendant(
                  of: card, matching: find.byType(TextField)))
              .focusNode!
              .hasFocus,
          isTrue);

      await tester.tapAt(const Offset(1270, 790));
      await tester.pump(const Duration(milliseconds: 40));
      expect(card, findsOneWidget, reason: 'leaving, not gone');
      await tester.pumpAndSettle();
      expect(card, findsNothing);
    });

    testWidgets('reduced motion: there at once', (tester) async {
      landscape(tester);
      tester.platformDispatcher.accessibilityFeaturesTestValue =
          const _Reduced();
      addTearDown(
          tester.platformDispatcher.clearAccessibilityFeaturesTestValue);
      await tester.pumpWidget(_shell());
      await tester.pumpAndSettle();
      await tester.tap(_button());
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 1));
      final card = find.byKey(const Key('search-palette'));
      expect(card, findsOneWidget);
      expect(_opacity(tester, card), 1);
    });
  });
}
