import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// The phone search lines up: the field, the scope chip and the result rows
/// share one 16 dp gutter at both sides, and the chip sits on the field's
/// centre line.

SearchHit _hit(String s, String t) => (
      subject: s,
      title: t,
      className: 'document-v2',
      drive: 'did:ad:drive',
      score: 1.0,
      emoji: null
    );

Future<void> _pump(WidgetTester tester, Size size,
    {double scale = 1, bool scope = false, double keyboard = 0}) async {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = size;
  tester.view.viewInsets = FakeViewPadding(bottom: keyboard);
  tester.view.padding = const FakeViewPadding(top: 40);
  addTearDown(tester.view.reset);
  final api =
      FakeApi(hits: [_hit('did:ad:a', 'Alpha'), _hit('did:ad:b', 'Beta')]);
  await tester.pumpWidget(MediaQuery(
    data: MediaQueryData(
        size: size,
        textScaler: TextScaler.linear(scale),
        viewInsets: EdgeInsets.only(bottom: keyboard),
        padding: const EdgeInsets.only(top: 40)),
    child: app(SearchScreen(
        drive: 'did:ad:drive',
        api: api,
        scopeDrive: scope ? 'did:ad:drive' : null)),
  ));
  await tester.pumpAndSettle();
  await tester.enterText(find.byType(TextField), 'a');
  await tester.pump(const Duration(milliseconds: 100));
  await tester.pumpAndSettle();
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));
  clearTests();

  for (final w in [360.0, 393.0, 412.0]) {
    for (final scale in [1.0, 1.3]) {
      for (final scope in [false, true]) {
        testWidgets('aligned at $w dp, text x$scale, scope $scope',
            (tester) async {
          await _pump(tester, Size(w, 800),
              scale: scale, scope: scope, keyboard: 300);
          final field = tester.getRect(find.byType(TextField));
          final topFinder = find.byKey(const Key('search-top-hit'));
          final top = tester.getRect(topFinder);
          final mat = tester.widget<Material>(topFinder);
          expect(mat.color, isNotNull);
          expect(mat.shape, isNull); // no outline of any kind
          expect(mat.borderRadius, BorderRadius.circular(12));
          final icons = find.byIcon(Icons.description_outlined);
          expect(icons, findsAtLeastNWidgets(2));
          final lefts = [
            for (var i = 0; i < 2; i++) tester.getRect(icons.at(i)).left
          ];
          final titles = [
            for (final t in ['Alpha', 'Beta']) tester.getRect(find.text(t)).left
          ];
          expect(lefts[0], closeTo(lefts[1], 0.01));
          expect(titles[0], closeTo(titles[1], 0.01));
          final rows = [
            for (final t in ['Alpha', 'Beta'])
              tester.getRect(find.ancestor(
                  of: find.text(t), matching: find.byType(ListTile)))
          ];
          expect(rows[0].height, closeTo(rows[1].height, 0.01));
          expect(rows[0].width, closeTo(rows[1].width, 0.01));
          // The highlight is exactly the row's rect.
          final topRow = rows[0].top < rows[1].top ? rows[0] : rows[1];
          final topRowReal = rows.firstWhere(
              (r) => r.top >= top.top - 0.5 && r.bottom <= top.bottom + 0.5);
          expect(top, topRowReal);
          expect(topRow.height, inInclusiveRange(48, 80));
          final icon = tester.getRect(icons.last);
          // ignore: avoid_print
          print(
              'w=$w s=$scale scope=$scope field=${field.left}..${field.right} '
              'top=${top.left}..${top.right} icon.left=${icon.left}');
          expect(field.left, closeTo(16, 0.5));
          expect(top.left, closeTo(0, 0.5)); // full-width highlight
          expect(top.right, closeTo(w, 0.5));
          expect(icon.left, closeTo(field.left, 0.5));
          if (scope) {
            final chip = tester.getRect(find.byKey(const Key('search-scope')));
            expect(chip.right, closeTo(w - 16, 0.5));
            expect(chip.center.dy, closeTo(field.center.dy, 0.5));
          } else {
            expect(field.right, closeTo(w - 16, 0.5));
          }
        });
      }
    }
  }
}

void clearTests() {
  group('clear button', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));
    testWidgets('only with text; clears and keeps focus', (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(393, 800);
      addTearDown(tester.view.reset);
      await tester.pumpWidget(app(SearchScreen(
          drive: 'did:ad:drive',
          api: FakeApi(hits: [_hit('did:ad:a', 'Alpha')]))));
      await tester.pumpAndSettle();
      final btn = find.byKey(const Key('search-clear'));
      final before = tester.getRect(find.byType(TextField));
      expect(
          tester
              .widget<AnimatedOpacity>(find
                  .ancestor(of: btn, matching: find.byType(AnimatedOpacity))
                  .first)
              .opacity,
          0);
      await tester.enterText(find.byType(TextField), 'a');
      await tester.pumpAndSettle();
      expect(
          tester
              .widget<AnimatedOpacity>(find
                  .ancestor(of: btn, matching: find.byType(AnimatedOpacity))
                  .first)
              .opacity,
          1);
      expect(tester.getRect(find.byType(TextField)), before);
      expect(find.bySemanticsLabel('Clear search'), findsWidgets);
      await tester.tap(btn);
      await tester.pumpAndSettle();
      expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
          '');
      expect(
          tester.widget<TextField>(find.byType(TextField)).focusNode!.hasFocus,
          isTrue);
      expect(find.text('Alpha'), findsNothing);
      expect(tester.getRect(find.byType(TextField)), before);
    });
    testWidgets('palette card: same cross, field does not move',
        (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(1000, 800);
      addTearDown(tester.view.reset);
      await tester.pumpWidget(app(SearchScreen(
          drive: 'did:ad:drive',
          palette: true,
          api: FakeApi(hits: [_hit('did:ad:a', 'Alpha')]))));
      await tester.pumpAndSettle();
      final before = tester.getRect(find.byType(TextField));
      expect(find.byKey(const Key('search-clear')), findsOneWidget);
      await tester.enterText(find.byType(TextField), 'a');
      await tester.pumpAndSettle();
      expect(tester.getRect(find.byType(TextField)), before);
      await tester.tap(find.byKey(const Key('search-clear')));
      await tester.pumpAndSettle();
      expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
          '');
      expect(find.text('Alpha'), findsNothing);
    });
  });
}
