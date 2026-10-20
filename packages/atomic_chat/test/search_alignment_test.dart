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

  for (final w in [360.0, 393.0, 412.0]) {
    for (final scale in [1.0, 1.3]) {
      for (final scope in [false, true]) {
        testWidgets('aligned at $w dp, text x$scale, scope $scope',
            (tester) async {
          await _pump(tester, Size(w, 800),
              scale: scale, scope: scope, keyboard: 300);
          final field = tester.getRect(find.byType(TextField));
          final top = tester.getRect(find
              .descendant(
                  of: find.byKey(const Key('search-top-hit')),
                  matching: find.byType(DecoratedBox))
              .first);
          final icon =
              tester.getRect(find.byIcon(Icons.description_outlined).last);
          // ignore: avoid_print
          print(
              'w=$w s=$scale scope=$scope field=${field.left}..${field.right} '
              'top=${top.left}..${top.right} icon.left=${icon.left}');
          expect(field.left, closeTo(16, 0.5));
          expect(top.left, closeTo(field.left, 0.5));
          expect(icon.left, closeTo(field.left, 0.5));
          if (scope) {
            final chip = tester.getRect(find.byKey(const Key('search-scope')));
            expect(chip.right, closeTo(w - 16, 0.5));
            expect(chip.center.dy, closeTo(field.center.dy, 0.5));
            expect(top.right, closeTo(w - 16, 0.5));
          } else {
            expect(field.right, closeTo(w - 16, 0.5));
            expect(top.right, closeTo(field.right, 0.5));
          }
        });
      }
    }
  }
}
