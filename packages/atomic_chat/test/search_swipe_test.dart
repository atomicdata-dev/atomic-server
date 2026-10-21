import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// A rightward swipe on the phone's search closes it with the page following
/// the finger; a flick or past 40% completes, less springs back. A flick that
/// starts on the text field closes it too.

Widget _shell() => app(AppShell(
      api: FakeApi(recent: const [], hits: const []),
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      home: ChatsScreen(
          drive: 'did:ad:drive',
          api: FakeApi(recent: const [], hits: const [])),
    ));

Future<void> _open(WidgetTester tester) async {
  await tester.pumpWidget(_shell());
  await tester.pumpAndSettle();
  await tester.tap(find.byTooltip('Search').first);
  await tester.pumpAndSettle();
  expect(find.byType(SearchScreen), findsOneWidget);
}

bool _focused(WidgetTester tester) =>
    tester.widget<TextField>(find.byType(TextField)).focusNode!.hasFocus;

/// A quick rightward flick (the test gesture's moves carry no time stamps, so
/// they are given here).
Future<void> _flick(WidgetTester tester, Offset from) async {
  final g = await tester.startGesture(from);
  var t = Duration.zero;
  for (var i = 0; i < 5; i++) {
    t += const Duration(milliseconds: 16);
    await g.moveBy(const Offset(40, 0), timeStamp: t);
    await tester.pump(const Duration(milliseconds: 16));
  }
  await g.up(timeStamp: t);
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('a fling to the right closes, page follows the finger',
      (tester) async {
    await _open(tester);
    final g = await tester.startGesture(const Offset(200, 400));
    await g.moveBy(const Offset(60, 0));
    await tester.pump(const Duration(milliseconds: 16));
    await g.moveBy(const Offset(60, 0));
    await tester.pump(const Duration(milliseconds: 16));
    expect(tester.getTopLeft(find.byType(SearchScreen)).dx, greaterThan(40),
        reason: 'moved with the finger');
    await g.up();
    await tester.pumpAndSettle();
    await tester.flingFrom(const Offset(200, 400), const Offset(150, 0), 3000);
    await tester.pumpAndSettle();
    expect(find.byType(SearchScreen), findsNothing);
  });

  testWidgets('past 40% and slowly released closes', (tester) async {
    await _open(tester);
    final w = tester.view.physicalSize.width / tester.view.devicePixelRatio;
    final g = await tester.startGesture(const Offset(100, 400));
    for (var i = 0; i < 10; i++) {
      await g.moveBy(Offset(w * 0.06, 0));
      await tester.pump(const Duration(milliseconds: 100));
    }
    await tester.pump(const Duration(milliseconds: 400));
    await g.up();
    await tester.pumpAndSettle();
    expect(find.byType(SearchScreen), findsNothing);
  });

  testWidgets('a short drag springs back, focus unchanged', (tester) async {
    await _open(tester);
    final before = _focused(tester);
    final g = await tester.startGesture(const Offset(200, 400));
    for (var i = 0; i < 4; i++) {
      await g.moveBy(const Offset(15, 0));
      await tester.pump(const Duration(milliseconds: 100));
    }
    await tester.pump(const Duration(milliseconds: 400));
    await g.up();
    await tester.pumpAndSettle();
    expect(find.byType(SearchScreen), findsOneWidget);
    expect(tester.getTopLeft(find.byType(SearchScreen)).dx, closeTo(0, 0.01));
    expect(_focused(tester), before);
  });

  testWidgets('a vertical drag does not close', (tester) async {
    await _open(tester);
    final g = await tester.startGesture(const Offset(200, 400));
    for (var i = 0; i < 8; i++) {
      await g.moveBy(const Offset(0, -40));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await g.up();
    await tester.pumpAndSettle();
    expect(find.byType(SearchScreen), findsOneWidget);
  });

  testWidgets(
      'a rightward flick starting on the field closes; vertical does not',
      (tester) async {
    await _open(tester);
    final field = tester.getCenter(find.byType(TextField));
    final g = await tester.startGesture(field);
    for (var i = 0; i < 6; i++) {
      await g.moveBy(const Offset(0, 30));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await g.up();
    await tester.pumpAndSettle();
    expect(find.byType(SearchScreen), findsOneWidget);

    await _flick(tester, field);
    await tester.pumpAndSettle();
    expect(find.byType(SearchScreen), findsNothing);
  });

  testWidgets('a drag starting in the system back gesture inset is left alone',
      (tester) async {
    tester.view.systemGestureInsets =
        const FakeViewPadding(left: 40 * 3, right: 0, top: 0, bottom: 0);
    addTearDown(tester.view.reset);
    await _open(tester);
    final g = await tester.startGesture(const Offset(10, 400));
    for (var i = 0; i < 5; i++) {
      await g.moveBy(const Offset(60, 0));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await g.up();
    await tester.pumpAndSettle();
    expect(find.byType(SearchScreen), findsOneWidget);
  });

  testWidgets('a vertical drag scrolls the results and does not close',
      (tester) async {
    final hits = [
      for (var i = 0; i < 40; i++)
        (
          subject: 'did:ad:$i',
          title: 'Hit $i',
          className: 'Document',
          classUrl: '',
          drive: '',
          score: 1.0,
          emoji: null,
          picture: null
        ),
    ];
    await tester.pumpWidget(app(AppShell(
      api: FakeApi(recent: const [], hits: hits),
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      home: ChatsScreen(
          drive: 'did:ad:drive',
          api: FakeApi(recent: const [], hits: const [])),
    )));
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Search').first);
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'h');
    await tester.pump(const Duration(milliseconds: 250));
    await tester.pumpAndSettle();
    final list = find
        .descendant(
            of: find.byType(ListView), matching: find.byType(Scrollable))
        .first;
    final before = tester.state<ScrollableState>(list).position.pixels;
    await tester.drag(find.text('Hit 0'), const Offset(2, 300));
    await tester.pumpAndSettle();
    expect(tester.state<ScrollableState>(list).position.pixels, isNot(before));
    expect(find.byType(SearchScreen), findsOneWidget);
    expect(tester.getTopLeft(find.byType(SearchScreen)).dx, closeTo(0, 0.01));
  });
}
