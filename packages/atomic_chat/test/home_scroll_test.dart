import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

RecentResource _r(String subject, String title) => (
      subject: subject,
      title: title,
      className: 'document-v2',
      openedAt: 1,
      emoji: null,
    );

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:home',
      home: ChatsScreen(drive: 'did:ad:home', api: api),
    ));

ShellController _controller(WidgetTester tester) =>
    tester.widget<ShellScope>(find.byType(ShellScope)).controller;

Finder _heading(String name) => find.byKey(ValueKey('section-heading-$name'));

double _offset(WidgetTester tester) => tester
    .state<ScrollableState>(find.byType(Scrollable).first)
    .position
    .pixels;

void main() {
  late FakeApi api;

  setUp(() {
    ResourceView.serverFactory = () async => throw 'no server in a test';
    api = FakeApi(
      driveList: [
        for (var i = 0; i < 7; i++)
          (subject: 'did:ad:d$i', name: 'Drive $i', emoji: null),
      ],
      favoriteList: [for (var i = 0; i < 7; i++) _r('did:ad:f$i', 'Fav $i')],
    );
  });

  Future<void> phone(WidgetTester tester, {double h = 480}) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = Size(400, h);
    addTearDown(tester.view.reset);
  }

  testWidgets('opening a lower section scrolls its heading to the top',
      (tester) async {
    SharedPreferences.setMockInitialValues({
      homeCollapsedKey: ['favorites'],
    });
    await phone(tester);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    expect(_offset(tester), 0);
    final listTop = tester.getTopLeft(find.byType(ListView).first).dy;
    await tester.scrollUntilVisible(_heading('favorites'), 100,
        scrollable: find.byType(Scrollable).first);
    await tester.pumpAndSettle();
    final before = _offset(tester);
    await tester.tap(_heading('favorites'));
    await tester.pumpAndSettle();
    expect(_offset(tester), greaterThanOrEqualTo(before));
    final y = tester.getTopLeft(_heading('favorites')).dy - listTop;
    expect(y, lessThanOrEqualTo(8 + 16));
    expect(find.text('Fav 0'), findsOneWidget);
  });

  testWidgets('a section that already fits does not move the list',
      (tester) async {
    SharedPreferences.setMockInitialValues({
      homeCollapsedKey: ['drives', 'favorites'],
    });
    await phone(tester, h: 900);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    await tester.tap(_heading('drives'));
    await tester.pumpAndSettle();
    expect(find.text('Drive 0'), findsOneWidget);
    expect(_offset(tester), 0);
  });

  testWidgets('collapsing does not scroll', (tester) async {
    SharedPreferences.setMockInitialValues({});
    await phone(tester);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(_heading('favorites'), 100,
        scrollable: find.byType(Scrollable).first);
    await tester.pumpAndSettle();
    final before = _offset(tester);
    await tester.tap(_heading('favorites'));
    await tester.pumpAndSettle();
    expect(find.text('Fav 0'), findsNothing);
    // Only the clamp of a shorter list may move it, never a reveal.
    expect(_offset(tester), lessThanOrEqualTo(before));
  });

  testWidgets('the hold menu path lands the same way', (tester) async {
    SharedPreferences.setMockInitialValues({
      homeCollapsedKey: ['favorites'],
    });
    await phone(tester);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    final listTop = tester.getTopLeft(find.byType(ListView).first).dy;
    _controller(tester).openHomeSection(HomeSection.favorites);
    await tester.pumpAndSettle();
    // The pick opens the full list on top; going back shows the home.
    expect(_controller(tester).topKind, ShellPage.listOf('favorites'));
    _controller(tester).goHome();
    await tester.pumpAndSettle();
    final y = tester.getTopLeft(_heading('favorites')).dy - listTop;
    expect(y, lessThanOrEqualTo(8 + 16));
  });

  group('a heading is one tap target', () {
    testWidgets('the far right, the title and a hold', (tester) async {
      SharedPreferences.setMockInitialValues({});
      await phone(tester, h: 800);
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      final heading = _heading('favorites');
      expect(tester.getSize(heading).width, 400);
      var r = tester.getRect(heading);
      expect(find.text('Fav 0'), findsOneWidget);
      // Empty space right of the title, left of the chevron.
      await tester.tapAt(Offset(r.right - 80, r.center.dy));
      await tester.pumpAndSettle();
      expect(find.text('Fav 0'), findsNothing);
      await tester.tap(find.text('Favorites'));
      await tester.pumpAndSettle();
      expect(find.text('Fav 0'), findsOneWidget);
      // Semantics.
      final h = tester.ensureSemantics();
      r = tester.getRect(heading);
      final node =
          tester.getSemantics(find.bySemanticsLabel('Favorites, expanded'));
      final data = node.getSemanticsData();
      expect(data.flagsCollection.isButton, isTrue);
      expect(data.flagsCollection.isExpanded.toString(), contains('isTrue'));
      await tester.tapAt(Offset(r.right - 80, r.center.dy));
      await tester.pumpAndSettle();
      expect(find.bySemanticsLabel('Favorites, collapsed'), findsOneWidget);
      h.dispose();
      r = tester.getRect(heading);
      // A hold opens the dialog.
      await tester.longPressAt(Offset(r.right - 80, r.center.dy));
      await tester.pumpAndSettle();
      expect(find.text('Home sections'), findsOneWidget);
    });
  });
}
