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
      picture: null,
    );

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:home',
      home: ChatsScreen(drive: 'did:ad:home', api: api),
    ));

ShellController _controller(WidgetTester tester) =>
    tester.widget<ShellScope>(find.byType(ShellScope)).controller;

Future<TestGesture> _holdHome(WidgetTester tester) async {
  final gesture = await tester.startGesture(tester.getCenter(
      find.byWidgetPredicate((w) => w is HoldFan && w.tooltip == 'Home')));
  await tester.pump(const Duration(milliseconds: 400));
  await tester.pump(const Duration(milliseconds: 200));
  return gesture;
}

void main() {
  late FakeApi api;

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ResourceView.serverFactory = () async => throw 'no server in a test';
    api = FakeApi(
      driveList: const [
        (subject: 'did:ad:home', name: 'Home', emoji: null, picture: null),
        (subject: 'did:ad:work', name: 'Work', emoji: null, picture: null),
      ],
      favoriteList: [_r('did:ad:fav', 'Starred doc')],
    );
  });

  testWidgets('the Home menu lists every section, empty ones muted',
      (tester) async {
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    final gesture = await _holdHome(tester);
    final entries = _controller(tester).homeSections.value;
    expect([for (final e in entries) e.section], HomeSection.values);
    expect([for (final e in entries) e.hidden], everyElement(isFalse));
    expect(entries.firstWhere((e) => e.section == HomeSection.drives).count, 2);
    expect(
        entries.firstWhere((e) => e.section == HomeSection.favorites).count, 1);
    expect(
        entries.firstWhere((e) => e.section == HomeSection.messages).count, 0);
    for (final s in HomeSection.values) {
      expect(find.text(s.title), findsWidgets, reason: s.title);
    }
    // The empty ones say 0, the others nothing.
    expect(find.byKey(const Key('hold-fan-hint')), findsWidgets);
    expect(find.text('0'), findsWidgets);
    await gesture.up();
    await tester.pumpAndSettle();
  });

  testWidgets(
      'the Home menu keeps hidden sections at their saved places, marked',
      (tester) async {
    SharedPreferences.setMockInitialValues({
      homeOrderKey: ['messages', 'favorites', 'drives'],
      homeHiddenKey: ['drives'],
    });
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    final entries = _controller(tester).homeSections.value;
    expect([for (final e in entries.take(3)) e.section],
        [HomeSection.messages, HomeSection.favorites, HomeSection.drives]);
    expect(entries.length, HomeSection.values.length);
    final drives = entries.firstWhere((e) => e.section == HomeSection.drives);
    expect(drives.hidden, isTrue);
    expect(entries.where((e) => e.hidden).length, 1);
    final gesture = await _holdHome(tester);
    expect(find.text('hidden'), findsOneWidget);
    await gesture.up();
    await tester.pumpAndSettle();
  });

  testWidgets('picking an empty section opens its page with the empty state',
      (tester) async {
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    final gesture = await _holdHome(tester);
    await gesture.moveTo(tester.getCenter(find.text('Messages').last));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    expect(_controller(tester).topKind, ShellPage.listOf('messages'));
    expect(find.byKey(const Key('list-empty')), findsOneWidget);
    expect(find.text('No messages yet'), findsWidgets);
  });

  testWidgets('every empty section opens a page that says so', (tester) async {
    const expected = {
      HomeSection.notifications: 'No notifications',
      HomeSection.chats: 'No chats yet',
      HomeSection.messages: 'No messages yet',
    };
    for (final e in expected.entries) {
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      _controller(tester).openHomeSection(e.key);
      await tester.pumpAndSettle();
      expect(_controller(tester).topKind, ShellPage.listOf(e.key.name));
      expect(find.byKey(const Key('list-empty')), findsOneWidget,
          reason: e.key.name);
      expect(find.text(e.value), findsWidgets, reason: e.key.name);
      await tester.pumpWidget(const SizedBox());
    }
  });

  testWidgets('picking a hidden section opens its page and keeps it hidden',
      (tester) async {
    SharedPreferences.setMockInitialValues({
      homeHiddenKey: ['drives'],
    });
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    expect(find.text('Work'), findsNothing);
    _controller(tester).openHomeSection(HomeSection.drives);
    await tester.pumpAndSettle();
    expect(_controller(tester).topKind, ShellPage.listOf('drives'));
    expect(find.text('Work'), findsOneWidget);
    expect((await SharedPreferences.getInstance()).getStringList(homeHiddenKey),
        ['drives'],
        reason: 'only the dialog writes the layout');
    // Still not on the home.
    _controller(tester).goHome();
    await tester.pumpAndSettle();
    expect(find.text('Work'), findsNothing);
  });

  testWidgets('on a tablet the Activity is in the menu too', (tester) async {
    tester.view.devicePixelRatio = 2;
    tester.view.physicalSize = const Size(1280, 800) * 2;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    final entries = _controller(tester).homeSections.value;
    expect(entries.map((e) => e.section), contains(HomeSection.activity));
    _controller(tester).openHomeSection(HomeSection.activity);
    await tester.pumpAndSettle();
    expect(_controller(tester).topKind, ShellPage.listOf('activity'));
  });

  testWidgets('a tablet gets the sections dialog centred, at most 420 wide',
      (tester) async {
    tester.view.physicalSize = const Size(1600, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    await tester.longPress(find.text('Favorites'));
    await tester.pumpAndSettle();
    expect(find.byType(Dialog), findsOneWidget);
    expect(tester.getSize(find.byType(ReorderableListView)).width,
        lessThanOrEqualTo(420));
  });

  testWidgets('a tap on Home goes home', (tester) async {
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    _controller(tester).openPage<void>(
        ShellPage.settings, (_) => const Scaffold(body: Text('a page')));
    await tester.pump(const Duration(milliseconds: 600));
    expect(_controller(tester).atHome, isFalse);
    await tester.tap(find.byTooltip('Home'));
    await tester.pumpAndSettle();
    expect(_controller(tester).atHome, isTrue);
    expect(find.text('Starred doc'), findsOneWidget);
  });

  testWidgets('hold, drag and release on a section opens its full list',
      (tester) async {
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    // Away from the home first: the pick brings it back.
    _controller(tester).openPage<void>(
        ShellPage.settings, (_) => const Scaffold(body: Text('a page')));
    await tester.pump(const Duration(milliseconds: 600));
    final gesture = await _holdHome(tester);
    await gesture.moveTo(tester.getCenter(find.text('Favorites').last));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    final shell = _controller(tester);
    expect(shell.topKind, ShellPage.listOf('favorites'));
    expect(find.text('Favorites'), findsWidgets);
  });

  testWidgets('a folded section is unfolded by the pick', (tester) async {
    SharedPreferences.setMockInitialValues({
      homeCollapsedKey: ['favorites'],
    });
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    expect(find.text('Starred doc'), findsNothing);
    final gesture = await _holdHome(tester);
    await gesture.moveTo(tester.getCenter(find.text('Favorites').last));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    expect(_controller(tester).topKind, ShellPage.listOf('favorites'));
    expect(
        (await SharedPreferences.getInstance()).getStringList(homeCollapsedKey),
        isEmpty);
  });

  testWidgets('releasing outside the menu cancels', (tester) async {
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    final gesture = await _holdHome(tester);
    await gesture.moveTo(const Offset(5, 5));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    expect(_controller(tester).topKind, ShellPage.home);
    expect(find.byKey(const ValueKey('hold-fan-menu')), findsNothing);
  });

  testWidgets('on a tablet the pick opens the list in the detail pane',
      (tester) async {
    tester.view.devicePixelRatio = 2;
    tester.view.physicalSize = const Size(1280, 800) * 2;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    expect(_controller(tester).layout, ShellLayout.split);
    final gesture = await _holdHome(tester);
    await gesture.moveTo(tester.getCenter(find.text('Drives').last));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    expect(_controller(tester).topKind, ShellPage.listOf('drives'));
  });
}
