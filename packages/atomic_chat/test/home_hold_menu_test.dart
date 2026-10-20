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
        (subject: 'did:ad:home', name: 'Home', emoji: null),
        (subject: 'did:ad:work', name: 'Work', emoji: null),
      ],
      favoriteList: [_r('did:ad:fav', 'Starred doc')],
    );
  });

  testWidgets('the Home menu lists only the sections that have rows',
      (tester) async {
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    final gesture = await _holdHome(tester);
    expect(_controller(tester).homeSections.value,
        [HomeSection.drives, HomeSection.favorites]);
    expect(find.text('Drives'), findsWidgets);
    expect(find.text('Favorites'), findsWidgets);
    expect(find.text('Messages'), findsNothing);
    await gesture.up();
    await tester.pumpAndSettle();
  });

  testWidgets('a tap on Home goes home', (tester) async {
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Settings'));
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
    await tester.tap(find.byTooltip('Settings'));
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
      homeCollapsedKey: ['drives'],
    });
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    expect(find.text('Work'), findsNothing);
    final gesture = await _holdHome(tester);
    await gesture.moveTo(tester.getCenter(find.text('Drives').last));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    expect(_controller(tester).topKind, ShellPage.listOf('drives'));
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
