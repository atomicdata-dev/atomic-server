import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

NotificationItem _n(int i, {bool read = false}) => (
      subject: 'n$i',
      title: 'Note $i',
      body: 'Body $i',
      about: 'did:ad:x$i',
      kind: 'chat',
      occurredAt: DateTime.now().millisecondsSinceEpoch - 60000,
      read: read
    );

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      home: ChatsScreen(drive: 'did:ad:drive', api: api),
    ));

ShellController _controller(WidgetTester tester) =>
    tester.widget<ShellScope>(find.byType(ShellScope).first).controller;

void _tablet(WidgetTester tester) {
  tester.view.devicePixelRatio = 2;
  tester.view.physicalSize = const Size(1280, 800) * 2;
  addTearDown(tester.view.reset);
}

Future<void> _done(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox());
  await tester.pump(const Duration(seconds: 1));
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ResourceView.serverFactory = () async => throw 'no server in a test';
  });

  testWidgets('the tablet sidebar shows Notifications with an unread badge',
      (tester) async {
    _tablet(tester);
    final api = FakeApi(
        notificationList: [_n(1), _n(2), _n(3, read: true), _n(4, read: true)]);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    expect(_controller(tester).layout, ShellLayout.split);
    expect(find.text('Notifications'), findsOneWidget);
    expect(
        find.descendant(
            of: find.byKey(const ValueKey('section-heading-notifications')),
            matching: find.text('2')),
        findsOneWidget);
    expect(find.text('Note 1'), findsOneWidget);
    expect(find.text('Body 1'), findsOneWidget);
    expect(find.byKey(const Key('notification-unread')), findsNWidgets(2));
    await _done(tester);
  });

  testWidgets('the badge caps at 99+', (tester) async {
    final api =
        FakeApi(notificationList: [for (var i = 0; i < 120; i++) _n(i)]);
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();
    expect(find.text('99+'), findsOneWidget);
  });

  testWidgets('no notifications: no section and no badge on the tablet',
      (tester) async {
    _tablet(tester);
    await tester.pumpWidget(_shell(FakeApi()));
    await tester.pumpAndSettle();
    expect(find.text('Notifications'), findsNothing);
    expect(find.byKey(const Key('notifications-badge')), findsNothing);
    await _done(tester);
  });

  testWidgets(
      'a tap on a row opens its resource in the detail pane and reads it',
      (tester) async {
    _tablet(tester);
    final api = FakeApi(notificationList: [_n(1)]);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Note 1'));
    await tester.pumpAndSettle();
    expect(api.markedRead, ['n1']);
    expect(find.byType(ResourceView), findsOneWidget);
    // Read now: no dot, no badge.
    expect(find.byKey(const Key('notification-unread')), findsNothing);
    expect(find.byKey(const Key('notifications-badge')), findsNothing);
    await _done(tester);
  });

  testWidgets('Show all opens the full list in the detail pane',
      (tester) async {
    _tablet(tester);
    final api = FakeApi(notificationList: [for (var i = 0; i < 6; i++) _n(i)]);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    expect(find.text('Note 4'), findsNothing);
    await tester
        .tap(find.byKey(const ValueKey('section-show-all-notifications')));
    await tester.pumpAndSettle();
    expect(_controller(tester).topKind, ShellPage.listOf('notifications'));
    final list = tester.getRect(find.byType(ChatsScreen));
    final title = find.descendant(
        of: find.byType(AppTopBar), matching: find.text('Notifications'));
    expect(tester.getRect(title).left, greaterThan(list.right));
    expect(find.text('Note 5'), findsOneWidget);
    await _done(tester);
  });

  testWidgets('the Home hold menu lists Notifications when it has rows',
      (tester) async {
    final api = FakeApi(notificationList: [_n(1)]);
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    expect(_controller(tester).homeSections.value,
        contains(HomeSection.notifications));
    await _done(tester);
  });
}
