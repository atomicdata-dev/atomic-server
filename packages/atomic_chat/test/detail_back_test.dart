import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// Back from a chat in the detail pane (tablet) shows the section's full list
/// there; the full lists scroll vertically.

const _tablet = Size(800, 1280);
const _phone = Size(393, 851);

void _size(WidgetTester tester, Size size) {
  tester.view.devicePixelRatio = 2;
  tester.view.physicalSize = size * 2;
  addTearDown(tester.view.reset);
}

FakeApi _api() => FakeApi(
      chatList: [
        for (var i = 0; i < 30; i++)
          (subject: 'did:ad:chat-$i', name: 'Chat $i', lastActivity: 100 - i),
      ],
      favoriteList: [
        for (var i = 0; i < 30; i++)
          (
            subject: 'did:ad:fav-$i',
            title: 'Fav $i',
            className: 'document-v2',
            openedAt: 1,
            emoji: null, picture: null,
          ),
      ],
      conversationList: [
        for (var i = 0; i < 30; i++)
          (
            subject: 'did:ad:conv-$i',
            title: 'Talk $i',
            className: 'chatroom',
            openedAt: 100 - i,
            emoji: null, picture: null,
          ),
      ],
      lastMessages: {
        for (var i = 0; i < 30; i++) 'did:ad:conv-$i': 'hello $i',
      },
    );

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      profile: (_) => const Scaffold(body: Text('profile page')),
      home: ChatsScreen(drive: 'did:ad:drive', api: api),
    ));

ShellController _controller(WidgetTester tester) =>
    tester.widget<ShellScope>(find.byType(ShellScope).first).controller;

Future<void> _settle(WidgetTester tester) async {
  await tester.pumpAndSettle();
  await tester.pump(const Duration(milliseconds: 50));
}

Future<void> _done(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox());
  await tester.pump(const Duration(seconds: 1));
}

Finder _inBar(String text) =>
    find.descendant(of: find.byType(AppTopBar), matching: find.text(text));

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('tablet: back from an AI chat shows all AI chats',
      (tester) async {
    _size(tester, _tablet);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    await tester.tap(find.text('Chat 0'));
    await _settle(tester);
    final shell = _controller(tester);
    expect(shell.topKind, isNot(ShellPage.listOf('chats')));
    expect(_inBar('Chat 0'), findsOneWidget);

    await tester.tap(find.byType(BackButton));
    await _settle(tester);
    expect(shell.topKind, ShellPage.listOf('chats'));
    expect(_inBar('AI chats'), findsOneWidget);
    expect(find.byKey(const Key('chats-all-list')), findsOneWidget);
    // The sidebar is still the home.
    expect(find.byType(ChatsScreen), findsOneWidget);
    expect(shell.list.value, ShellPage.home);

    // The system back from a chat does the same.
    await tester.tap(find.text('Chat 1').last);
    await _settle(tester);
    expect(_inBar('Chat 1'), findsOneWidget);
    await tester.binding.handlePopRoute();
    await _settle(tester);
    expect(shell.topKind, ShellPage.listOf('chats'));
    await _done(tester);
  });

  testWidgets('tablet: back from a chat room shows all Messages',
      (tester) async {
    _size(tester, _tablet);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    await tester.tap(find.text('Talk 0'));
    await _settle(tester);
    expect(_inBar('Talk 0'), findsOneWidget);
    await tester.tap(find.byType(BackButton));
    await _settle(tester);
    expect(_controller(tester).topKind, ShellPage.listOf('messages'));
    expect(_inBar('Messages'), findsOneWidget);
    await _done(tester);
  });

  testWidgets('phone: back from a chat pops to the home', (tester) async {
    _size(tester, _phone);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    await tester.tap(find.text('Chat 0'));
    await _settle(tester);
    await tester.tap(find.byType(BackButton));
    await _settle(tester);
    expect(find.byType(ChatsScreen), findsOneWidget);
    expect(_controller(tester).topKind, isNot(ShellPage.listOf('chats')));
    await _done(tester);
  });

  for (final (id, title) in [
    ('chats', 'AI chats'),
    ('messages', 'Messages'),
    ('favorites', 'Favorites'),
  ]) {
    testWidgets('tablet: the $title full list scrolls vertically',
        (tester) async {
      _size(tester, _tablet);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      await tester.ensureVisible(find.byKey(ValueKey('section-show-all-$id')));
      await tester.pump();
      await tester.tap(find.byKey(ValueKey('section-show-all-$id')));
      await _settle(tester);
      final shell = _controller(tester);
      expect(shell.topKind, ShellPage.listOf(id));
      final scrollable = find
          .descendant(
              of: find.ancestor(
                  of: _inBar(title), matching: find.byType(Scaffold)),
              matching: find.byType(Scrollable))
          .first;
      double offset() =>
          tester.state<ScrollableState>(scrollable).position.pixels;
      expect(offset(), 0);
      await tester.drag(scrollable, const Offset(0, -300));
      await _settle(tester);
      expect(offset(), greaterThan(0));
      // A wobbly finger (sideways first, then back up the list) still scrolls.
      final before = offset();
      final g = await tester.startGesture(tester.getCenter(scrollable));
      await g.moveBy(const Offset(-30, 4));
      await g.moveBy(const Offset(-6, 200));
      await g.up();
      await _settle(tester);
      expect(offset(), lessThan(before));
      expect(shell.topKind, ShellPage.listOf(id));
      await _done(tester);
    });
  }
}
