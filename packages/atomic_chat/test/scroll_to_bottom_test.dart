import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

/// The one scroll-to-bottom button of the three chat lists: absent at the
/// bottom, scales in once scrolled up, scrolls to the newest message on a
/// tap and shrinks away; with the count of what arrived meanwhile.
const _t0 = 1700000000000;

class _Api extends UnimplementedApi {
  final List<ConversationMessage> convo = [
    for (var i = 0; i < 60; i++)
      (
        id: 'c$i',
        author: 'a',
        authorName: 'A',
        mine: false,
        text: 'Message $i',
        createdAt: _t0 + i * 600000
      ),
  ];
  final List<ChatRoomMessage> room = [
    for (var i = 0; i < 60; i++)
      (
        id: 'r$i',
        kind: ChatRoomKind.text,
        author: 'a',
        authorName: 'A',
        mine: false,
        text: 'Line $i',
        createdAt: _t0 + i * 600000,
        about: null,
        aboutTitle: '',
      ),
  ];

  @override
  Future<List<ConversationMessage>> conversationMessages(String s) async =>
      List.of(convo);
  @override
  Future<void> followConversation(String subject) async {}
  @override
  Future<List<ChatRoomMessage>> chatRoomMessages(String subject) async =>
      List.of(room);
  @override
  Future<HostedAi?> hostedAi() async => HostedAi(
        status: {'enabled': true, 'consent': true, 'model': 'm'},
        stream: (m, model) => const Stream.empty(),
        enable: () async => {},
      );
  @override
  Future<List<ChatMessage>> messages(String chat) async => [
        for (var i = 0; i < 60; i++)
          (
            id: 'h$i',
            role: i.isEven ? 'user' : 'assistant',
            text: 'Earlier message $i',
            createdAt: _t0 + i * 1000
          ),
      ];
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: [AppColors.light]),
      home: home,
    );

final _button = find.byKey(const Key('scroll-to-bottom'));

double _scale(WidgetTester t) => t
    .widget<ScaleTransition>(find.byKey(const Key('scroll-to-bottom-scale')))
    .scale
    .value;

ScrollPosition _pos(WidgetTester t) =>
    t.state<ScrollableState>(find.byType(Scrollable).first).position;

Future<void> _up(WidgetTester t) async {
  await t.drag(find.byType(ListView), const Offset(0, 500));
  await t.pumpAndSettle();
}

void main() {
  final screens = <String, Widget Function(_Api)>{
    'ChatScreen': (api) => ChatScreen(api: api, subject: 'did:ad:chat'),
    'ChatRoomScreen': (api) => ChatRoomScreen(
        api: api, drive: 'did:ad:drive', subject: 'did:ad:room', title: 'R'),
    'ConversationScreen': (api) =>
        ConversationScreen(api: api, subject: 'did:ad:c', title: 'C'),
  };
  for (final e in screens.entries) {
    testWidgets(
        '${e.key}: button hidden at the bottom, shown and used '
        'after scrolling up', (tester) async {
      await tester.pumpWidget(_app(e.value(_Api())));
      await tester.pumpAndSettle();
      expect(_button, findsNothing);
      await _up(tester);
      expect(_pos(tester).pixels, greaterThan(120));
      expect(_button, findsOneWidget);
      expect(_scale(tester), 1);
      await tester.tap(_button);
      // Mid-way it is still on its way.
      await tester.pump(const Duration(milliseconds: 100));
      expect(_pos(tester).pixels, greaterThan(0));
      await tester.pumpAndSettle();
      expect(_pos(tester).pixels, 0);
      expect(_button, findsNothing);
      // A small scroll under the threshold does not show it.
      await tester.drag(find.byType(ListView), const Offset(0, 60));
      await tester.pumpAndSettle();
      expect(_button, findsNothing);
      await tester.pumpWidget(const SizedBox());
    });
  }

  testWidgets('the button scales in from nothing and out again',
      (tester) async {
    await tester.pumpWidget(
        _app(ConversationScreen(api: _Api(), subject: 'did:ad:c', title: 'C')));
    await tester.pumpAndSettle();
    await tester.drag(find.byType(ListView), const Offset(0, 500));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 30));
    expect(_scale(tester), inExclusiveRange(0, 1.2));
    await tester.pumpAndSettle();
    await tester.tap(_button);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pumpAndSettle();
    expect(_button, findsNothing);
    await tester.pumpWidget(const SizedBox());
  });

  for (final room in [true, false]) {
    testWidgets(
        '${room ? 'ChatRoomScreen' : 'ConversationScreen'}: the badge counts '
        'new messages while scrolled up and clears at the bottom',
        (tester) async {
      final api = _Api();
      await tester.pumpWidget(_app(room
          ? ChatRoomScreen(
              api: api, drive: 'did:ad:drive', subject: 'did:ad:r', title: 'R')
          : ConversationScreen(api: api, subject: 'did:ad:c', title: 'C')));
      await tester.pumpAndSettle();
      await _up(tester);
      for (var i = 0; i < 2; i++) {
        if (room) {
          api.room.add((
            id: 'rn$i',
            kind: ChatRoomKind.text,
            author: 'a',
            authorName: 'A',
            mine: false,
            text: 'Fresh $i',
            createdAt: _t0 + 99999999 + i,
            about: null,
            aboutTitle: '',
          ));
        } else {
          api.convo.add((
            id: 'cn$i',
            author: 'a',
            authorName: 'A',
            mine: false,
            text: 'Fresh $i',
            createdAt: _t0 + 99999999 + i,
          ));
        }
        await tester.pump(conversationRefresh);
        await tester.pumpAndSettle();
        expect(find.descendant(of: _button, matching: find.text('${i + 1}')),
            findsOneWidget);
      }
      await tester.tap(_button);
      await tester.pumpAndSettle();
      expect(_pos(tester).pixels, 0);
      expect(find.text('Fresh 1'), findsOneWidget);
      expect(_button, findsNothing);
      await tester.pumpWidget(const SizedBox());
    });
  }
}
