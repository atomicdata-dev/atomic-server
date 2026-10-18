import 'dart:convert';

import 'package:atomiccanvas_flutter/assistant/assistant_api.dart';
import 'package:atomiccanvas_flutter/assistant/chat_screen.dart';
import 'package:atomiccanvas_flutter/assistant/chats_screen.dart';
import 'package:atomiccanvas_flutter/assistant/search_screen.dart';
import 'package:atomiccanvas_flutter/atomic/atomic_client.dart';
import 'package:atomiccanvas_flutter/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeApi extends AssistantApi {
  final List<ChatSummary> chatList;
  final List<ChatMessage> messageList;
  final List<SearchHit> hits;
  final List<String> asked = [];

  FakeApi({
    this.chatList = const [],
    this.messageList = const [],
    this.hits = const [],
  });

  @override
  Future<List<ChatSummary>> chats(String drive) async => chatList;
  @override
  Future<List<ChatMessage>> messages(String chat) async => messageList;
  @override
  Future<List<SearchHit>> search(String drive, String query) async {
    asked.add(query);
    return hits;
  }

  @override
  String webUrl(String subject) => throw 'Not connected to a server';
}

Widget app(Widget home, {Brightness brightness = Brightness.light}) =>
    MaterialApp(
      theme: ThemeData(
        brightness: brightness,
        extensions: [
          brightness == Brightness.light ? AppColors.light : AppColors.dark,
        ],
      ),
      home: home,
    );

void main() {
  group('ChatsScreen', () {
    testWidgets('lists the chats and opens one', (tester) async {
      final now = DateTime.now().millisecondsSinceEpoch;
      final api = FakeApi(
        chatList: [
          (subject: 'did:ad:1', name: 'Trip plan', lastActivity: now),
          (subject: 'did:ad:2', name: '', lastActivity: 0),
        ],
        messageList: [
          (id: 'p#1', role: 'user', text: 'Where to?', createdAt: 1),
          (id: 'p#2', role: 'assistant', text: 'Lisbon.', createdAt: 2),
        ],
      );
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();

      expect(find.text('Trip plan'), findsOneWidget);
      expect(find.text('just now'), findsOneWidget);
      expect(find.text('Untitled chat'), findsOneWidget);

      await tester.tap(find.text('Trip plan'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
      expect(find.text('Where to?'), findsOneWidget);
      expect(find.text('Lisbon.'), findsOneWidget);
    });

    testWidgets('says so when there are no chats', (tester) async {
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('No chats yet'), findsOneWidget);
    });

    testWidgets('reaches the canvas gallery and the search', (tester) async {
      var gallery = 0;
      await tester.pumpWidget(app(
        ChatsScreen(
            drive: 'did:ad:drive',
            api: FakeApi(),
            onOpenGallery: () => gallery++),
        brightness: Brightness.dark,
      ));
      await tester.pumpAndSettle();

      await tester.tap(find.byTooltip('Canvases'));
      expect(gallery, 1);

      await tester.tap(find.byType(TextField));
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen), findsOneWidget);
    });

    testWidgets('shows the error when the chats cannot be read',
        (tester) async {
      final api = _Failing();
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.textContaining('No active drive'), findsOneWidget);
    });
  });

  group('SearchScreen', () {
    testWidgets('searches as you type, once per pause', (tester) async {
      final api = FakeApi(hits: [
        (subject: 'did:ad:9', title: 'Zebra', className: 'Folder', score: 1.5),
      ]);
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));

      await tester.enterText(find.byType(TextField), 'ze');
      await tester.pump(const Duration(milliseconds: 50));
      await tester.enterText(find.byType(TextField), 'zebr');
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();

      expect(api.asked, ['zebr']);
      expect(find.text('Zebra'), findsOneWidget);
      expect(find.text('Folder'), findsOneWidget);

      await tester.enterText(find.byType(TextField), '');
      await tester.pumpAndSettle();
      expect(find.text('Zebra'), findsNothing);
    });
  });

  group('AtomicClient parsing', () {
    test('keeps the text parts of user and assistant entries only', () {
      final messages = AtomicClient.parseChatMessages(jsonEncode([
        {
          'id': 'p#1',
          'role': 'user',
          'c': 5,
          'parts': [
            {'type': 'text', 'text': 'Hi'}
          ],
        },
        {
          'id': 'p#2',
          'role': 'assistant',
          'c': 6,
          'parts': [
            {'type': 'reasoning', 'text': 'thinking'},
            {'type': 'tool-search', 'toolCallId': 'x'},
            {'type': 'text', 'text': 'One'},
            {'type': 'text', 'text': 'Two'},
          ],
        },
        {'id': 'p#3', 'role': 'assistant', 'parts': []},
        {
          'id': 'p#4',
          'role': 'summary',
          'parts': [
            {'type': 'text', 'text': 'older'}
          ],
        },
      ]));
      expect(messages.map((m) => (m.id, m.role, m.text)), [
        ('p#1', 'user', 'Hi'),
        ('p#2', 'assistant', 'One\n\nTwo'),
      ]);
      expect(messages.first.createdAt, 5);
    });

    test('reads chats and hits', () {
      final chats = AtomicClient.parseChats(
          '[{"subject":"did:ad:1","name":"A","last_activity":7}]');
      expect(chats.single.lastActivity, 7);
      final hits = AtomicClient.parseHits(
          '[{"subject":"did:ad:1","title":"T","class_name":"C","score":0.5}]');
      expect((hits.single.title, hits.single.className, hits.single.score),
          ('T', 'C', 0.5));
    });

    test('timeAgo', () {
      final now = DateTime(2026, 10, 18, 12);
      int ago(Duration d) => now.subtract(d).millisecondsSinceEpoch;
      expect(timeAgo(ago(const Duration(minutes: 5)), now: now), '5 min ago');
      expect(timeAgo(ago(const Duration(hours: 3)), now: now), '3 h ago');
      expect(timeAgo(ago(const Duration(days: 2)), now: now), '2 d ago');
      expect(timeAgo(ago(const Duration(days: 30)), now: now), '2026-09-18');
    });
  });
}

class _Failing extends FakeApi {
  @override
  Future<List<ChatSummary>> chats(String drive) => Future.error('No active drive');
}
