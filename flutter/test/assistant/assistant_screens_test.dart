import 'dart:convert';

import 'package:atomiccanvas_flutter/assistant/assistant_api.dart';
import 'package:atomiccanvas_flutter/assistant/hosted_ai.dart';
import 'package:atomiccanvas_flutter/assistant/chat_screen.dart';
import 'package:atomiccanvas_flutter/assistant/chats_screen.dart';
import 'package:atomiccanvas_flutter/assistant/search_screen.dart';
import 'package:atomiccanvas_flutter/atomic/atomic_client.dart';
import 'package:atomiccanvas_flutter/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeApi extends AssistantApi {
  final List<DriveInfo> driveList;
  final List<RecentResource> recent;
  final List<ChatSummary> chatList;
  final List<ChatMessage> messageList;
  final List<SearchHit> hits;
  final List<String> asked = [];
  final List<String> opened = [];
  final HostedAi? ai;
  final List<(String, String, String)> added = [];
  final List<String> created = [];

  FakeApi({
    this.driveList = const [(subject: 'did:ad:drive', name: 'Home')],
    this.recent = const [],
    this.ai,
    this.chatList = const [],
    this.messageList = const [],
    this.hits = const [],
  });

  @override
  Future<String?> agentName() async => 'Joep';
  @override
  Future<List<DriveInfo>> drives() async => driveList;
  @override
  Future<List<ChatSummary>> chats() async => chatList;
  @override
  Future<List<RecentResource>> recentResources(String drive) async => recent;
  @override
  Future<List<ChatMessage>> messages(String chat) async => messageList;
  @override
  Future<List<SearchHit>> search(String drive, String query) async {
    asked.add(query);
    return hits;
  }

  @override
  Future<HostedAi?> hostedAi() async => ai;
  @override
  Future<String> newChat(String name) async {
    created.add(name);
    return 'did:ad:new-chat';
  }

  @override
  Future<void> addMessage(String chat, String role, String text) async =>
      added.add((chat, role, text));

  @override
  void noteOpened(String drive, String subject) => opened.add(subject);
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
      expect(find.text('Today'), findsOneWidget);
      expect(find.text('Earlier'), findsOneWidget);
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

    testWidgets('chats stay put while the drives swipe', (tester) async {
      final api = FakeApi(
        driveList: [
          (subject: 'did:ad:a', name: 'Alpha'),
          (subject: 'did:ad:b', name: 'Beta'),
        ],
        chatList: [(subject: 'c1', name: 'Any drive chat', lastActivity: 0)],
        recent: [
          (
            subject: 'r1',
            title: 'Opened doc',
            className: 'Document',
            openedAt: DateTime.now().millisecondsSinceEpoch,
          ),
        ],
      );
      await tester.pumpWidget(
          app(ChatsScreen(drive: 'did:ad:a', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();

      expect(find.text('Any drive chat'), findsOneWidget);
      expect(find.text('Opened doc'), findsOneWidget);
      expect(find.text('Search in Alpha'), findsOneWidget);

      await tester.fling(find.text('Opened doc'), const Offset(-600, 0), 2000);
      await tester.pumpAndSettle();
      expect(find.text('Search in Beta'), findsOneWidget);
      expect(find.text('Any drive chat'), findsOneWidget);
    });

    testWidgets('on a phone with five chats, the drives still swipe and scroll',
        (tester) async {
      tester.view.physicalSize = const Size(1080, 1920);
      tester.view.devicePixelRatio = 3; // 360 x 640
      addTearDown(tester.view.reset);
      final now = DateTime.now().millisecondsSinceEpoch;
      final api = FakeApi(
        driveList: [
          (subject: 'did:ad:a', name: 'Alpha'),
          (subject: 'did:ad:b', name: 'Beta'),
        ],
        chatList: [
          for (var i = 0; i < 5; i++)
            (subject: 'c$i', name: 'Chat $i', lastActivity: now),
        ],
        recent: [
          for (var i = 0; i < 20; i++)
            (
              subject: 'r$i',
              title: 'Doc $i',
              className: 'Document',
              openedAt: now,
            ),
        ],
      );
      await tester.pumpWidget(
          app(ChatsScreen(drive: 'did:ad:a', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();

      // Scrolling up moves the chats away and reaches the last opened doc.
      await tester.dragUntilVisible(find.text('Doc 19'),
          find.byType(NestedScrollView), const Offset(0, -300));
      expect(find.text('Doc 19'), findsOneWidget);

      await tester.fling(find.text('Doc 19'), const Offset(-300, 0), 2000);
      await tester.pumpAndSettle();
      expect(find.text('Search in Beta'), findsOneWidget);
    });

    testWidgets('the agent avatar is the way to agent and sync',
        (tester) async {
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('J'), findsOneWidget);
      expect(find.byTooltip('Your agent and sync'), findsOneWidget);
      expect(find.byIcon(Icons.settings_outlined), findsNothing);
    });

    testWidgets('opens on the drive it is given', (tester) async {
      final api = FakeApi(driveList: [
        (subject: 'did:ad:a', name: 'Alpha'),
        (subject: 'did:ad:b', name: 'Beta'),
      ], recent: [
        (subject: 'r', title: 'Doc', className: 'Document', openedAt: 1),
      ]);
      await tester.pumpWidget(
          app(ChatsScreen(drive: 'did:ad:b', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('Search in Beta'), findsOneWidget);
    });

    testWidgets('a drive with nothing opened gets no page', (tester) async {
      final api = FakeApi(driveList: [
        (subject: 'did:ad:a', name: 'Alpha'),
        (subject: 'did:ad:b', name: 'Beta'),
      ]);
      await tester.pumpWidget(
          app(ChatsScreen(drive: 'did:ad:a', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      // Only the drive it opened on: no swipe, no dots, no drive name.
      expect(find.text('Search'), findsOneWidget);
      expect(find.text('Recently opened'), findsOneWidget);
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

    testWidgets('opening a hit is remembered as recently opened',
        (tester) async {
      final api = FakeApi(hits: [
        (subject: 'did:ad:9', title: 'Zebra', className: 'Folder', score: 1.5),
      ]);
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.enterText(find.byType(TextField), 'zebr');
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Zebra'));
      await tester.pump();
      expect(api.opened, ['did:ad:9']);
    });
  });

  group('ChatScreen with an AI', () {
    HostedAi ai(
            {bool consent = true, List<String> answer = const ['Ho', 'i!']}) =>
        HostedAi(
          status: {'enabled': true, 'consent': consent, 'model': 'm'},
          stream: (messages, model) => Stream.fromIterable(answer),
          enable: () async => {'enabled': true, 'consent': true, 'model': 'm'},
        );

    testWidgets('writes, streams the answer and keeps both messages',
        (tester) async {
      final api = FakeApi(ai: ai());
      await tester.pumpWidget(app(ChatScreen(api: api)));
      await tester.pumpAndSettle();

      await tester.enterText(find.byType(TextField), 'Hallo daar');
      await tester.tap(find.byTooltip('Send'));
      await tester.pumpAndSettle();

      // A new chat is created with the first message, named after it.
      expect(api.created, ['Hallo daar']);
      expect(api.added, [
        ('did:ad:new-chat', 'user', 'Hallo daar'),
        ('did:ad:new-chat', 'assistant', 'Hoi!'),
      ]);
    });

    testWidgets('asks for consent before the AI is used', (tester) async {
      final api = FakeApi(ai: ai(consent: false));
      await tester.pumpWidget(app(ChatScreen(api: api)));
      await tester.pumpAndSettle();

      expect(find.byType(TextField), findsNothing);
      await tester.tap(find.text('Turn on AI'));
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsOneWidget);
    });

    testWidgets('says so, without more, when there is no AI', (tester) async {
      await tester.pumpWidget(app(ChatScreen(api: FakeApi())));
      await tester.pumpAndSettle();

      expect(find.byType(TextField), findsNothing);
      expect(find.text('No AI is set up on this device.'), findsOneWidget);
    });

    testWidgets('a new chat can be started from the home', (tester) async {
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive',
          api: FakeApi(ai: ai()),
          onOpenGallery: () {})));
      await tester.pumpAndSettle();

      await tester.tap(find.text('New chat'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
      expect(find.text('Message'), findsOneWidget);
    });
  });

  group('groupChatsByAge', () {
    final now = DateTime(2026, 10, 19, 15);
    int ago(Duration d) => now.subtract(d).millisecondsSinceEpoch;
    ChatSummary chat(String name, int at) =>
        (subject: name, name: name, lastActivity: at);

    test('groups by day, keeps the order, skips empty groups', () {
      final groups = groupChatsByAge([
        chat('a', ago(const Duration(hours: 2))),
        chat('b', ago(const Duration(hours: 20))),
        chat('c', ago(const Duration(days: 3))),
        chat('d', ago(const Duration(days: 4))),
        chat('e', ago(const Duration(days: 40))),
        chat('f', 0),
      ], now: now);
      expect(groups.map((g) => g.$1).toList(),
          ['Today', 'Yesterday', 'This week', 'Earlier']);
      expect(groups.map((g) => g.$2.map((c) => c.name).join()).toList(),
          ['a', 'b', 'cd', 'ef']);
    });

    test('nothing, no groups', () {
      expect(groupChatsByAge([], now: now), isEmpty);
    });

    testWidgets('the home shows the headings and no chat icons',
        (tester) async {
      final api = FakeApi(chatList: [
        chat('Fresh chat', DateTime.now().millisecondsSinceEpoch),
        chat(
            'Old chat',
            DateTime.now()
                .subtract(const Duration(days: 90))
                .millisecondsSinceEpoch),
      ]);
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('Today'), findsOneWidget);
      expect(find.text('Earlier'), findsOneWidget);
      expect(find.text('Recent chats'), findsNothing);
      expect(find.byIcon(Icons.chat_bubble_outline), findsNothing);
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

    test('reads recently opened resources', () {
      final recent = AtomicClient.parseRecentResources(
          '[{"subject":"did:ad:1","title":"T","class_name":"C","opened_at":9}]');
      expect((recent.single.title, recent.single.openedAt), ('T', 9));
    });

    test('lists each drive once, only those that are on the device', () {
      final shown = AtomicClient.visibleDrives([
        (subject: 'did:ad:AAA', name: 'Private'),
        (subject: 'atomic:AAA', name: 'Private'),
        (subject: 'did:ad:BBB', name: ''),
        (subject: 'did:ad:CCC', name: 'Team'),
        (subject: 'did:ad:DDD', name: ''),
      ], active: 'atomic:DDD');
      expect(shown.map((d) => d.subject),
          ['did:ad:AAA', 'did:ad:CCC', 'did:ad:DDD']);
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
  Future<List<ChatSummary>> chats() => Future.error('No active drive');
}
