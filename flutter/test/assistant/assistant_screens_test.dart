import 'dart:async';
import 'dart:convert';

import 'package:atomiccanvas_flutter/assistant/assistant_api.dart';
import 'package:atomiccanvas_flutter/assistant/hosted_ai.dart';
import 'package:atomiccanvas_flutter/assistant/chat_screen.dart';
import 'package:atomiccanvas_flutter/assistant/chats_screen.dart';
import 'package:atomiccanvas_flutter/assistant/resource_view.dart';
import 'package:atomiccanvas_flutter/assistant/search_screen.dart';
import 'package:atomiccanvas_flutter/atomic/atomic_client.dart';
import 'package:atomiccanvas_flutter/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeApi extends AssistantApi {
  final List<DriveInfo> driveList;
  final List<RecentResource> recent;
  final List<RecentResource> favoriteList;
  final List<RecentResource> conversationList;
  final List<ActivityEntry> activityList;
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
    this.favoriteList = const [],
    this.conversationList = const [],
    this.activityList = const [],
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
  Future<List<ActivityEntry>> activity(int limit) async =>
      activityList.take(limit).toList();
  @override
  Future<List<RecentResource>> recentResources(String drive) async => recent;
  @override
  Future<List<RecentResource>> favorites() async => favoriteList;
  @override
  Future<List<RecentResource>> conversations() async => conversationList;
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

ActivityEntry _activity(String subject, String name,
        {String kind = 'changed', String? actor = 'Ann'}) =>
    ActivityEntry(
      subject: subject,
      drive: 'did:ad:drive',
      kind: kind,
      at: DateTime.now().millisecondsSinceEpoch - 5 * 60 * 1000 - 5000,
      actor: actor,
      name: name,
      className: 'Document',
    );

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

      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen), findsOneWidget);
    });

    testWidgets('sections come in order: Drives, Recents, AI Chats',
        (tester) async {
      final api = FakeApi(
        chatList: [(subject: 'c1', name: 'A chat', lastActivity: 0)],
        recent: [
          (subject: 'r1', title: 'A doc', className: 'Document', openedAt: 1),
        ],
      );
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      double y(String t) => tester.getTopLeft(find.text(t)).dy;
      expect(y('Drives'), lessThan(y('Recents')));
      expect(y('Recents'), lessThan(y('AI Chats')));
      expect(find.text('Show all'), findsNothing);
    });

    testWidgets('Favorites and Messages come after AI Chats, hidden if empty',
        (tester) async {
      tester.view.physicalSize = const Size(800, 3000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      Future<void> pump(FakeApi api) async {
        await tester.pumpWidget(const SizedBox());
        await tester.pumpWidget(app(ChatsScreen(
            drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
        await tester.pumpAndSettle();
      }

      await pump(FakeApi());
      expect(find.text('Favorites'), findsNothing);
      expect(find.text('Messages'), findsNothing);

      final api = FakeApi(
        chatList: [(subject: 'c1', name: 'A chat', lastActivity: 0)],
        favoriteList: [
          (subject: 'f1', title: 'Starred', className: 'Folder', openedAt: 0),
        ],
        conversationList: [
          (subject: 'm1', title: 'Alice, Bob', className: '', openedAt: 0),
        ],
      );
      await pump(api);
      double y(String t) => tester.getTopLeft(find.text(t)).dy;
      expect(y('AI Chats'), lessThan(y('Favorites')));
      expect(y('Favorites'), lessThan(y('Messages')));
      expect(find.text('Starred'), findsOneWidget);
      expect(find.text('Folder'), findsOneWidget);

      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.tap(find.text('Alice, Bob'));
      await tester.pumpAndSettle();
      expect(api.opened, ['m1']);
      expect(find.byType(ResourceView), findsOneWidget);
    });

    testWidgets('Favorites shows 4, Show all lists the rest', (tester) async {
      final api = FakeApi(favoriteList: [
        for (var i = 0; i < 6; i++)
          (subject: 'f$i', title: 'Fav $i', className: '', openedAt: 0),
      ]);
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('Fav 4'), findsNothing);
      await tester.tap(find.text('Show all'));
      await tester.pumpAndSettle();
      expect(find.text('Fav 5'), findsOneWidget);
    });

    testWidgets('a section shows at most 4, Show all lists the rest',
        (tester) async {
      final now = DateTime.now().millisecondsSinceEpoch;
      final api = FakeApi(chatList: [
        for (var i = 0; i < 6; i++)
          (subject: 'c$i', name: 'Chat $i', lastActivity: now),
      ]);
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('Chat 3'), findsOneWidget);
      expect(find.text('Chat 4'), findsNothing);
      expect(find.text('Show all'), findsOneWidget);

      await tester.tap(find.text('Show all'));
      await tester.pumpAndSettle();
      expect(find.text('Chat 5'), findsOneWidget);
      expect(find.text('Today'), findsOneWidget);
    });

    testWidgets('Activity sits between Recents and AI Chats', (tester) async {
      final api = FakeApi(
        chatList: [(subject: 'c1', name: 'A chat', lastActivity: 0)],
        recent: [
          (subject: 'r1', title: 'A doc', className: 'Document', openedAt: 1),
        ],
        activityList: [_activity('a1', 'Plan')],
      );
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      double y(String t) => tester.getTopLeft(find.text(t)).dy;
      expect(y('Recents'), lessThan(y('Activity')));
      expect(y('Activity'), lessThan(y('AI Chats')));
      expect(find.text('Ann changed · 5 min ago'), findsOneWidget);
    });

    testWidgets('says so when there is no activity', (tester) async {
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('No activity yet'), findsOneWidget);
    });

    testWidgets('activity shows 4, Show all appears only above 4',
        (tester) async {
      Future<void> pump(int n) async {
        await tester.pumpWidget(Container());
        await tester.pumpWidget(app(ChatsScreen(
            drive: 'did:ad:drive',
            api: FakeApi(activityList: [
              for (var i = 0; i < n; i++) _activity('a$i', 'Item $i'),
            ]),
            onOpenGallery: () {})));
        await tester.pumpAndSettle();
      }

      await pump(4);
      expect(find.text('Item 3'), findsOneWidget);
      expect(find.text('Show all'), findsNothing);

      await pump(6);
      expect(find.text('Item 3'), findsOneWidget);
      expect(find.text('Item 4'), findsNothing);
      await tester.tap(find.text('Show all'));
      await tester.pumpAndSettle();
      expect(find.text('Item 5'), findsOneWidget);
    });

    testWidgets('a deleted entry is not tappable, a changed one opens',
        (tester) async {
      final api = FakeApi(activityList: [
        _activity('gone', 'Old note', kind: 'deleted', actor: null),
        _activity('here', 'Fresh note', kind: 'created'),
      ]);
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('Someone deleted · 5 min ago'), findsOneWidget);
      ListTile tile(String title) => tester.widget<ListTile>(
          find.ancestor(of: find.text(title), matching: find.byType(ListTile)));
      expect(tile('Old note').onTap, isNull);

      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.tap(find.text('Fresh note'));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
    });

    testWidgets('recents merge all drives, newest first', (tester) async {
      final api = _PerDrive(
        driveList: [
          (subject: 'did:ad:a', name: 'Alpha'),
          (subject: 'did:ad:b', name: 'Beta'),
        ],
        byDrive: {
          'did:ad:a': [
            (subject: 'a1', title: 'Old a', className: '', openedAt: 10),
            (subject: 'a2', title: 'Newest a', className: '', openedAt: 50),
          ],
          'did:ad:b': [
            (subject: 'b1', title: 'Mid b', className: '', openedAt: 30),
            (subject: 'b2', title: 'Oldest b', className: '', openedAt: 5),
            (subject: 'b3', title: 'Second b', className: '', openedAt: 40),
          ],
        },
      );
      await tester.pumpWidget(
          app(ChatsScreen(drive: 'did:ad:a', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      double y(String t) => tester.getTopLeft(find.text(t)).dy;
      expect(y('Newest a'), lessThan(y('Second b')));
      expect(y('Second b'), lessThan(y('Mid b')));
      expect(y('Mid b'), lessThan(y('Old a')));
      expect(find.text('Oldest b'), findsNothing);

      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.tap(find.text('Second b'));
      await tester.pump();
      expect(api.opened, ['b3']);
    });

    testWidgets('a drive opens as a resource page', (tester) async {
      final api = _PerDrive(
        driveList: [(subject: 'did:ad:a', name: 'Alpha')],
        byDrive: {
          'did:ad:a': [
            for (var i = 0; i < 6; i++)
              (subject: 'a$i', title: 'Doc $i', className: '', openedAt: i),
          ],
        },
      );
      await tester.pumpWidget(
          app(ChatsScreen(drive: 'did:ad:a', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.tap(find.text('Alpha').first);
      await tester.pumpAndSettle();
      final page = tester.widget<ResourceView>(find.byType(ResourceView));
      expect(page.subject, 'did:ad:a');
      expect(page.drive, 'did:ad:a');
    });

    testWidgets(
        'the bottom bar is one row: search, new chat, profile, settings',
        (tester) async {
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsNothing);
      final tips = ['Search', 'New chat', 'Profile', 'Settings'];
      for (final t in tips) {
        expect(find.byTooltip(t), findsOneWidget);
      }
      for (final t in ['Notifications', 'Sync']) {
        expect(find.byTooltip(t), findsNothing);
      }
      final ys = [for (final t in tips) tester.getCenter(find.byTooltip(t)).dy];
      expect(ys.every((y) => (y - ys.first).abs() < 1), isTrue);
      final screen = tester.view.physicalSize / tester.view.devicePixelRatio;
      expect(ys.first, greaterThan(screen.height * 0.7));
      expect(find.byIcon(Icons.person_outline), findsOneWidget);
    });

    testWidgets('Search opens the search screen', (tester) async {
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen), findsOneWidget);
    });

    testWidgets('New chat opens a chat', (tester) async {
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('New chat'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
    });

    testWidgets('Settings opens the settings page', (tester) async {
      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Settings'));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
      expect(tester.widget<ResourceView>(find.byType(ResourceView)).path,
          '/app/settings');
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

    testWidgets('an empty query lists what was opened lately', (tester) async {
      final api = FakeApi(
        recent: [
          (
            subject: 'r1',
            title: 'Opened doc',
            className: 'Document',
            openedAt: 1
          ),
        ],
        hits: [
          (
            subject: 'did:ad:9',
            title: 'Zebra',
            className: 'Folder',
            score: 1.0
          ),
        ],
      );
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.text('Recently opened'), findsOneWidget);
      expect(find.text('Opened doc'), findsOneWidget);

      // Typing swaps the list for the hits; clearing brings it back.
      await tester.enterText(find.byType(TextField), 'zeb');
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();
      expect(find.text('Opened doc'), findsNothing);
      expect(find.text('Zebra'), findsOneWidget);

      await tester.enterText(find.byType(TextField), '');
      await tester.pumpAndSettle();
      expect(find.text('Opened doc'), findsOneWidget);
      expect(find.text('Zebra'), findsNothing);

      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.tap(find.text('Opened doc'));
      await tester.pump();
      expect(api.opened, ['r1']);
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

    testWidgets('the messages do not jump when the AI lookup lands',
        (tester) async {
      final lookup = Completer<HostedAi?>();
      final api = _SlowAi(lookup.future);
      await tester.pumpWidget(app(ChatScreen(api: api)));
      await tester.pump();
      final before = tester.getBottomLeft(find.text('No messages')).dy;
      lookup.complete(ai());
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsOneWidget);
      expect(tester.getBottomLeft(find.text('No messages')).dy, before);
    });

    testWidgets('an existing chat sends its history along', (tester) async {
      List<Map<String, String>>? sent;
      final api = FakeApi(
        messageList: [
          (id: 'p#1', role: 'user', text: 'Where to?', createdAt: 1),
          (id: 'p#2', role: 'assistant', text: 'Lisbon.', createdAt: 2),
        ],
        ai: HostedAi(
          status: {'enabled': true, 'consent': true, 'model': 'm'},
          stream: (messages, model) {
            sent = messages;
            return Stream.value('ok');
          },
          enable: () async => {},
        ),
      );
      await tester.pumpWidget(
          app(ChatScreen(api: api, subject: 'did:ad:chat', title: 'Trip')));
      await tester.pumpAndSettle();

      await tester.enterText(find.byType(TextField), 'And food?');
      await tester.tap(find.byTooltip('Send'));
      await tester.pumpAndSettle();

      expect(sent!.map((m) => '${m['role']}: ${m['content']}').toList(), [
        startsWith('system:'),
        'user: Where to?',
        'assistant: Lisbon.',
        'user: And food?',
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

      await tester.tap(find.byTooltip('New chat'));
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

    testWidgets('the full chat list has the headings and no chat icons',
        (tester) async {
      final now = DateTime.now();
      final api = FakeApi(chatList: [
        for (var i = 0; i < 4; i++)
          chat('Fresh $i', now.millisecondsSinceEpoch),
        chat('Old chat',
            now.subtract(const Duration(days: 90)).millisecondsSinceEpoch),
      ]);
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('Today'), findsNothing);
      await tester.tap(find.text('Show all'));
      await tester.pumpAndSettle();
      expect(find.text('Today'), findsOneWidget);
      expect(find.text('Earlier'), findsOneWidget);
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

class _SlowAi extends FakeApi {
  final Future<HostedAi?> lookup;
  _SlowAi(this.lookup);

  @override
  Future<HostedAi?> hostedAi() => lookup;
}

class _PerDrive extends FakeApi {
  final Map<String, List<RecentResource>> byDrive;
  _PerDrive({required super.driveList, required this.byDrive});

  @override
  Future<List<RecentResource>> recentResources(String drive) async =>
      byDrive[drive] ?? [];
}

class _Failing extends FakeApi {
  @override
  Future<List<ChatSummary>> chats() => Future.error('No active drive');
}
