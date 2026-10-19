import 'dart:math' as math;
import 'dart:async';
import 'dart:convert';

import 'package:atomiccanvas_flutter/assistant/app_bottom_bar.dart';
import 'package:atomiccanvas_flutter/assistant/app_shell.dart';
import 'package:atomiccanvas_flutter/assistant/assistant_api.dart';
import 'package:atomiccanvas_flutter/assistant/native_views.dart';
import 'package:atomiccanvas_flutter/assistant/hosted_ai.dart';
import 'package:atomiccanvas_flutter/assistant/chat_screen.dart';
import 'package:atomiccanvas_flutter/assistant/chats_screen.dart';
import 'package:atomiccanvas_flutter/assistant/resource_view.dart';
import 'package:atomiccanvas_flutter/assistant/search_screen.dart';
import 'package:atomiccanvas_flutter/assistant/voice.dart';
import 'package:atomiccanvas_flutter/atomic/atomic_client.dart';
import 'package:atomiccanvas_flutter/theme.dart';
import 'package:atomiccanvas_flutter/widgets/covered_insets_freeze.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

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
  final List<String> openedDrives = [];
  final HostedAi? ai;
  final List<(String, String, String)> added = [];
  final List<String> created = [];
  final Map<String, String> texts;

  /// How many times `drives()` was asked, and an optional gate it waits on.
  int drivesCalls = 0;
  Future<void>? drivesGate;

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
    this.texts = const {},
  });

  @override
  Future<String?> agentName() async => 'Joep';
  @override
  Future<List<DriveInfo>> drives() async {
    drivesCalls++;
    await drivesGate;
    return driveList;
  }

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
  Future<List<SearchHit>> search(String query, {String? drive}) async {
    asked.add(query);
    return hits;
  }

  @override
  Future<HostedAi?> hostedAi() async => ai;
  @override
  Future<String> resourceText(String subject, {int maxChars = 4000}) async =>
      texts[subject] ?? 'text of $subject';
  @override
  Future<String> newChat(String name) async {
    created.add(name);
    return 'did:ad:new-chat';
  }

  @override
  Future<void> addMessage(String chat, String role, String text) async =>
      added.add((chat, role, text));

  @override
  void noteOpened(String drive, String subject) {
    opened.add(subject);
    openedDrives.add(drive);
  }

  @override
  String webUrl(String subject) => throw 'Not connected to a server';
}

class FakeSpeechInput implements SpeechInput {
  final bool available;
  int starts = 0;
  int stops = 0;
  bool _on = false;
  void Function(String, bool)? onText;
  void Function(String)? onError;
  void Function(double)? onLevel;

  /// Simulates the permission prompt before listening begins.
  final Duration startDelay;

  FakeSpeechInput({this.available = true, this.startDelay = Duration.zero});

  String? lastLocale;
  List<SpeechLocale> available_ = const [
    SpeechLocale('en_US', 'English (United States)'),
    SpeechLocale('nl_NL', 'Dutch (Netherlands)'),
    SpeechLocale('de_DE', 'German (Germany)'),
  ];

  @override
  Future<List<SpeechLocale>> locales() async => available_;

  @override
  Future<String?> systemLocale() async => 'en_US';

  @override
  bool get listening => _on;

  @override
  Future<bool> start({
    required void Function(String text, bool isFinal) onText,
    required void Function(String error) onError,
    void Function(double level)? onLevel,
    String? localeId,
  }) async {
    starts++;
    lastLocale = localeId;
    if (startDelay > Duration.zero) await Future<void>.delayed(startDelay);
    if (!available) return false;
    this.onText = onText;
    this.onError = onError;
    this.onLevel = onLevel;
    _on = true;
    return true;
  }

  @override
  Future<void> stop() async {
    stops++;
    _on = false;
  }
}

class FakeSpeechOutput implements SpeechOutput {
  final List<String> spoken = [];
  int stops = 0;

  @override
  Future<void> speak(String text) async => spoken.add(text);

  @override
  Future<void> stop() async => stops++;
}

/// A fake whose `chats()` answers only when the test completes it.
class _SlowChatsApi extends FakeApi {
  final List<Completer<List<ChatSummary>>> pending = [];

  _SlowChatsApi({super.chatList, super.messageList});

  @override
  Future<List<ChatSummary>> chats() {
    final c = Completer<List<ChatSummary>>();
    pending.add(c);
    return c.future;
  }
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

/// The home in the app shell: the static bottom bar is there.
Widget shellApp(ChatsScreen home, {Brightness brightness = Brightness.light}) =>
    app(AppShell(api: home.api, drive: home.drive, home: home),
        brightness: brightness);

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

    testWidgets('keeps the old rows while a reload is pending', (tester) async {
      final api = _SlowChatsApi(
        chatList: [(subject: 'did:ad:1', name: 'Trip plan', lastActivity: 5)],
        messageList: [
          (id: 'p#1', role: 'user', text: 'Where to?', createdAt: 1),
        ],
      );
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      // The first load shows a spinner until the chats arrive.
      await tester.pump();
      expect(find.byType(CircularProgressIndicator), findsWidgets);
      api.pending.removeAt(0).complete(api.chatList);
      await tester.pumpAndSettle();
      expect(find.text('Trip plan'), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsNothing);

      // Open the chat and come back: that reloads the home.
      await tester.tap(find.text('Trip plan'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
      Navigator.of(tester.element(find.byType(ChatScreen))).pop();
      await tester.pumpAndSettle();
      expect(api.pending, hasLength(1), reason: 'one reload, still pending');

      // While it is pending the old row stays and nothing spins.
      expect(find.text('Trip plan'), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsNothing);

      api.pending.removeAt(0).complete([
        (subject: 'did:ad:1', name: 'Trip plan', lastActivity: 5),
        (subject: 'did:ad:3', name: 'New idea', lastActivity: 9),
      ]);
      await tester.pumpAndSettle();
      expect(find.text('New idea'), findsOneWidget);
    });

    testWidgets('keeps the old rows when a reload fails', (tester) async {
      final api = _SlowChatsApi(
        chatList: [(subject: 'did:ad:1', name: 'Trip plan', lastActivity: 5)],
      );
      await tester.pumpWidget(app(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pump();
      api.pending.removeAt(0).complete(api.chatList);
      await tester.pumpAndSettle();

      await tester.tap(find.text('Trip plan'));
      await tester.pumpAndSettle();
      Navigator.of(tester.element(find.byType(ChatScreen))).pop();
      await tester.pumpAndSettle();
      api.pending.removeAt(0).completeError('offline');
      await tester.pumpAndSettle();

      expect(find.text('Trip plan'), findsOneWidget);
      expect(find.text('offline'), findsNothing);
    });

    testWidgets('says so when there are no chats', (tester) async {
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.text('No chats yet'), findsOneWidget);
    });

    testWidgets('reaches the canvas gallery and the search', (tester) async {
      var gallery = 0;
      await tester.pumpWidget(shellApp(
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
      await tester.pumpWidget(shellApp(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsNothing);
      final tips = ['Search', 'New chat', 'Profile', 'Settings'];
      for (final t in tips) {
        expect(find.byTooltip(t), findsOneWidget);
      }
      for (final t in ['Notifications', 'Sync', 'Back', 'More']) {
        expect(find.byTooltip(t), findsNothing);
      }
      final ys = [for (final t in tips) tester.getCenter(find.byTooltip(t)).dy];
      expect(ys.every((y) => (y - ys.first).abs() < 1), isTrue);
      final xs = [for (final t in tips) tester.getCenter(find.byTooltip(t)).dx];
      expect(xs, orderedEquals([...xs]..sort()));
      final screen = tester.view.physicalSize / tester.view.devicePixelRatio;
      expect(ys.first, greaterThan(screen.height * 0.7));
      expect(find.byIcon(Icons.person_outline), findsOneWidget);
    });

    testWidgets('Search opens the search screen', (tester) async {
      await tester.pumpWidget(shellApp(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen), findsOneWidget);
    });

    testWidgets('New chat opens a chat', (tester) async {
      await tester.pumpWidget(shellApp(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('New chat'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
    });

    testWidgets('Settings opens the settings page', (tester) async {
      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.pumpWidget(shellApp(ChatsScreen(
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
        (
          subject: 'did:ad:9',
          title: 'Zebra',
          className: 'Folder',
          drive: '',
          score: 1.5
        ),
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
            drive: '',
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
        (
          subject: 'did:ad:9',
          title: 'Zebra',
          className: 'Folder',
          drive: '',
          score: 1.5
        ),
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

  group('SearchScreen thumb layout', () {
    SearchHit hit(String id, String title, double score) => (
          subject: 'did:ad:$id',
          title: title,
          className: 'Folder',
          drive: '',
          score: score
        );

    Future<void> type(WidgetTester tester, String text) async {
      await tester.enterText(find.byType(TextField), text);
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();
    }

    testWidgets('field at the bottom, best hit lowest and outlined',
        (tester) async {
      final api = FakeApi(hits: [hit('1', 'Best', 2), hit('2', 'Second', 1)]);
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await type(tester, 'b');

      final field = tester.getTopLeft(find.byType(TextField)).dy;
      final best = tester.getTopLeft(find.text('Best')).dy;
      final second = tester.getTopLeft(find.text('Second')).dy;
      expect(field, greaterThan(best));
      expect(best, greaterThan(second));

      final box =
          tester.widget<Container>(find.byKey(const Key('search-top-hit')));
      final border = (box.decoration! as BoxDecoration).border! as Border;
      expect(border.top.width, 1.5);
      expect(
          find.descendant(
              of: find.byKey(const Key('search-top-hit')),
              matching: find.text('Best')),
          findsOneWidget);
      expect(find.byKey(const Key('search-top-hit')), findsOneWidget);
    });

    testWidgets('Enter opens the best hit', (tester) async {
      final api = FakeApi(hits: [hit('1', 'Best', 2), hit('2', 'Second', 1)]);
      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await type(tester, 'b');
      await tester.testTextInput.receiveAction(TextInputAction.search);
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 500));
      expect(api.opened, ['did:ad:1']);
      expect(find.byType(ResourceView), findsOneWidget);
    });

    testWidgets('Enter without hits opens nothing', (tester) async {
      final api = FakeApi();
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await type(tester, 'nothing');
      await tester.testTextInput.receiveAction(TextInputAction.search);
      await tester.pump();
      expect(api.opened, isEmpty);
      expect(find.byType(ResourceView), findsNothing);
    });

    testWidgets('the back arrow pops in one tap with the keyboard open',
        (tester) async {
      final api = FakeApi();
      await tester.pumpWidget(app(Builder(
        builder: (context) => TextButton(
          onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(
              builder: (_) => SearchScreen(drive: 'did:ad:drive', api: api))),
          child: const Text('go'),
        ),
      )));
      await tester.tap(find.text('go'));
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen), findsOneWidget);
      expect(FocusManager.instance.primaryFocus, isNotNull);

      await tester.tap(find.byTooltip('Back'));
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen), findsNothing);
    });

    testWidgets('recents: newest at the bottom, outlined', (tester) async {
      final api = FakeApi(recent: [
        (subject: 'r2', title: 'Newer', className: 'Document', openedAt: 2),
        (subject: 'r1', title: 'Older', className: 'Document', openedAt: 1),
      ]);
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      final newer = tester.getTopLeft(find.text('Newer')).dy;
      final older = tester.getTopLeft(find.text('Older')).dy;
      final heading = tester.getTopLeft(find.text('Recently opened')).dy;
      expect(newer, greaterThan(older));
      expect(older, greaterThan(heading));
      expect(
          find.descendant(
              of: find.byKey(const Key('search-top-hit')),
              matching: find.text('Newer')),
          findsOneWidget);
    });
  });

  group('SearchScreen across drives', () {
    testWidgets('shows the drive of each hit and opens it in that drive',
        (tester) async {
      final api = FakeApi(
        driveList: [
          (subject: 'did:ad:drive', name: 'Home'),
          (subject: 'did:ad:work', name: 'Work'),
        ],
        hits: [
          (
            subject: 'did:ad:a',
            title: 'Zebra home',
            className: 'Folder',
            drive: 'did:ad:drive',
            score: 2.0
          ),
          (
            subject: 'did:ad:b',
            title: 'Zebra work',
            className: 'Document',
            drive: 'did:ad:work',
            score: 1.0
          ),
        ],
      );
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'zebra');
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();

      expect(find.text('Folder · Home'), findsOneWidget);
      expect(find.text('Document · Work'), findsOneWidget);

      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.tap(find.text('Zebra work'));
      await tester.pump();
      expect(api.opened, ['did:ad:b']);
      expect(api.openedDrives, ['did:ad:work']);
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
      await tester.pump();
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
      final before = tester.getTopLeft(find.text('Add context?')).dy;
      lookup.complete(ai());
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsOneWidget);
      expect(tester.getTopLeft(find.text('Add context?')).dy, before);
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
      await tester.pump();
      await tester.tap(find.byTooltip('Send'));
      await tester.pumpAndSettle();

      expect(sent!.map((m) => '${m['role']}: ${m['content']}').toList(), [
        startsWith('system:'),
        'user: Where to?',
        'assistant: Lisbon.',
        'user: And food?',
      ]);
    });

    group('voice', () {
      setUp(() => SharedPreferences.setMockInitialValues({}));

      Future<void> open(WidgetTester tester, FakeSpeechInput input,
          FakeSpeechOutput output) async {
        await tester.pumpWidget(app(ChatScreen(
          api: FakeApi(ai: ai()),
          speechInput: input,
          speechOutput: output,
        )));
        await tester.pumpAndSettle();
      }

      String field(WidgetTester tester) =>
          tester.widget<TextField>(find.byType(TextField)).controller!.text;

      testWidgets('dictation fills the field after typed text, stop ends it',
          (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        await tester.enterText(find.byType(TextField), 'Hello');
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        expect(find.byIcon(Icons.stop), findsOneWidget);

        input.onText!('wor', false);
        await tester.pump();
        expect(field(tester), 'Hello wor');
        input.onText!('world', false);
        await tester.pump();
        expect(field(tester), 'Hello world');

        await tester.tap(find.byIcon(Icons.stop));
        await tester.pump();
        expect(input.stops, 1);
        expect(find.byIcon(Icons.mic), findsOneWidget);
        expect(field(tester), 'Hello world');
      });

      testWidgets('a final result leaves the text, not sent', (tester) async {
        final input = FakeSpeechInput();
        final api = FakeApi(ai: ai());
        await tester.pumpWidget(app(ChatScreen(
            api: api, speechInput: input, speechOutput: FakeSpeechOutput())));
        await tester.pumpAndSettle();
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        input.onText!('good morning', true);
        await tester.pump();
        expect(field(tester), 'good morning');
        expect(find.byIcon(Icons.mic), findsOneWidget);
        expect(api.added, isEmpty);
      });

      testWidgets('says so when voice input is not available', (tester) async {
        await open(
            tester, FakeSpeechInput(available: false), FakeSpeechOutput());
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        expect(find.textContaining('Voice input is not available'),
            findsOneWidget);
        expect(find.byIcon(Icons.mic), findsOneWidget);
        expect(find.byType(TextField), findsOneWidget);
      });

      for (final code in ['error_no_match', 'error_speech_timeout']) {
        testWidgets('$code ends listening silently, keeps the text',
            (tester) async {
          final input = FakeSpeechInput();
          await open(tester, input, FakeSpeechOutput());
          await tester.tap(find.byIcon(Icons.mic));
          await tester.pump();
          input.onText!('some words', false);
          input.onError!(code);
          await tester.pump();
          expect(find.byIcon(Icons.mic), findsOneWidget);
          expect(find.textContaining('Voice input'), findsNothing);
          expect(find.textContaining('error_'), findsNothing);
          expect(field(tester), 'some words');
        });
      }

      testWidgets('real errors show a short message', (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        input.onError!('error_network');
        await tester.pump();
        expect(find.text('No internet connection for speech recognition.'),
            findsOneWidget);
        expect(find.byIcon(Icons.mic), findsOneWidget);

        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        input.onError!('error_weird');
        await tester.pump();
        expect(find.text('Voice input failed.'), findsOneWidget);
      });

      test('maps common error codes', () {
        expect(voiceErrorMessage('error_permission'),
            'Microphone permission is needed.');
        expect(voiceErrorMessage('error_recognizer_busy'),
            'Voice input is busy, try again.');
        expect(voiceErrorMessage('error_no_match'), isNull);
      });

      test('normalises sound levels defensively', () {
        expect(normaliseSoundLevel(-50), 0);
        expect(normaliseSoundLevel(100), 1);
        expect(normaliseSoundLevel(double.nan), 0);
        expect(normaliseSoundLevel(4), closeTo(0.5, 0.01));
      });

      testWidgets('the ring follows the input level', (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        expect(find.byKey(const Key('mic-level-ring')), findsNothing);
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        double ring() =>
            tester.getSize(find.byKey(const Key('mic-level-ring'))).width;
        input.onLevel!(0);
        await tester.pump();
        await tester.pump(const Duration(milliseconds: 300));
        final quiet = ring();
        input.onLevel!(1);
        await tester.pump();
        await tester.pump(const Duration(milliseconds: 300));
        final loud = ring();
        expect(loud, greaterThan(quiet));
        expect(loud, closeTo(48 * 1.6, 0.5));
        expect(quiet, lessThan(48 * 1.2));

        await tester.tap(find.byIcon(Icons.stop));
        await tester.pump();
        expect(find.byKey(const Key('mic-level-ring')), findsNothing);
      });

      testWidgets('partials replace each other after the typed prefix',
          (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        await tester.enterText(find.byType(TextField), 'Note:');
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        for (final t in ['a', 'a b', 'a b c']) {
          input.onText!(t, false);
          await tester.pump();
          expect(field(tester), 'Note: $t');
        }
        input.onText!('a b c d', true);
        await tester.pump();
        expect(field(tester), 'Note: a b c d');
      });

      testWidgets('a waveform shows while listening and follows the levels',
          (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        expect(find.byKey(const Key('mic-waveform')), findsNothing);
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        expect(find.byKey(const Key('mic-waveform')), findsOneWidget);
        expect(
            find.descendant(
                of: find.byKey(const Key('mic-waveform')),
                matching: find.byType(AnimatedContainer)),
            findsNWidgets(24));
        input.onLevel!(1);
        await tester.pump();
        await tester.pump(const Duration(milliseconds: 300));
        final bars = find.descendant(
            of: find.byKey(const Key('mic-waveform')),
            matching: find.byType(AnimatedContainer));
        expect(tester.getSize(bars.last).height,
            greaterThan(tester.getSize(bars.first).height));
        await tester.tap(find.byIcon(Icons.stop));
        await tester.pump();
        expect(find.byKey(const Key('mic-waveform')), findsNothing);
      });

      testWidgets('a first start that waits for permission ends up listening',
          (tester) async {
        final input =
            FakeSpeechInput(startDelay: const Duration(milliseconds: 500));
        await open(tester, input, FakeSpeechOutput());
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        // The prompt pauses the app; that must not cancel the start.
        tester.binding
            .handleAppLifecycleStateChanged(AppLifecycleState.inactive);
        tester.binding
            .handleAppLifecycleStateChanged(AppLifecycleState.resumed);
        await tester.pump(const Duration(milliseconds: 600));
        expect(input.starts, 1);
        expect(input.listening, isTrue);
        expect(find.byIcon(Icons.stop), findsOneWidget);
        input.onText!('hello', false);
        await tester.pump();
        expect(field(tester), 'hello');
      });

      testWidgets('a final result with no words shows a hint, typing clears it',
          (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        expect(find.byKey(const Key('voice-hint')), findsNothing);
        input.onText!('', true);
        await tester.pump();
        expect(find.byKey(const Key('voice-hint')), findsOneWidget);
        await tester.enterText(find.byType(TextField), 'x');
        await tester.pump();
        expect(find.byKey(const Key('voice-hint')), findsNothing);

        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        input.onError!('error_no_match');
        await tester.pump();
        expect(find.byKey(const Key('voice-hint')), findsOneWidget);
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        expect(find.byKey(const Key('voice-hint')), findsNothing);
      });

      testWidgets('the system locale is used and shown while listening',
          (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        expect(input.lastLocale, 'en_US');
        expect(find.text('en-US'), findsOneWidget);
      });

      testWidgets('a language chosen in the sheet is used and remembered',
          (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        await tester.longPress(find.byIcon(Icons.mic));
        await tester.pumpAndSettle();
        expect(find.text('Suggested'), findsOneWidget);
        await tester.enterText(find.byKey(const Key('locale-search')), 'dutch');
        await tester.pumpAndSettle();
        expect(find.text('German (Germany)'), findsNothing);
        await tester.tap(find.text('Dutch (Netherlands)'));
        await tester.pumpAndSettle();
        expect(
            (await SharedPreferences.getInstance()).getString('voice_locale'),
            'nl_NL');
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        expect(input.lastLocale, 'nl_NL');
        expect(find.text('nl-NL'), findsOneWidget);
      });

      testWidgets('partials after a permission pause update the field',
          (tester) async {
        final input =
            FakeSpeechInput(startDelay: const Duration(milliseconds: 500));
        await open(tester, input, FakeSpeechOutput());
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        for (final st in [
          AppLifecycleState.inactive,
          AppLifecycleState.hidden,
          AppLifecycleState.paused,
          AppLifecycleState.hidden,
          AppLifecycleState.inactive,
          AppLifecycleState.resumed,
        ]) {
          tester.binding.handleAppLifecycleStateChanged(st);
        }
        await tester.pump(const Duration(milliseconds: 600));
        for (final t in ['goe', 'goedemorgen']) {
          input.onText!(t, false);
          await tester.pump();
          expect(field(tester), t);
        }
        input.onText!('goedemorgen allemaal', true);
        await tester.pump();
        expect(field(tester), 'goedemorgen allemaal');
        expect(find.byKey(const Key('voice-hint')), findsNothing);
      });

      testWidgets('send is disabled for empty text and enabled with text',
          (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        bool enabled() =>
            tester
                .widget<IconButton>(
                    find.widgetWithIcon(IconButton, Icons.arrow_upward))
                .onPressed !=
            null;
        expect(enabled(), isFalse);
        await tester.enterText(find.byType(TextField), '   ');
        await tester.pump();
        expect(enabled(), isFalse);
        await tester.enterText(find.byType(TextField), 'hi');
        await tester.pump();
        expect(enabled(), isTrue);
        await tester.enterText(find.byType(TextField), '');
        await tester.pump();
        expect(enabled(), isFalse);
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        input.onText!('dictated', false);
        await tester.pump();
        expect(enabled(), isTrue);
      });

      testWidgets('sending stops listening', (tester) async {
        final input = FakeSpeechInput();
        await open(tester, input, FakeSpeechOutput());
        await tester.tap(find.byIcon(Icons.mic));
        await tester.pump();
        input.onText!('hi there', false);
        await tester.pump();
        await tester.tap(find.byTooltip('Send'));
        await tester.pumpAndSettle();
        expect(input.stops, 1);
        expect(input.listening, isFalse);
        expect(find.byIcon(Icons.mic), findsOneWidget);
        expect(field(tester), '');
      });

      testWidgets('read aloud on speaks a finished answer once',
          (tester) async {
        SharedPreferences.setMockInitialValues({'chat_read_aloud': true});
        final output = FakeSpeechOutput();
        await open(tester, FakeSpeechInput(), output);
        expect(find.byIcon(Icons.volume_up), findsOneWidget);
        await tester.enterText(find.byType(TextField), 'Hi');
        await tester.pump();
        await tester.tap(find.byTooltip('Send'));
        await tester.pumpAndSettle();
        expect(output.spoken, ['Hoi!']);
      });

      testWidgets('read aloud off never speaks', (tester) async {
        final output = FakeSpeechOutput();
        await open(tester, FakeSpeechInput(), output);
        expect(find.byIcon(Icons.volume_off), findsOneWidget);
        await tester.enterText(find.byType(TextField), 'Hi');
        await tester.pump();
        await tester.tap(find.byTooltip('Send'));
        await tester.pumpAndSettle();
        expect(output.spoken, isEmpty);
      });

      testWidgets('toggling off or sending stops speech, toggle persists',
          (tester) async {
        SharedPreferences.setMockInitialValues({'chat_read_aloud': true});
        final output = FakeSpeechOutput();
        await open(tester, FakeSpeechInput(), output);
        await tester.tap(find.byIcon(Icons.volume_up));
        await tester.pumpAndSettle();
        expect(output.stops, 1);
        expect(find.byIcon(Icons.volume_off), findsOneWidget);
        expect(
            (await SharedPreferences.getInstance()).getBool('chat_read_aloud'),
            isFalse);

        await tester.tap(find.byIcon(Icons.volume_off));
        await tester.pumpAndSettle();
        expect(
            (await SharedPreferences.getInstance()).getBool('chat_read_aloud'),
            isTrue);

        await tester.enterText(find.byType(TextField), 'Hi');
        await tester.pump();
        await tester.tap(find.byTooltip('Send'));
        await tester.pumpAndSettle();
        // Sending stopped speech first, then the new answer was read.
        expect(output.stops, 2);
        expect(output.spoken, ['Hoi!']);
      });
    });

    group('context picker', () {
      final recent = [
        (subject: 'r1', title: 'Trip plan', className: 'Document', openedAt: 5),
        (subject: 'r2', title: 'Budget', className: 'Table', openedAt: 9),
      ];

      testWidgets('a new chat offers drives and recent, not "No messages"',
          (tester) async {
        final api = FakeApi(ai: ai(), recent: recent);
        await tester.pumpWidget(app(ChatScreen(api: api)));
        await tester.pumpAndSettle();

        expect(find.text('No messages'), findsNothing);
        expect(find.text('Add context?'), findsOneWidget);
        expect(find.text('Drives'), findsNothing);
        expect(find.text('Recent'), findsNothing);
        expect(find.text('Home'), findsOneWidget);
        // Newest first, after the drive.
        expect(tester.getTopLeft(find.text('Budget')).dx,
            lessThan(tester.getTopLeft(find.text('Trip plan')).dx));
        expect(
            find.descendant(of: find.byType(Wrap), matching: find.byType(Icon)),
            findsNothing);
      });

      testWidgets('an existing chat with messages shows them, not the picker',
          (tester) async {
        final api = FakeApi(ai: ai(), messageList: [
          (id: 'p#1', role: 'user', text: 'Where to?', createdAt: 1),
        ]);
        await tester.pumpWidget(
            app(ChatScreen(api: api, subject: 'did:ad:chat', title: 'Trip')));
        await tester.pumpAndSettle();
        expect(find.text('Where to?'), findsOneWidget);
        expect(find.text('Add context?'), findsNothing);
        expect(
            tester
                .widget<TextField>(find.byType(TextField))
                .focusNode!
                .hasFocus,
            isFalse);
      });

      testWidgets('an existing empty chat shows the picker', (tester) async {
        await tester.pumpWidget(app(ChatScreen(
            api: FakeApi(ai: ai(), recent: recent), subject: 'did:ad:chat')));
        await tester.pumpAndSettle();
        expect(find.text('Add context?'), findsOneWidget);
      });

      testWidgets('the input has focus once the AI is ready', (tester) async {
        final lookup = Completer<HostedAi?>();
        await tester.pumpWidget(app(ChatScreen(api: _SlowAi(lookup.future))));
        await tester.pump();
        lookup.complete(ai());
        await tester.pumpAndSettle();
        final field = tester.widget<TextField>(find.byType(TextField));
        expect(field.focusNode!.hasFocus, isTrue);
      });

      testWidgets('tapping a pill toggles it by colour, with no icon',
          (tester) async {
        await tester.pumpWidget(
            app(ChatScreen(api: FakeApi(ai: ai(), recent: recent))));
        await tester.pumpAndSettle();
        Color? colour() =>
            tester.widget<Text>(find.text('Trip plan')).style!.color;
        final off = colour();
        await tester.tap(find.text('Trip plan'));
        await tester.pump();
        expect(colour(), isNot(off));
        expect(find.byType(Chip), findsNothing);
        expect(find.byIcon(Icons.check), findsNothing);
        await tester.tap(find.text('Trip plan'));
        await tester.pump();
        expect(colour(), off);
      });

      testWidgets('at most 5 pills: two drives, then the latest',
          (tester) async {
        final many = [
          for (var i = 0; i < 8; i++)
            (
              subject: 'r$i',
              title: 'Res $i',
              className: 'Document',
              openedAt: i
            ),
        ];
        await tester
            .pumpWidget(app(ChatScreen(api: FakeApi(ai: ai(), recent: many))));
        await tester.pumpAndSettle();
        // The one drive plus the four latest resources.
        expect(find.text('Home'), findsOneWidget);
        expect(find.textContaining('Res '), findsNWidgets(4));
        expect(find.text('Res 7'), findsOneWidget);
        expect(find.text('Res 4'), findsOneWidget);
        expect(find.text('Res 3'), findsNothing);
      });

      testWidgets('sending gives the AI the text of what was picked',
          (tester) async {
        final sent = <List<Map<String, String>>>[];
        final api = FakeApi(
          recent: recent,
          texts: {'r1': 'Day 1: Lisbon'},
          ai: HostedAi(
            status: {'enabled': true, 'consent': true, 'model': 'm'},
            stream: (messages, model) {
              sent.add(messages);
              return Stream.value('ok');
            },
            enable: () async => {},
          ),
        );
        await tester.pumpWidget(app(ChatScreen(api: api)));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Trip plan'));
        await tester.pump();

        await tester.enterText(find.byType(TextField), 'Summarize');
        await tester.pump();
        await tester.tap(find.byTooltip('Send'));
        await tester.pumpAndSettle();
        await tester.enterText(find.byType(TextField), 'More');
        await tester.pump();
        await tester.tap(find.byTooltip('Send'));
        await tester.pumpAndSettle();

        // Every message of the screen carries the context ahead of the chat.
        expect(sent, hasLength(2));
        for (final messages in sent) {
          final ctx = messages
              .firstWhere((m) => m['content']!.startsWith('The user attached'));
          expect(ctx['role'], 'system');
          expect(ctx['content'], contains('Trip plan (Document)'));
          expect(ctx['content'], contains('Day 1: Lisbon'));
        }
        // Not part of the chat log.
        expect(api.added.where((m) => m.$3.contains('Lisbon')), isEmpty);
      });

      testWidgets('without a pick nothing is added', (tester) async {
        List<Map<String, String>>? sent;
        final api = FakeApi(
          ai: HostedAi(
            status: {'enabled': true, 'consent': true, 'model': 'm'},
            stream: (messages, model) {
              sent = messages;
              return Stream.value('ok');
            },
            enable: () async => {},
          ),
        );
        await tester.pumpWidget(app(ChatScreen(api: api)));
        await tester.pumpAndSettle();
        await tester.enterText(find.byType(TextField), 'Hi');
        await tester.pump();
        await tester.tap(find.byTooltip('Send'));
        await tester.pumpAndSettle();
        expect(sent, hasLength(2));
      });
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
      await tester.pumpWidget(shellApp(ChatsScreen(
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

  group('native views', () {
    testWidgets('an ai-chat opens the chat, anything else the web view',
        (tester) async {
      ResourceView.serverFactory = () async => throw 'no server in a test';
      final api = FakeApi();
      Widget open(String className) => openResourceView(
          api: api,
          drive: 'did:ad:drive',
          subject: 'did:ad:x',
          title: 'X',
          className: className);

      await tester.pumpWidget(app(open('ai-chat')));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
      expect(find.byType(ResourceView), findsNothing);

      await tester.pumpWidget(app(open('Document')));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
      expect(find.byType(ChatScreen), findsNothing);

      await tester.pumpWidget(app(open('')));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
    });
  });

  group('AppShell', () {
    const doc =
        (subject: 'r1', title: 'A doc', className: 'Document', openedAt: 1);

    Future<void> pumpHome(WidgetTester tester) async {
      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.pumpWidget(shellApp(ChatsScreen(
          drive: 'did:ad:drive',
          api: FakeApi(recent: [doc]),
          onOpenGallery: () {})));
      await tester.pumpAndSettle();
    }

    double x(WidgetTester tester, String tip) =>
        tester.getCenter(find.byTooltip(tip)).dx;

    Future<void> pumpFieldShell(WidgetTester tester) async {
      tester.view.physicalSize = const Size(1200, 2400);
      tester.view.devicePixelRatio = 3;
      addTearDown(tester.view.reset);
      addTearDown(tester.view.resetViewInsets);
      await tester.pumpWidget(app(const AppShell(
        drive: 'd',
        home: Scaffold(
          body: SafeArea(
            top: false,
            child: Column(children: [
              Spacer(),
              TextField(key: Key('bottom-field')),
            ]),
          ),
        ),
      )));
      await tester.pumpAndSettle();
    }

    double fieldBottom(WidgetTester tester) =>
        tester.getBottomLeft(find.byKey(const Key('bottom-field'))).dy;

    testWidgets('the keyboard covers the bar; the page ends on the keyboard',
        (tester) async {
      await pumpFieldShell(tester);
      final screen = tester.view.physicalSize / tester.view.devicePixelRatio;
      final bar = find.byType(AppBottomBar);
      expect(bar, findsOneWidget);
      final barH = tester.getSize(bar).height;
      expect(fieldBottom(tester), closeTo(screen.height - barH, 0.5));

      tester.view.viewInsets = const FakeViewPadding(bottom: 900);
      await tester.pumpAndSettle();
      expect(bar, findsOneWidget);
      expect(fieldBottom(tester), closeTo(screen.height - 300, 0.5));

      // Smaller than the bar: the field must not move below the bar.
      tester.view.viewInsets = const FakeViewPadding(bottom: 120);
      await tester.pumpAndSettle();
      expect(fieldBottom(tester), closeTo(screen.height - barH, 0.5));

      tester.view.resetViewInsets();
      await tester.pumpAndSettle();
      expect(fieldBottom(tester), closeTo(screen.height - barH, 0.5));
    });

    testWidgets('closing the keyboard moves the page and the bar together',
        (tester) async {
      await pumpFieldShell(tester);
      final screen = tester.view.physicalSize / tester.view.devicePixelRatio;
      final bar = find.byType(AppBottomBar);
      final barTop = tester.getTopLeft(bar);
      final barSize = tester.getSize(bar);
      final barH = barSize.height;
      tester.view.viewInsets = const FakeViewPadding(bottom: 900);
      await tester.pumpAndSettle();

      for (final kb in [300.0, 200.0, 100.0, 40.0, 0.0]) {
        tester.view.viewInsets = FakeViewPadding(bottom: kb * 3);
        await tester.pump(const Duration(milliseconds: 16));
        expect(fieldBottom(tester),
            closeTo(screen.height - math.max(kb, barH), 0.5),
            reason: 'keyboard $kb');
        expect(tester.getTopLeft(bar), barTop);
        expect(tester.getSize(bar), barSize);
      }
      expect(tester.hasRunningAnimations, isFalse);
    });

    testWidgets('the bar stays put while a page slides in', (tester) async {
      await pumpHome(tester);
      final bar = find.byType(AppBottomBar);
      final before = tester.getTopLeft(bar);
      final element = tester.element(bar);

      await tester.tap(find.text('A doc'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));
      // Mid-transition: the page is moving, the bar is not.
      expect(tester.getTopLeft(bar), before);
      expect(tester.element(bar), same(element));
      expect(tester.getTopLeft(find.byType(ResourceView)).dx, greaterThan(0));
      await tester.pumpAndSettle();
      expect(tester.getTopLeft(bar), before);
      expect(tester.element(bar), same(element));
    });

    testWidgets('buttons keep their order: search, new chat, profile, last',
        (tester) async {
      await pumpHome(tester);
      expect(x(tester, 'Search'), lessThan(x(tester, 'New chat')));
      expect(x(tester, 'New chat'), lessThan(x(tester, 'Profile')));
      expect(x(tester, 'Profile'), lessThan(x(tester, 'Settings')));
      final xs = [
        for (final t in ['Search', 'New chat', 'Profile']) x(tester, t)
      ];

      await tester.tap(find.text('A doc'));
      await tester.pumpAndSettle();
      expect(x(tester, 'Profile'), lessThan(x(tester, 'More')));
      expect([
        for (final t in ['Search', 'New chat', 'Profile']) x(tester, t)
      ], xs);
    });

    testWidgets('the last button follows the page on top', (tester) async {
      await pumpHome(tester);
      expect(find.byTooltip('Settings'), findsOneWidget);
      expect(find.byTooltip('More'), findsNothing);

      await tester.tap(find.text('A doc'));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
      expect(find.byTooltip('More'), findsOneWidget);
      expect(find.byTooltip('Settings'), findsNothing);

      // Another page over the resource: no menu of its own, so Settings.
      await tester.tap(find.byTooltip('New chat'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
      expect(find.byTooltip('Settings'), findsOneWidget);
      expect(find.byTooltip('More'), findsNothing);

      // Back to the resource: its menu is the active one again.
      tester.state<NavigatorState>(find.byType(Navigator).last).pop();
      await tester.pumpAndSettle();
      expect(find.byTooltip('More'), findsOneWidget);
      expect(find.byTooltip('Settings'), findsNothing);

      // And back to the home.
      tester.state<NavigatorState>(find.byType(Navigator).last).pop();
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsNothing);
      expect(find.byTooltip('Settings'), findsOneWidget);
      expect(find.byTooltip('More'), findsNothing);
    });

    testWidgets('a settings page has no menu: the bar keeps Settings',
        (tester) async {
      await pumpHome(tester);
      await tester.tap(find.byTooltip('Settings'));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
      expect(find.byTooltip('Settings'), findsOneWidget);
      expect(find.byTooltip('More'), findsNothing);
    });

    testWidgets('there is no Back button anywhere', (tester) async {
      await pumpHome(tester);
      expect(find.byTooltip('Back'), findsNothing);
      await tester.tap(find.text('A doc'));
      await tester.pumpAndSettle();
      expect(find.byTooltip('Back'), findsNothing);
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
  group('SearchScreen opens fast', () {
    testWidgets('settles within 160 ms, field at the bottom', (tester) async {
      await tester.pumpWidget(shellApp(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Search'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 160));
      final settled = tester.getTopLeft(find.byType(TextField));
      final fade = find
          .ancestor(
              of: find.byType(SearchScreen), matching: find.byType(Opacity))
          .first;
      expect(tester.widget<Opacity>(fade).opacity, 1);
      await tester.pumpAndSettle();
      expect(tester.getTopLeft(find.byType(TextField)), settled);
      final screen = tester.view.physicalSize / tester.view.devicePixelRatio;
      expect(settled.dy, greaterThan(screen.height * 0.7));
    });

    testWidgets('the covered page does not follow the keyboard',
        (tester) async {
      var builds = 0;
      await tester.pumpWidget(app(AppShell(
        api: FakeApi(),
        drive: 'did:ad:drive',
        home: Builder(builder: (context) {
          MediaQuery.of(context);
          builds++;
          return const Scaffold(body: Text('probe page'));
        }),
      )));
      await tester.pumpAndSettle();
      addTearDown(tester.view.resetViewInsets);

      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      final before = builds;
      for (var b = 50.0; b <= 500; b += 50) {
        tester.view.viewInsets = FakeViewPadding(bottom: b);
        await tester.pump(const Duration(milliseconds: 16));
      }
      expect(builds, before);
      // Closing it in steps does not rebuild the covered page either.
      for (var b = 450.0; b >= 0; b -= 50) {
        tester.view.viewInsets = FakeViewPadding(bottom: b);
        await tester.pump(const Duration(milliseconds: 16));
      }
      expect(builds, before);
      tester.view.viewInsets = const FakeViewPadding(bottom: 500);
      await tester.pump();
      // The page on top does follow it.
      expect(find.byType(SearchScreen), findsOneWidget);

      // Back on top, it is live again.
      tester.view.resetViewInsets();
      await tester.pump();
      await tester.tap(find.byTooltip('Back'));
      await tester.pumpAndSettle();
      await tester.pump(CoveredInsetsFreeze.hold);
      final back = builds;
      tester.view.viewInsets = const FakeViewPadding(bottom: 200);
      await tester.pump();
      expect(builds, greaterThan(back));
    });

    testWidgets('Home goes back to the home screen from any page',
        (tester) async {
      await tester.pumpWidget(shellApp(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onOpenGallery: () {})));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('New chat'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
      // Home sits first in the row.
      expect(tester.getCenter(find.byTooltip('Home')).dx,
          lessThan(tester.getCenter(find.byTooltip('Search')).dx));
      await tester.tap(find.byTooltip('Home'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsNothing);
      expect(find.byType(ChatsScreen), findsOneWidget);
    });

    testWidgets(
        'one drives call per open; the second open shows cached recents',
        (tester) async {
      Finder inSearch(String t) => find.descendant(
          of: find.byType(SearchScreen), matching: find.text(t));
      final api = FakeApi(recent: [
        (
          subject: 'r1',
          title: 'Opened doc',
          className: 'Document',
          openedAt: 1
        ),
      ]);
      await tester.pumpWidget(shellApp(
          ChatsScreen(drive: 'did:ad:drive', api: api, onOpenGallery: () {})));
      await tester.pumpAndSettle();

      var calls = api.drivesCalls;
      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(api.drivesCalls - calls, 1);
      expect(inSearch('Opened doc'), findsOneWidget);

      await tester.tap(find.byTooltip('Back'));
      await tester.pumpAndSettle();

      // The refresh is still on its way when the list is first painted.
      final gate = Completer<void>();
      api.drivesGate = gate.future;
      calls = api.drivesCalls;
      await tester.tap(find.byTooltip('Search'));
      await tester.pump();
      expect(inSearch('Opened doc'), findsOneWidget);
      expect(api.drivesCalls - calls, 1);
      gate.complete();
      await tester.pumpAndSettle();
      expect(api.drivesCalls - calls, 1);
      expect(inSearch('Opened doc'), findsOneWidget);
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
