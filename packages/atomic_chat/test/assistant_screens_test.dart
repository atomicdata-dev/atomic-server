import 'dart:async';
import 'dart:math' as math;
import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'unimplemented_api.dart';

class FakeApi extends UnimplementedApi {
  final List<DriveInfo> driveList;
  final List<RecentResource> recent;
  final List<RecentResource> favoriteList;
  final List<RecentResource> conversationList;
  List<NotificationItem> notificationList;
  final List<String> markedRead = [];

  /// The newest message text of each conversation, by subject.
  final Map<String, String> lastMessages;
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

  /// The emojis `resourceIcons` answers with.
  final Map<String, String> icons;

  /// How many times `drives()` was asked, and an optional gate it waits on.
  int drivesCalls = 0;
  Future<void>? drivesGate;

  FakeApi({
    this.notificationList = const [],
    this.driveList = const [
      (subject: 'did:ad:drive', name: 'Home', emoji: null)
    ],
    this.recent = const [],
    this.favoriteList = const [],
    this.conversationList = const [],
    this.lastMessages = const {},
    this.activityList = const [],
    this.ai,
    this.chatList = const [],
    this.messageList = const [],
    this.hits = const [],
    this.texts = const {},
    this.icons = const {},
  });

  /// How many times each list was asked for, by method name.
  final Map<String, int> calls = {};
  void _count(String what) => calls[what] = (calls[what] ?? 0) + 1;

  @override
  Future<Map<String, String>> resourceIcons(List<String> subjects) async {
    _count('resourceIcons');
    return {
      for (final e in icons.entries)
        if (subjects.contains(e.key)) e.key: e.value,
    };
  }

  @override
  Future<String?> agentName() async => 'Joep';
  @override
  Future<List<DriveInfo>> drives() async {
    drivesCalls++;
    _count('drives');
    await drivesGate;
    return driveList;
  }

  @override
  Future<List<ChatSummary>> chats() async {
    _count('chats');
    return chatList;
  }

  @override
  Future<List<ActivityEntry>> activity(int limit) async {
    _count('activity');
    return activityList.take(limit).toList();
  }

  @override
  Future<List<RecentResource>> recentResources(String drive) async {
    _count('recentResources');
    return recent;
  }

  @override
  Future<List<RecentResource>> favorites() async {
    _count('favorites');
    return favoriteList;
  }

  @override
  Future<List<NotificationItem>> notifications() async {
    _count('notifications');
    return notificationList;
  }

  @override
  Future<void> markNotificationRead(String subject) async {
    markedRead.add(subject);
    notificationList = [
      for (final n in notificationList)
        n.subject == subject
            ? (
                subject: n.subject,
                title: n.title,
                body: n.body,
                about: n.about,
                kind: n.kind,
                occurredAt: n.occurredAt,
                read: true
              )
            : n,
    ];
  }

  @override
  Future<List<ConversationRow>> conversations() async {
    _count('conversations');
    return [
      for (final r in conversationList)
        (resource: r, lastMessage: lastMessages[r.subject] ?? ''),
    ];
  }

  @override
  Future<List<ChatMessage>> messages(String chat) async => messageList;
  @override
  Future<List<ConversationMessage>> conversationMessages(String s) async =>
      const [];
  @override
  Future<void> followConversation(String subject) async {}
  @override
  Future<List<SearchHit>> search(String query, {String? drive}) async {
    asked.add(query);
    final gate = searchGate;
    if (gate != null) await gate;
    return hits;
  }

  /// When set, a search answers only once it completes.
  Future<void>? searchGate;

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

  /// When set, stop() delivers this as the final result after
  /// [finalDelay] (like the plugin does); otherwise none arrives.
  String? finalOnStop;
  Duration finalDelay = Duration.zero;

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
    final text = finalOnStop;
    if (text != null) {
      if (finalDelay > Duration.zero) await Future<void>.delayed(finalDelay);
      onText?.call(text, true);
    }
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

/// A tap on + lists the kinds; AI chat starts a new chat.
Future<void> tapNewChat(WidgetTester tester) async {
  await tester.tap(find.byTooltip('New'));
  await tester.pump();
  await tester.tap(find.text('AI chat'));
}

void main() {
  group('ChatsScreen', () {
    // On a phone, scrolling the home back up never reached the top: each
    // section that scrolled out of the list's cache was rebuilt with a
    // spinner when it came back and only then got its rows, so the list
    // placed it too small, found the top was not at 0 and corrected the
    // offset downwards: the page kept moving down while being pulled up.
    testWidgets(
        'the home scrolls back to the top without jumping, and idling or '
        'pulling at the top asks for nothing again', (tester) async {
      tester.view.physicalSize = const Size(1080, 2340);
      tester.view.devicePixelRatio = 2.75;
      addTearDown(tester.view.reset);
      final now = DateTime.now().millisecondsSinceEpoch;
      RecentResource res(String s) => (
            subject: s,
            title: 'Doc $s',
            className: 'Document',
            openedAt: now - 60 * 60 * 1000,
            emoji: null
          );
      final api = FakeApi(
        driveList: [
          for (var i = 0; i < 6; i++)
            (subject: 'did:ad:drive$i', name: 'Drive $i', emoji: '📁'),
        ],
        favoriteList: [for (var i = 0; i < 6; i++) res('f$i')],
        conversationList: [for (var i = 0; i < 6; i++) res('c$i')],
        activityList: [for (var i = 0; i < 6; i++) _activity('a$i', 'A $i')],
        chatList: [
          for (var i = 0; i < 6; i++)
            (subject: 'chat$i', name: 'Chat $i', lastActivity: now),
        ],
        notificationList: [
          for (var i = 0; i < 6; i++)
            (
              subject: 'n$i',
              title: 'Note $i',
              body: 'body',
              about: 'x$i',
              kind: 'chat',
              occurredAt: now,
              read: false
            ),
        ],
      );
      await tester
          .pumpWidget(shellApp(ChatsScreen(drive: 'did:ad:drive0', api: api)));
      await tester.pumpAndSettle();
      final asked = Map.of(api.calls);

      final position =
          tester.state<ScrollableState>(find.byType(Scrollable).first).position;
      expect(position.maxScrollExtent, greaterThan(800));

      // Down to the bottom, one finger stroke at a time.
      final list = find.byType(ListView).first;
      while (position.pixels < position.maxScrollExtent) {
        await tester.drag(list, const Offset(0, -300));
        await tester.pumpAndSettle();
      }

      // Then pulled up slowly: the page follows the finger, and stops at the
      // top.
      final g = await tester.startGesture(tester.getCenter(list));
      var last = position.pixels;
      final jumps = <String>[];
      for (var i = 0; i < 400; i++) {
        await g.moveBy(const Offset(0, 20));
        await tester.pump(const Duration(milliseconds: 16));
        // The finger moved 20 px: so does the page, or less at the top.
        final moved = last - position.pixels;
        if (moved < -0.5 || moved > 20.5) {
          jumps.add('${last.round()} -> ${position.pixels.round()}');
        }
        last = position.pixels;
      }
      await g.up();
      await tester.pumpAndSettle();
      expect(jumps, isEmpty, reason: 'the page jumped while pulled up');
      expect(position.pixels, 0);

      // Idle for half a minute: nothing reloads.
      await tester.pump(const Duration(seconds: 30));
      await tester.pumpAndSettle();
      expect(api.calls, asked);
    });

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
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();

      expect(find.text('Trip plan'), findsOneWidget);
      expect(find.text('Untitled chat'), findsOneWidget);

      await tester.tap(find.text('Trip plan'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
      expect(find.text('Where to?'), findsOneWidget);
      expect(find.text('Lisbon.'), findsOneWidget);
    });

    testWidgets(
        'notifications sit after Drives, unread marked and counted; a tap opens '
        'the subject and reads it; hidden when empty', (tester) async {
      final now = DateTime.now().millisecondsSinceEpoch;
      final api = FakeApi(
        chatList: [(subject: 'c1', name: 'A chat', lastActivity: 0)],
        notificationList: [
          (
            subject: 'n1',
            title: 'Polle in Team chat',
            body: 'See you at ten',
            about: 'did:ad:teamchat',
            kind: 'chat',
            occurredAt: now - 5 * 60 * 1000,
            read: false
          ),
          (
            subject: 'n2',
            title: 'Old news',
            body: '',
            about: 'did:ad:old',
            kind: 'chat',
            occurredAt: now - 3 * 3600 * 1000,
            read: true
          ),
        ],
      );
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      double y(String t) => tester.getTopLeft(find.text(t)).dy;
      expect(y('Notifications'), greaterThan(y('Drives')));
      expect(find.text('1'), findsOneWidget); // the unread badge
      expect(find.text('Polle in Team chat'), findsOneWidget);
      expect(find.text('See you at ten'), findsOneWidget);
      expect(find.text('5 min ago'), findsOneWidget);
      expect(find.byKey(const Key('notification-unread')), findsOneWidget);

      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.tap(find.text('Polle in Team chat'));
      await tester.pump();
      expect(api.markedRead, ['n1']);
      // Noted once the page is left (no list moves under the finger).
      expect(api.opened, isEmpty);
      await _leave(tester);
      expect(api.opened, ['did:ad:teamchat']);
      await tester.pump(const Duration(milliseconds: 500));
    });

    testWidgets('a section hidden when empty stays hidden while it loads',
        (tester) async {
      final pending = Completer<List<NotificationItem>>();
      await tester.pumpWidget(app(ChatsScreen(
          drive: 'did:ad:drive', api: _SlowNotifications(pending.future))));
      await tester.pump(const Duration(milliseconds: 100));
      expect(find.text('Notifications'), findsNothing);
      expect(find.text('Drives'), findsOneWidget);
      pending.complete(const []);
      await tester.pumpAndSettle();
      expect(find.text('Notifications'), findsNothing);
    });

    testWidgets('sideways, the headings keep out of the cutout like the rows',
        (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(900, 400);
      tester.view.padding = const FakeViewPadding(left: 60);
      addTearDown(tester.view.reset);
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      expect(tester.getTopLeft(find.text('Drives')).dx, greaterThan(60));
    });

    testWidgets('no notifications, no Notifications section', (tester) async {
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      expect(find.text('Notifications'), findsNothing);
      expect(find.text('No notifications'), findsNothing);
    });

    testWidgets('flicking down at the top does not stretch or bounce the home',
        (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      final api = FakeApi(
        chatList: [
          for (var i = 0; i < 6; i++)
            (subject: 'c$i', name: 'Chat $i', lastActivity: 0),
        ],
      );
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      final list = find.byType(ListView);
      double offset() => tester
          .state<ScrollableState>(
              find.descendant(of: list, matching: find.byType(Scrollable)))
          .position
          .pixels;
      expect(offset(), 0);
      expect(find.byType(StretchingOverscrollIndicator), findsNothing);
      await tester.fling(list, const Offset(0, 600), 3000);
      await tester.pump(const Duration(milliseconds: 100));
      expect(offset(), 0);
      await tester.pumpAndSettle();
      expect(offset(), 0);
      // And a flick up to the bottom ends there, not back above it.
      await tester.fling(list, const Offset(0, -2000), 3000);
      await tester.pumpAndSettle();
      final max = tester
          .state<ScrollableState>(
              find.descendant(of: list, matching: find.byType(Scrollable)))
          .position
          .maxScrollExtent;
      expect(offset(), max);
      debugDefaultTargetPlatformOverride = null;
    });

    testWidgets('a tap on a heading folds its section', (tester) async {
      final api = FakeApi(
        chatList: [(subject: 'c1', name: 'A chat', lastActivity: 0)],
      );
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.text('A chat'), findsOneWidget);
      await tester.tap(find.text('AI chats'));
      await tester.pumpAndSettle();
      expect(find.text('A chat'), findsNothing);
      expect(find.text('AI chats'), findsOneWidget);
      await tester.tap(find.text('AI chats'));
      await tester.pumpAndSettle();
      expect(find.text('A chat'), findsOneWidget);
    });

    group('holding a heading opens the Home sections dialog', () {
      setUp(() => SharedPreferences.setMockInitialValues({}));

      Future<void> pumpHome(WidgetTester tester) async {
        final api = FakeApi(
          chatList: [(subject: 'c1', name: 'A chat', lastActivity: 0)],
          favoriteList: [
            (
              subject: 'f1',
              title: 'A star',
              className: 'Document',
              openedAt: 1,
              emoji: null
            ),
          ],
        );
        await tester
            .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
        await tester.pumpAndSettle();
      }

      Future<void> hold(WidgetTester tester, String heading) async {
        await tester.longPress(find.text(heading));
        await tester.pumpAndSettle();
      }

      double y(WidgetTester tester, String t) =>
          tester.getTopLeft(find.text(t).first).dy;

      Finder box(String title) => find.descendant(
          of: find.byKey(ValueKey('home-section-${_name(title)}')),
          matching: find.byType(Checkbox));

      testWidgets('it lists every section with a checkbox', (tester) async {
        await pumpHome(tester);
        await hold(tester, 'AI chats');
        expect(find.text('Home sections'), findsOneWidget);
        for (final s in HomeSection.values) {
          expect(
              find.descendant(
                  of: find.byKey(ValueKey('home-section-${s.name}')),
                  matching: find.byType(Checkbox)),
              findsOneWidget,
              reason: s.title);
        }
        expect(find.text('Reset to default'), findsOneWidget);
      });

      testWidgets('unchecking hides the section on Home, at once',
          (tester) async {
        await pumpHome(tester);
        expect(find.text('A star'), findsOneWidget);
        await hold(tester, 'Favorites');
        await tester.tap(box('Favorites'));
        await tester.pumpAndSettle();
        expect(find.text('A star'), findsNothing);
        await tester.tap(box('Favorites'));
        await tester.pumpAndSettle();
        expect(find.text('A star'), findsOneWidget);
      });

      testWidgets('dragging a row changes the Home order and it is kept',
          (tester) async {
        await pumpHome(tester);
        expect(y(tester, 'AI chats'), lessThan(y(tester, 'Favorites')));
        await hold(tester, 'AI chats');
        // Drag Favorites up by two rows (above Activity and AI chats).
        final handle = find.descendant(
            of: find.byKey(const ValueKey('home-section-favorites')),
            matching: find.byIcon(Icons.drag_handle));
        final g = await tester.startGesture(tester.getCenter(handle));
        await tester.pump(const Duration(milliseconds: 100));
        await g.moveBy(const Offset(0, -60));
        await tester.pump();
        await g.moveBy(const Offset(0, -60));
        await tester.pump();
        await g.up();
        await tester.pumpAndSettle();
        await tester.tap(find.text('Done'));
        await tester.pumpAndSettle();
        expect(y(tester, 'Favorites'), lessThan(y(tester, 'AI chats')));

        // A fresh screen with the same stored prefs: same order.
        await tester.pumpWidget(const SizedBox());
        await pumpHome(tester);
        expect(y(tester, 'Favorites'), lessThan(y(tester, 'AI chats')));
      });

      testWidgets('reset to default brings everything back', (tester) async {
        await pumpHome(tester);
        await hold(tester, 'AI chats');
        await tester.tap(box('AI chats'));
        await tester.pumpAndSettle();
        expect(find.text('A chat'), findsNothing);
        await tester.tap(find.text('Reset to default'));
        await tester.pumpAndSettle();
        expect(find.text('A chat'), findsOneWidget);
      });

      testWidgets('all off shows a Customize button that reopens it',
          (tester) async {
        await pumpHome(tester);
        await hold(tester, 'AI chats');
        for (final s in HomeSection.values) {
          await tester.tap(box(s.title));
          await tester.pumpAndSettle();
        }
        await tester.tap(find.text('Done'));
        await tester.pumpAndSettle();
        expect(find.text('Customize'), findsOneWidget);
        await tester.tap(find.text('Customize'));
        await tester.pumpAndSettle();
        expect(find.text('Home sections'), findsOneWidget);
      });

      testWidgets('a stored "recents" is ignored', (tester) async {
        SharedPreferences.setMockInitialValues({
          homeOrderKey: ['recents', 'chats'],
          homeHiddenKey: ['recents'],
        });
        await pumpHome(tester);
        expect(find.text('A chat'), findsOneWidget);
      });
    });

    testWidgets('keeps the old rows while a reload is pending', (tester) async {
      final api = _SlowChatsApi(
        chatList: [(subject: 'did:ad:1', name: 'Trip plan', lastActivity: 5)],
        messageList: [
          (id: 'p#1', role: 'user', text: 'Where to?', createdAt: 1),
        ],
      );
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
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
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
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
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      expect(find.text('No chats yet'), findsOneWidget);
    });

    testWidgets('reaches the search', (tester) async {
      await tester.pumpWidget(shellApp(
        ChatsScreen(drive: 'did:ad:drive', api: FakeApi()),
        brightness: Brightness.dark,
      ));
      await tester.pumpAndSettle();

      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen), findsOneWidget);
    });

    // Seen on a phone: a document made with New, typed in and found with
    // Search was missing from Activity back on the home, which
    // only reloaded after pages it had opened itself.
    testWidgets('reads its lists again when a page of the bar closes',
        (tester) async {
      final api = FakeApi();
      await tester
          .pumpWidget(shellApp(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      final before = api.calls['activity'];

      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(api.calls['activity'], before, reason: 'not while covered');
      Navigator.of(tester.element(find.byType(SearchScreen))).pop();
      await tester.pumpAndSettle();

      expect(api.calls['activity'], before! + 1);
      expect(api.calls['chats'], greaterThan(1));
    });

    testWidgets('sections come in order: Drives, AI chats, Favorites',
        (tester) async {
      final api = FakeApi(
        chatList: [(subject: 'c1', name: 'A chat', lastActivity: 0)],
        favoriteList: [
          (
            subject: 'r1',
            title: 'A doc',
            className: 'Document',
            openedAt: 1,
            emoji: null
          ),
        ],
      );
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      double y(String t) => tester.getTopLeft(find.text(t)).dy;
      expect(y('Drives'), lessThan(y('AI chats')));
      expect(y('AI chats'), lessThan(y('Favorites')));
      // No "Show all" text: an All button per section with something in it.
      expect(find.text('Show all'), findsNothing);
    });

    testWidgets('Favorites and Messages come after AI chats, hidden if empty',
        (tester) async {
      tester.view.physicalSize = const Size(800, 3000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      Future<void> pump(FakeApi api) async {
        await tester.pumpWidget(const SizedBox());
        await tester
            .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
        await tester.pumpAndSettle();
      }

      await pump(FakeApi());
      expect(find.text('Favorites'), findsNothing);
      expect(find.text('Messages'), findsNothing);

      final api = FakeApi(
        chatList: [(subject: 'c1', name: 'A chat', lastActivity: 0)],
        favoriteList: [
          (
            subject: 'f1',
            title: 'Starred',
            className: 'Folder',
            openedAt: 0,
            emoji: null
          ),
        ],
        conversationList: [
          (
            subject: 'm1',
            title: 'Alice, Bob',
            className: '',
            openedAt: 0,
            emoji: null
          ),
        ],
      );
      await pump(api);
      double y(String t) => tester.getTopLeft(find.text(t)).dy;
      expect(y('AI chats'), lessThan(y('Favorites')));
      expect(y('Favorites'), lessThan(y('Messages')));
      expect(find.text('Starred'), findsOneWidget);
      expect(find.text('Folder'), findsOneWidget);

      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.tap(find.text('Alice, Bob'));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
      // Noted once the page is left (no list moves under the finger).
      expect(api.opened, isEmpty);
      await _leave(tester);
      expect(api.opened, ['m1']);
    });

    testWidgets('Messages rows show the newest message and open natively',
        (tester) async {
      final api = FakeApi(
        conversationList: [
          (
            subject: 'm1',
            title: 'Alice, Bob',
            className: 'conversation',
            openedAt: 0,
            emoji: null
          ),
        ],
        lastMessages: {'m1': 'See you\n  tomorrow'},
      );
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.text('See you tomorrow'), findsOneWidget);

      await tester.tap(find.text('Alice, Bob'));
      await tester.pumpAndSettle();
      expect(find.byType(ConversationScreen), findsOneWidget);
      expect(find.byType(ResourceView), findsNothing);
    });

    testWidgets('Favorites shows 4, Show all lists the rest', (tester) async {
      final api = FakeApi(favoriteList: [
        for (var i = 0; i < 6; i++)
          (
            subject: 'f$i',
            title: 'Fav $i',
            className: '',
            openedAt: 0,
            emoji: null
          ),
      ]);
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.text('Fav 4'), findsNothing);
      await tester
          .tap(find.byKey(const ValueKey('section-show-all-favorites')));
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
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.text('Chat 3'), findsOneWidget);
      expect(find.text('Chat 4'), findsNothing);
      expect(find.text('Show all (6)'), findsOneWidget);

      await tester.tap(find.byKey(const ValueKey('section-show-all-chats')));
      await tester.pumpAndSettle();
      expect(find.text('Chat 5'), findsOneWidget);
      expect(find.text('Today'), findsOneWidget);
    });

    testWidgets('Activity sits between Drives and AI chats', (tester) async {
      final api = FakeApi(
        chatList: [(subject: 'c1', name: 'A chat', lastActivity: 0)],
        favoriteList: [
          (
            subject: 'r1',
            title: 'A doc',
            className: 'Document',
            openedAt: 1,
            emoji: null
          ),
        ],
        activityList: [_activity('a1', 'Plan')],
      );
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      double y(String t) => tester.getTopLeft(find.text(t)).dy;
      expect(y('Drives'), lessThan(y('Activity')));
      expect(y('Activity'), lessThan(y('AI chats')));
      expect(find.text('Ann edited · 5 min ago'), findsOneWidget);
    });

    testWidgets('says so when there is no activity', (tester) async {
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      expect(find.text('No activity from others yet'), findsOneWidget);
    });

    testWidgets('activity shows 4, Show all appears with more than 4',
        (tester) async {
      Future<void> pump(int n) async {
        await tester.pumpWidget(Container());
        await tester.pumpWidget(app(ChatsScreen(
            drive: 'did:ad:drive',
            api: FakeApi(activityList: [
              for (var i = 0; i < n; i++) _activity('a$i', 'Item $i'),
            ]))));
        await tester.pumpAndSettle();
      }

      await pump(0);
      expect(find.textContaining('Show all'), findsNothing);

      await pump(4);
      expect(find.text('Item 3'), findsOneWidget);
      expect(find.textContaining('Show all'), findsNothing);

      await pump(6);
      expect(find.text('Item 3'), findsOneWidget);
      expect(find.text('Item 4'), findsNothing);
      await tester.tap(find.byKey(const ValueKey('section-show-all-activity')));
      await tester.pumpAndSettle();
      expect(find.text('Item 5'), findsOneWidget);
    });

    testWidgets(
        'headings are a title and a chevron: no search, + or list '
        'buttons', (tester) async {
      final now = DateTime.now().millisecondsSinceEpoch;
      final api = FakeApi(
        chatList: [
          for (var i = 0; i < 6; i++)
            (subject: 'c$i', name: 'Chat $i', lastActivity: now),
        ],
        activityList: [_activity('a1', 'Plan')],
      );
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.byType(IconButton), findsNothing);
      expect(find.byIcon(Icons.search), findsNothing);
      expect(find.byIcon(Icons.add), findsNothing);
      expect(find.byIcon(Icons.format_list_bulleted), findsNothing);
      // The Activity filter is the full page's, not the section's.
      expect(find.byType(ShowMineChip), findsNothing);
      expect(find.widgetWithText(FilterChip, 'Show mine'), findsNothing);
      // The Show all row is a 48 dp row at the rows' 16 dp inset.
      final row = find.byKey(const ValueKey('section-show-all-chats'));
      expect(tester.getSize(row).height, 48);
      expect(tester.getTopLeft(find.text('Show all (6)')).dx, 16);
    });

    testWidgets('a deleted entry is not tappable, a changed one opens',
        (tester) async {
      final api = FakeApi(activityList: [
        _activity('gone', 'Old note', kind: 'deleted', actor: null),
        _activity('here', 'Fresh note', kind: 'created'),
      ]);
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.text('Unknown member deleted · 5 min ago'), findsOneWidget);
      ListTile tile(String title) => tester.widget<ListTile>(
          find.ancestor(of: find.text(title), matching: find.byType(ListTile)));
      expect(tile('Old note').onTap, isNull);

      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.tap(find.text('Fresh note'));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
    });

    testWidgets('a drive opens as a resource page', (tester) async {
      final api = _PerDrive(
        driveList: [(subject: 'did:ad:a', name: 'Alpha', emoji: null)],
        byDrive: {
          'did:ad:a': [
            for (var i = 0; i < 6; i++)
              (
                subject: 'a$i',
                title: 'Doc $i',
                className: '',
                openedAt: i,
                emoji: null
              ),
          ],
        },
      );
      await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:a', api: api)));
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
      await tester.pumpWidget(
          shellApp(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsNothing);
      final tips = ['Search', 'New', 'Profile', 'Settings'];
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
      await tester.pumpWidget(
          shellApp(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen), findsOneWidget);
    });

    testWidgets('New chat opens a chat', (tester) async {
      await tester.pumpWidget(
          shellApp(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsOneWidget);
    });

    testWidgets('Settings opens the settings page', (tester) async {
      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.pumpWidget(
          shellApp(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
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
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.textContaining('No active drive'), findsOneWidget);
    });
  });

  group('resource icons', () {
    testWidgets('home Favorites shows the emoji of a row that has one',
        (tester) async {
      final api = FakeApi(favoriteList: [
        (
          subject: 'r1',
          title: 'Fox doc',
          className: 'Document',
          openedAt: 2,
          emoji: '🦊'
        ),
        (
          subject: 'r2',
          title: 'Plain table',
          className: 'Table',
          openedAt: 1,
          emoji: null
        ),
      ], driveList: const [
        (subject: 'did:ad:drive', name: 'Home', emoji: '🏔'),
      ], activityList: [
        _activity('a1', 'Active thing'),
      ], icons: {
        'a1': '🚀'
      });
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.text('🦊'), findsOneWidget);
      expect(find.text('🏔'), findsOneWidget);
      // Filled in after the activity list was shown.
      expect(find.text('🚀'), findsOneWidget);
      expect(find.byIcon(Icons.table_chart_outlined), findsOneWidget);
      // The drive with an emoji has no folder icon.
      expect(find.byIcon(Icons.folder_outlined), findsNothing);
    });

    testWidgets('search results show the emoji, else the class icon',
        (tester) async {
      final api = FakeApi(hits: [
        (
          subject: 'did:ad:1',
          title: 'Fox',
          className: 'Document',
          drive: '',
          score: 2.0,
          emoji: '🦊'
        ),
        (
          subject: 'did:ad:2',
          title: 'Board',
          className: 'Canvas',
          drive: '',
          score: 1.0,
          emoji: null
        ),
      ]);
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.enterText(find.byType(TextField), 'f');
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();
      expect(find.text('🦊'), findsOneWidget);
      expect(find.byIcon(Icons.draw_outlined), findsOneWidget);
      expect(find.byIcon(Icons.description_outlined), findsNothing);
    });

    testWidgets('the new-chat context pills prefix the emoji', (tester) async {
      final api = FakeApi(
          ai: HostedAi(
            status: {'enabled': true, 'consent': true, 'model': 'm'},
            stream: (messages, model) => const Stream.empty(),
            enable: () async => {'enabled': true, 'consent': true},
          ),
          recent: [
            (
              subject: 'r1',
              title: 'Fox doc',
              className: 'Document',
              openedAt: 2,
              emoji: '🦊'
            ),
          ]);
      await tester.pumpWidget(app(ChatScreen(api: api)));
      await tester.pumpAndSettle();
      expect(find.text('🦊 Fox doc'), findsOneWidget);
    });

    test('parsing carries the emoji, empty or absent is none', () {
      final rows = AssistantJson.parseRecentResources(
          '[{"subject":"a","title":"A","class_name":"","opened_at":1,"emoji":"🦊"},'
          '{"subject":"b","title":"B","class_name":"","opened_at":1}]');
      expect(rows.map((r) => r.emoji), ['🦊', null]);
      final hits = AssistantJson.parseHits(
          '[{"subject":"a","title":"A","class_name":"","drive":"","score":1,"emoji":""}]');
      expect(hits.single.emoji, isNull);
      expect(AssistantJson.parseIcons('{"a":"🦊","b":""}'), {'a': '🦊'});
    });
  });

  group('SearchScreen', () {
    testWidgets('searches every keystroke, results in the next frame',
        (tester) async {
      final api = FakeApi(hits: [
        (
          subject: 'did:ad:9',
          title: 'Zebra',
          className: 'Folder',
          drive: '',
          score: 1.5,
          emoji: null
        ),
      ]);
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();

      // No debounce: the keystroke asks at once, and the hits are drawn in
      // the frame after the answer, without any time passing.
      await tester.enterText(find.byType(TextField), 'ze');
      expect(api.asked, ['ze']);
      await tester.pump();
      expect(find.text('Zebra'), findsOneWidget);
      await tester.enterText(find.byType(TextField), 'zebr');
      await tester.pump();
      expect(api.asked, ['ze', 'zebr']);
      expect(find.text('Zebra'), findsOneWidget);
      expect(find.text('Folder'), findsOneWidget);

      await tester.enterText(find.byType(TextField), '');
      await tester.pumpAndSettle();
      expect(find.text('Zebra'), findsNothing);
    });

    testWidgets(
        'one search at a time: typing meanwhile asks for the latest text only, '
        'and the list keeps what it shows until the answer', (tester) async {
      final api = FakeApi(
        recent: [
          (
            subject: 'r1',
            title: 'Opened doc',
            className: 'Document',
            openedAt: 1,
            emoji: null
          ),
        ],
        hits: [
          (
            subject: 'did:ad:9',
            title: 'Zebra',
            className: 'Folder',
            drive: '',
            score: 1.5,
            emoji: null
          ),
        ],
      );
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      final gate = Completer<void>();
      api.searchGate = gate.future;

      await tester.enterText(find.byType(TextField), 'z');
      await tester.pump();
      await tester.enterText(find.byType(TextField), 'ze');
      await tester.pump();
      await tester.enterText(find.byType(TextField), 'zeb');
      await tester.pump();
      expect(api.asked, ['z']);
      // No blank list and no spinner while it runs: the recents stay.
      expect(find.text('Opened doc'), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsNothing);

      api.searchGate = null;
      gate.complete();
      await tester.pump();
      await tester.pump();
      // The answer for "z" is stale; "ze" was never asked.
      expect(api.asked, ['z', 'zeb']);
      expect(find.text('Zebra'), findsOneWidget);
      expect(find.text('Opened doc'), findsNothing);
    });

    testWidgets('sideways with the keyboard up, the field fits',
        (tester) async {
      tester.view.devicePixelRatio = 1;
      // The emulator sideways: 914 x 411, status bar, keyboard.
      tester.view.physicalSize = const Size(914, 411);
      tester.view.padding = const FakeViewPadding(top: 24, left: 42);
      tester.view.viewInsets = const FakeViewPadding(bottom: 265);
      addTearDown(tester.view.reset);
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      expect(find.byType(TextField), findsOneWidget);
    });

    testWidgets('a query without hits says so, not a blank page',
        (tester) async {
      final api = FakeApi(hits: const []);
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.enterText(find.byType(TextField), 'qqzz');
      // Before the answer: nothing claimed yet.
      expect(find.byKey(const Key('search-nothing-found')), findsNothing);
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();
      expect(find.text('Nothing found for “qqzz”'), findsOneWidget);
      expect(find.text('Search all drives'), findsNothing);
    });

    testWidgets('in a drive, the drive is no hit of its own', (tester) async {
      final api = FakeApi(hits: [
        (
          subject: 'did:ad:drive',
          title: 'My drive',
          className: 'Drive',
          drive: 'did:ad:drive',
          score: 2,
          emoji: null
        ),
      ]);
      await tester.pumpWidget(app(SearchScreen(
          drive: 'did:ad:drive', api: api, scopeDrive: 'did:ad:drive')));
      await tester.enterText(find.byType(TextField), 'my');
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();
      expect(find.text('My drive'), findsNothing);
      expect(find.text('Nothing found for “my” in this drive'), findsOneWidget);
      await tester.tap(find.text('Search all drives'));
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();
      expect(find.text('My drive'), findsOneWidget);
    });

    testWidgets('an empty query lists what was opened lately', (tester) async {
      final api = FakeApi(
        recent: [
          (
            subject: 'r1',
            title: 'Opened doc',
            className: 'Document',
            openedAt: 1,
            emoji: null
          ),
        ],
        hits: [
          (
            subject: 'did:ad:9',
            title: 'Zebra',
            className: 'Folder',
            drive: '',
            score: 1.0,
            emoji: null
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
      // Noted once the page is left (no list moves under the finger).
      expect(api.opened, isEmpty);
      await _leave(tester);
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
          score: 1.5,
          emoji: null
        ),
      ]);
      await tester
          .pumpWidget(app(SearchScreen(drive: 'did:ad:drive', api: api)));
      await tester.enterText(find.byType(TextField), 'zebr');
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Zebra'));
      await tester.pump();
      // Noted once the page is left (no list moves under the finger).
      expect(api.opened, isEmpty);
      await _leave(tester);
      expect(api.opened, ['did:ad:9']);
    });
  });

  group('SearchScreen thumb layout', () {
    SearchHit hit(String id, String title, double score) => (
          subject: 'did:ad:$id',
          title: title,
          className: 'Folder',
          drive: '',
          score: score,
          emoji: null
        );

    Future<void> type(WidgetTester tester, String text) async {
      await tester.enterText(find.byType(TextField), text);
      await tester.pump(const Duration(milliseconds: 250));
      await tester.pumpAndSettle();
    }

    testWidgets('field at the bottom, best hit lowest and filled',
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
          tester.widget<Material>(find.byKey(const Key('search-top-hit')));
      expect(box.color, isNotNull);
      expect(box.shape, isNull);
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
      expect(find.byType(ResourceView), findsOneWidget);
      // Noted once the page is left (no list moves under the finger).
      expect(api.opened, isEmpty);
      await _leave(tester);
      expect(api.opened, ['did:ad:1']);
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
        (
          subject: 'r2',
          title: 'Newer',
          className: 'Document',
          openedAt: 2,
          emoji: null
        ),
        (
          subject: 'r1',
          title: 'Older',
          className: 'Document',
          openedAt: 1,
          emoji: null
        ),
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
          (subject: 'did:ad:drive', name: 'Home', emoji: null),
          (subject: 'did:ad:work', name: 'Work', emoji: null),
        ],
        hits: [
          (
            subject: 'did:ad:a',
            title: 'Zebra home',
            className: 'Folder',
            drive: 'did:ad:drive',
            score: 2.0,
            emoji: null
          ),
          (
            subject: 'did:ad:b',
            title: 'Zebra work',
            className: 'Document',
            drive: 'did:ad:work',
            score: 1.0,
            emoji: null
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
      // Noted once the page is left (no list moves under the finger).
      expect(api.opened, isEmpty);
      await _leave(tester);
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

      group('stop and send', () {
        Future<(FakeSpeechInput, FakeApi)> record(WidgetTester tester,
            {String typed = ''}) async {
          final input = FakeSpeechInput();
          final api = FakeApi(ai: ai());
          await tester.pumpWidget(app(ChatScreen(
              api: api, speechInput: input, speechOutput: FakeSpeechOutput())));
          await tester.pumpAndSettle();
          if (typed.isNotEmpty) {
            await tester.enterText(find.byType(TextField), typed);
          }
          await tester.tap(find.byIcon(Icons.mic));
          await tester.pump();
          return (input, api);
        }

        testWidgets('sends the final transcript once and clears the field',
            (tester) async {
          final (input, api) = await record(tester);
          input.onText!('hello the', false);
          await tester.pump();
          input.finalOnStop = 'hello there';
          await tester.tap(find.byTooltip('Stop and send'));
          await tester.pumpAndSettle();
          expect(input.stops, 1);
          expect(api.added.where((m) => m.$2 == 'user').toList(), [
            ('did:ad:new-chat', 'user', 'hello there'),
          ]);
          expect(field(tester), '');
          expect(find.byIcon(Icons.mic), findsOneWidget);
        });

        testWidgets('uses the latest partial when no final arrives',
            (tester) async {
          final (input, api) = await record(tester);
          input.onText!('good morning', false);
          await tester.pump();
          await tester.tap(find.byTooltip('Stop and send'));
          await tester.pump(const Duration(milliseconds: 300));
          expect(api.added, isEmpty);
          // A second tap while finalising does nothing.
          await tester.tap(find.byTooltip('Stop and send'),
              warnIfMissed: false);
          await tester.pump(const Duration(milliseconds: 400));
          await tester.pumpAndSettle();
          expect(input.stops, 1);
          expect(api.added.where((m) => m.$2 == 'user').toList(), [
            ('did:ad:new-chat', 'user', 'good morning'),
          ]);
        });

        testWidgets('an empty transcript sends nothing', (tester) async {
          final (input, api) = await record(tester);
          await tester.tap(find.byTooltip('Stop and send'));
          await tester.pump(const Duration(milliseconds: 700));
          await tester.pumpAndSettle();
          expect(input.stops, 1);
          expect(api.added, isEmpty);
          expect(find.byKey(const Key('voice-hint')), findsOneWidget);
          expect(find.byIcon(Icons.mic), findsOneWidget);
        });

        testWidgets('keeps the typed draft and sends all of it',
            (tester) async {
          final (input, api) = await record(tester, typed: 'Hello');
          input.onText!('world', false);
          await tester.pump();
          await tester.tap(find.byTooltip('Stop and send'));
          await tester.pump(const Duration(milliseconds: 700));
          await tester.pumpAndSettle();
          expect(api.added.where((m) => m.$2 == 'user').toList(), [
            ('did:ad:new-chat', 'user', 'Hello world'),
          ]);
        });

        testWidgets('plain stop leaves the text in the field, unsent',
            (tester) async {
          final (input, api) = await record(tester);
          input.onText!('just this', false);
          await tester.pump();
          await tester.tap(find.byIcon(Icons.stop));
          await tester.pumpAndSettle();
          expect(input.stops, 1);
          expect(field(tester), 'just this');
          expect(api.added, isEmpty);
        });
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
        await tester.tap(find.byTooltip('Stop and send'));
        await tester.pump(const Duration(milliseconds: 700));
        await tester.pumpAndSettle();
        expect(input.stops, 1);
        expect(input.listening, isFalse);
        expect(find.byIcon(Icons.mic), findsOneWidget);
        expect(field(tester), '');
      });

      testWidgets('a text chat has no read-aloud toggle and never speaks',
          (tester) async {
        final output = FakeSpeechOutput();
        await open(tester, FakeSpeechInput(), output);
        expect(find.byIcon(Icons.volume_up), findsNothing);
        expect(find.byIcon(Icons.volume_off), findsNothing);
        await tester.enterText(find.byType(TextField), 'Hi');
        await tester.pump();
        await tester.tap(find.byTooltip('Send'));
        await tester.pumpAndSettle();
        expect(output.spoken, isEmpty);
      });
    });

    group('context picker', () {
      final recent = [
        (
          subject: 'r1',
          title: 'Trip plan',
          className: 'Document',
          openedAt: 5,
          emoji: null
        ),
        (
          subject: 'r2',
          title: 'Budget',
          className: 'Table',
          openedAt: 9,
          emoji: null
        ),
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
              openedAt: i,
              emoji: null
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
      expect(
          find.text('AI chat needs an atomic.place account'), findsOneWidget);
      // No context to pick for a chat that cannot be had.
      expect(find.text('Add context?'), findsNothing);
    });

    testWidgets('a new chat can be started from the home', (tester) async {
      await tester.pumpWidget(
          shellApp(ChatsScreen(drive: 'did:ad:drive', api: FakeApi(ai: ai()))));
      await tester.pumpAndSettle();

      await tapNewChat(tester);
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

    testWidgets('a host registers its own native view, and removes it',
        (tester) async {
      ResourceView.serverFactory = () async => throw 'no server in a test';
      addTearDown(() => registerNativeView('table', null));
      registerNativeView('https://atomicdata.dev/classes/Table',
          (api, drive, subject, title) => Text('table $title'));
      Widget open() => openResourceView(
          api: FakeApi(),
          drive: 'did:ad:drive',
          subject: 'did:ad:x',
          title: 'Sales',
          className: 'Table');

      await tester.pumpWidget(app(open()));
      expect(find.text('table Sales'), findsOneWidget);

      registerNativeView('table', null);
      await tester.pumpWidget(app(open()));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
    });
  });

  group('host pages', () {
    testWidgets(
        'Profile opens the host\'s page; signing out there reaches '
        'the host', (tester) async {
      var signedOut = 0;
      final home = ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(), onSignOut: () => signedOut++);
      await tester.pumpWidget(app(AppShell(
        api: home.api,
        drive: home.drive,
        home: home,
        profile: (context) => Scaffold(
          body: TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Sign out'),
          ),
        ),
      )));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Profile'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Sign out'));
      await tester.pumpAndSettle();
      expect(signedOut, 1);
    });

    testWidgets('without a profile page the Profile button is off',
        (tester) async {
      await tester.pumpWidget(app(const AppShell(
          api: UnimplementedApi(), drive: 'd', home: SizedBox())));
      final button = tester.widget<IconButton>(find.ancestor(
          of: find.byIcon(Icons.person_outline),
          matching: find.byType(IconButton)));
      expect(button.onPressed, isNull);
    });
  });

  group('AppShell', () {
    const doc = (
      subject: 'r1',
      title: 'A doc',
      className: 'Document',
      openedAt: 1,
      emoji: null
    );

    Future<void> pumpHome(WidgetTester tester) async {
      ResourceView.serverFactory = () async => throw 'no server in a test';
      await tester.pumpWidget(shellApp(ChatsScreen(
          drive: 'did:ad:drive', api: FakeApi(favoriteList: [doc]))));
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
        api: UnimplementedApi(),
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
      expect(x(tester, 'Search'), lessThan(x(tester, 'New')));
      expect(x(tester, 'New'), lessThan(x(tester, 'Profile')));
      expect(x(tester, 'Profile'), lessThan(x(tester, 'Settings')));
      final xs = [
        for (final t in ['Search', 'New', 'Profile']) x(tester, t)
      ];

      await tester.tap(find.text('A doc'));
      await tester.pumpAndSettle();
      expect(x(tester, 'Profile'), lessThan(x(tester, 'More')));
      expect([
        for (final t in ['Search', 'New', 'Profile']) x(tester, t)
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
      await tapNewChat(tester);
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
      await tester
          .pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      expect(find.text('Today'), findsNothing);
      await tester.tap(find.byKey(const ValueKey('section-show-all-chats')));
      await tester.pumpAndSettle();
      expect(find.text('Today'), findsOneWidget);
      expect(find.text('Earlier'), findsOneWidget);
      expect(find.byIcon(Icons.chat_bubble_outline), findsNothing);
    });
  });

  group('AssistantJson parsing', () {
    test('keeps the text parts of user and assistant entries only', () {
      final messages = AssistantJson.parseChatMessages(jsonEncode([
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
      final chats = AssistantJson.parseChats(
          '[{"subject":"did:ad:1","name":"A","last_activity":7}]');
      expect(chats.single.lastActivity, 7);
      final hits = AssistantJson.parseHits(
          '[{"subject":"did:ad:1","title":"T","class_name":"C","score":0.5}]');
      expect((hits.single.title, hits.single.className, hits.single.score),
          ('T', 'C', 0.5));
    });

    test('reads recently opened resources', () {
      final recent = AssistantJson.parseRecentResources(
          '[{"subject":"did:ad:1","title":"T","class_name":"C","opened_at":9}]');
      expect((recent.single.title, recent.single.openedAt), ('T', 9));
    });

    test('lists each drive once, only those that are on the device', () {
      final shown = visibleDrives([
        (subject: 'did:ad:AAA', name: 'Private', emoji: null),
        (subject: 'atomic:AAA', name: 'Private', emoji: null),
        (subject: 'did:ad:BBB', name: '', emoji: null),
        (subject: 'did:ad:CCC', name: 'Team', emoji: null),
        (subject: 'did:ad:DDD', name: '', emoji: null),
      ], active: 'atomic:DDD');
      expect(shown.map((d) => d.subject),
          ['did:ad:AAA', 'did:ad:CCC', 'did:ad:DDD']);
    });

    test('reads drives and conversations, and writes a text entry', () {
      final drives = AssistantJson.parseDrives(
          '[{"subject":"did:ad:A","name":"Home","emoji":"🏠"},'
          '{"subject":"atomic:A","name":"Home"},'
          '{"subject":"did:ad:B","name":""}]');
      expect(drives, [(subject: 'did:ad:A', name: 'Home', emoji: '🏠')]);
      final rows = AssistantJson.parseConversations(
          '[{"subject":"did:ad:c","title":"Ann","class_name":"conversation",'
          '"opened_at":3,"last_message":"hi"},{"subject":"did:ad:d"}]');
      expect([for (final r in rows) (r.resource.subject, r.lastMessage)],
          [('did:ad:c', 'hi'), ('did:ad:d', '')]);
      expect(jsonDecode(AssistantJson.textParts('yo')), [
        {'type': 'text', 'text': 'yo'}
      ]);
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
    testWidgets('settles within 220 ms, field at the bottom', (tester) async {
      await tester.pumpWidget(
          shellApp(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Search'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 220));
      final settled = tester.getTopLeft(find.byType(TextField));
      final fade = find
          .ancestor(
              of: find.byType(SearchScreen),
              matching: find.byType(FadeTransition))
          .first;
      expect(tester.widget<FadeTransition>(fade).opacity.value, 1);
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

    testWidgets(
        'a page back on top keeps its layout while the keyboard returns',
        (tester) async {
      final seen = <double>[];
      final key = GlobalKey<NavigatorState>();
      await tester.pumpWidget(MaterialApp(
        navigatorKey: key,
        home: CoveredInsetsFreeze(
          child: Builder(builder: (context) {
            seen.add(MediaQuery.of(context).viewInsets.bottom);
            return const Scaffold(body: Text('results'));
          }),
        ),
      ));
      addTearDown(tester.view.resetViewInsets);
      tester.view.viewInsets = FakeViewPadding(bottom: 500);
      await tester.pump();
      key.currentState!.push(MaterialPageRoute<void>(
          builder: (_) => const Scaffold(body: Text('result'))));
      await tester.pumpAndSettle();
      tester.view.viewInsets = FakeViewPadding.zero;
      await tester.pump();
      key.currentState!.pop();
      await tester.pump();
      seen.clear();
      // The keyboard comes back as the page slides in, over about 500 ms.
      for (var i = 1; i <= 31; i++) {
        tester.view.viewInsets = FakeViewPadding(bottom: 500.0 * i / 31);
        await tester.pump(const Duration(milliseconds: 16));
      }
      await tester.pump(CoveredInsetsFreeze.hold);
      expect(seen.where((b) => b != 500), isEmpty,
          reason: 'no half-way layout: $seen');
    });

    testWidgets('Home goes back to the home screen from any page',
        (tester) async {
      await tester.pumpWidget(
          shellApp(ChatsScreen(drive: 'did:ad:drive', api: FakeApi())));
      await tester.pumpAndSettle();
      await tapNewChat(tester);
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
          openedAt: 1,
          emoji: null
        ),
      ]);
      await tester
          .pumpWidget(shellApp(ChatsScreen(drive: 'did:ad:drive', api: api)));
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

class _SlowNotifications extends FakeApi {
  final Future<List<NotificationItem>> pending;
  _SlowNotifications(this.pending);
  @override
  Future<List<NotificationItem>> notifications() => pending;
}

/// Leaves the page on top: what was opened is noted as visited then.
Future<void> _leave(WidgetTester tester) async {
  await tester.pump(const Duration(milliseconds: 500));
  await tester.binding.handlePopRoute();
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 500));
}

String _name(String title) =>
    HomeSection.values.firstWhere((s) => s.title == title).name;
