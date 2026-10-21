import 'dart:async';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart'
    show FakeApi, FakeSpeechInput, FakeSpeechOutput, app;

/// [FakeApi] with two drives, that records what is created and searched.
class _BarApi extends FakeApi {
  final List<(String, String, String)> made = [];
  final List<(String, String?)> searched = [];
  Object? createError;
  List<SearchHit> searchHits = const [];

  _BarApi({super.ai})
      : super(driveList: const [
          (subject: 'did:ad:home', name: 'Home', emoji: null),
          (subject: 'did:ad:work', name: 'Work', emoji: '💼'),
        ]);

  @override
  Future<String> createResource(
      String drive, String classUrl, String name) async {
    if (createError != null) throw createError!;
    made.add((drive, classUrl, name));
    return 'did:ad:made';
  }

  @override
  Future<List<SearchHit>> search(String query, {String? drive}) async {
    searched.add((query, drive));
    return searchHits;
  }
}

Widget _shell(AssistantApi api, {WidgetBuilder? profile}) => app(AppShell(
      api: api,
      drive: 'did:ad:home',
      profile: profile,
      home: ChatsScreen(drive: 'did:ad:home', api: api),
    ));

/// A host that is slow to create a chat: [gate] lets it go on.
class _SlowChatApi extends _BarApi {
  final gate = Completer<void>();

  _SlowChatApi({super.ai});

  @override
  Future<String> newChat(String name) async {
    await gate.future;
    return super.newChat(name);
  }
}

ShellController _controller(WidgetTester tester) =>
    tester.widget<ShellScope>(find.byType(ShellScope)).controller;

/// Touch and hold the bar button with [tooltip]; the list is open after.
Future<TestGesture> _hold(WidgetTester tester, String tooltip) async {
  final gesture = await tester.startGesture(tester.getCenter(
      find.byWidgetPredicate((w) => w is HoldFan && w.tooltip == tooltip)));
  await tester.pump(const Duration(milliseconds: 400));
  await tester.pump(const Duration(milliseconds: 200));
  return gesture;
}

Future<void> _pick(
    WidgetTester tester, TestGesture gesture, String item) async {
  await gesture.moveTo(tester.getCenter(find.text(item).last));
  await tester.pump();
  await gesture.up();
  await tester.pumpAndSettle();
}

/// Lets the futures and frames run; the mic's ring breathes while listening,
/// so the screen never settles by itself.
Future<void> _settle(WidgetTester tester) async {
  for (var i = 0; i < 10; i++) {
    await tester.pump(const Duration(milliseconds: 100));
  }
}

bool _current(String label) =>
    find.byKey(ValueKey('current:$label')).evaluate().isNotEmpty;

/// A tap on + lists the kinds; AI chat starts a new chat.
Future<void> tapNewChat(WidgetTester tester) async {
  await tester.tap(find.byTooltip('New'));
  await tester.pump();
  await tester.tap(find.text('AI chat'));
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ResourceView.serverFactory = () async => throw 'no server in a test';
  });

  testWidgets('the Home button is a house, filled on the home', (tester) async {
    await tester.pumpWidget(_shell(_BarApi()));
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.home), findsOneWidget);
    expect(find.byIcon(Icons.home_outlined), findsNothing);
    await tester.tap(find.byTooltip('Settings'));
    await tester.pump(const Duration(milliseconds: 600));
    expect(find.byIcon(Icons.home_outlined), findsOneWidget);
  });

  testWidgets('Settings has the top bar with a back arrow that pops it',
      (tester) async {
    await tester.pumpWidget(_shell(_BarApi()));
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Settings'));
    await tester.pump(const Duration(milliseconds: 600));
    expect(
        find.descendant(
            of: find.byType(AppBar), matching: find.text('Settings')),
        findsOneWidget);
    expect(_controller(tester).topKind, ShellPage.settings);
    await tester.pump(const Duration(seconds: 1));
    await tester.tap(find.byType(BackButton).last);
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pump(const Duration(milliseconds: 600));
    expect(_controller(tester).topKind, ShellPage.home);
  });

  group('wide screen', () {
    void wide(WidgetTester tester) {
      tester.view.physicalSize = const Size(1800, 2880);
      tester.view.devicePixelRatio = 2;
      addTearDown(tester.view.reset);
    }

    testWidgets('the bar next to the list has no More button, only six',
        (tester) async {
      wide(tester);
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      // A tablet: the same bar, the width of the list pane. A page's menu
      // is shown by the page itself, never by the bar.
      expect(find.byType(AppBottomBar), findsOneWidget);
      expect(tester.getSize(find.byType(AppBottomBar)).width, 360);
      final route = _controller(tester).top!;
      _controller(tester).registerMenu(route, (_) {});
      await tester.pumpAndSettle();
      expect(
          find.descendant(
              of: find.byType(AppBottomBar), matching: find.byTooltip('More')),
          findsNothing);
      expect(find.byTooltip('Close sidebar'), findsOneWidget);
    });

    testWidgets('the + and Search lists open next to their own buttons',
        (tester) async {
      wide(tester);
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      for (final tooltip in ['New', 'Search']) {
        final button = tester.getRect(find
            .byWidgetPredicate((w) => w is HoldFan && w.tooltip == tooltip));
        final gesture = await _hold(tester, tooltip);
        final pill =
            tester.getRect(find.byKey(const ValueKey('hold-fan-item-0')));
        // Above the bar's button, over it.
        expect(pill.bottom, lessThan(button.top), reason: tooltip);
        expect(pill.left, lessThan(button.right), reason: tooltip);
        expect(pill.right, greaterThan(button.left), reason: tooltip);
        await gesture.moveTo(const Offset(1, 1));
        await gesture.up();
        await tester.pumpAndSettle();
      }
    });
  });

  group('New (+)', () {
    testWidgets('a tap lists the kinds; picking AI chat starts a chat',
        (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('New'));
      await tester.pump();
      // Nothing is made by the tap itself.
      expect(find.byType(ChatScreen), findsNothing);
      final rows = [
        for (final t in [
          'AI chat',
          'AI voice',
          'Document',
          'New chat room',
          'New drive',
          'Other…'
        ])
          tester.getRect(find.text(t)),
      ];
      for (var i = 1; i < rows.length; i++) {
        expect(rows[i].top, greaterThan(rows[i - 1].top), reason: 'order');
      }
      final bar = tester.getRect(find.byTooltip('New'));
      expect(rows.last.bottom, lessThan(bar.top), reason: 'above the +');
      for (final r in rows) {
        expect(r.left, greaterThanOrEqualTo(0));
        expect(r.right, lessThanOrEqualTo(360));
      }
      await tester.tap(find.text('AI chat'));
      await tester.pumpAndSettle();
      final chat = tester.widget<ChatScreen>(find.byType(ChatScreen));
      expect(chat.subject, isNull);
      expect(chat.voiceMode, isFalse);
      expect(find.text('AI chat'), findsNothing);
    });

    testWidgets('a tap outside closes the list and starts nothing',
        (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('New'));
      await tester.pump();
      await tester.tapAt(const Offset(180, 60));
      await tester.pumpAndSettle();
      expect(find.text('AI chat'), findsNothing);
      expect(find.byType(ChatScreen), findsNothing);
    });

    testWidgets('back closes the list and keeps the page', (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Settings'));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('New'));
      await tester.pump();
      expect(find.text('AI chat'), findsOneWidget);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.text('AI chat'), findsNothing);
      expect(_controller(tester).topKind, ShellPage.settings);
    });

    testWidgets(
        'holding lists the kinds and the drag picks the one under '
        'the finger', (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      final gesture = await _hold(tester, 'New');
      for (final t in [
        'AI chat',
        'AI voice',
        'Document',
        'New chat room',
        'New drive',
        'Other…'
      ]) {
        expect(find.text(t), findsOneWidget);
      }
      // Letting go off the list picks nothing.
      await gesture.moveTo(const Offset(1, 1));
      await gesture.up();
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsNothing);
      expect(find.text('AI chat'), findsNothing);

      await _pick(tester, await _hold(tester, 'New'), 'AI chat');
      final chat = tester.widget<ChatScreen>(find.byType(ChatScreen));
      expect(chat.subject, isNull);
      expect(chat.voiceMode, isFalse);
    });

    testWidgets('a swipe opens the list at once; a drag picks', (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      final gesture = await tester.startGesture(tester.getCenter(
          find.byWidgetPredicate((w) => w is HoldFan && w.tooltip == 'New')));
      // No wait for a hold: the frame after the swipe passes the slop.
      await gesture.moveBy(const Offset(0, -12));
      await tester.pump();
      expect(find.text('AI voice'), findsOneWidget);
      await gesture.moveTo(tester.getCenter(find.text('AI voice')));
      await tester.pump();
      await gesture.up();
      await tester.pumpAndSettle();
      expect(
          tester.widget<ChatScreen>(find.byType(ChatScreen)).voiceMode, isTrue);
    });

    testWidgets('AI chat from inside a chat with messages is a fresh chat',
        (tester) async {
      final api = _BarApi(
        ai: HostedAi(
          status: {'enabled': true, 'consent': true, 'model': 'm'},
          stream: (messages, model) => Stream.value('ok'),
          enable: () async => {},
        ),
      );
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'Hi');
      await tester.pump();
      await tester.tap(find.byTooltip('Send'));
      await tester.pumpAndSettle();
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen, skipOffstage: false), findsNWidgets(2));
      final top = tester.widget<ChatScreen>(find.byType(ChatScreen));
      expect(top.subject, isNull);
      // And again on that empty one: no third chat, its field gets the cursor.
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen, skipOffstage: false), findsNWidgets(2));
    });

    testWidgets('AI voice opens a new chat in voice mode', (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New'), 'AI voice');
      final chat = tester.widget<ChatScreen>(find.byType(ChatScreen));
      expect(chat.voiceMode, isTrue);
      expect(chat.subject, isNull);
      expect(find.text('Voice chat'), findsOneWidget);
    });

    testWidgets('Document creates in the chosen drive and opens it',
        (tester) async {
      SharedPreferences.setMockInitialValues(
          {newResourceDriveKey: 'did:ad:work'});
      final api = _BarApi();
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New'), 'Document');
      expect(find.text('New document'), findsOneWidget);
      // The last used drive is preselected.
      expect(
          tester
              .widget<ChoiceChip>(
                  find.byKey(const ValueKey('drive-did:ad:work')))
              .selected,
          isTrue);
      await tester.tap(find.byKey(const ValueKey('drive-did:ad:home')));
      await tester.enterText(
          find.byKey(const Key('new-document-name')), 'Plans');
      await tester.tap(find.text('Create'));
      await tester.pumpAndSettle();

      expect(api.made, [('did:ad:home', documentClass, 'Plans')]);
      expect(find.text('New document'), findsNothing);
      final view = tester.widget<ResourceView>(find.byType(ResourceView));
      expect(view.subject, 'did:ad:made');
      expect(view.drive, 'did:ad:home');
      expect(api.opened, contains('did:ad:made'));
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString(newResourceDriveKey), 'did:ad:home');
    });

    testWidgets('Document shows a failure in the sheet', (tester) async {
      final api = _BarApi()..createError = 'Drive is read-only';
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New'), 'Document');
      await tester.tap(find.text('Create'));
      await tester.pumpAndSettle();
      expect(find.text('Drive is read-only'), findsOneWidget);
      expect(find.text('New document'), findsOneWidget);
      expect(find.byType(ResourceView), findsNothing);
    });

    testWidgets('New chat room and New drive open the web forms',
        (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New'), 'New chat room');
      var view = tester.widget<ResourceView>(find.byType(ResourceView));
      expect(view.title, 'New chat room');
      expect(Uri.parse(view.path!).path, '/app/new');
      expect(
          Uri.parse(view.path!).queryParameters['classSubject'], chatRoomClass);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New'), 'New drive');
      view = tester.widget<ResourceView>(find.byType(ResourceView));
      expect(view.title, 'New drive');
      expect(view.path, '/app/new-drive');
    });

    testWidgets('Other opens the web New page in the last drive',
        (tester) async {
      SharedPreferences.setMockInitialValues(
          {newResourceDriveKey: 'did:ad:work'});
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New'), 'Other…');
      final view = tester.widget<ResourceView>(find.byType(ResourceView));
      expect(Uri.parse(view.path!).path, '/app/new');
      expect(Uri.parse(view.path!).queryParameters['parentSubject'],
          'did:ad:work');
    });
  });

  group('Search hold', () {
    testWidgets('a drive from the list scopes the search, and x clears it',
        (tester) async {
      final api = _BarApi();
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      final gesture = await _hold(tester, 'Search');
      expect(find.text('All drives'), findsOneWidget);
      expect(find.text('Home'), findsWidgets);
      await _pick(tester, gesture, 'Work');

      final screen = tester.widget<SearchScreen>(find.byType(SearchScreen));
      expect(screen.scopeDrive, 'did:ad:work');
      expect(find.text('In: Work'), findsOneWidget);
      await tester.enterText(find.byType(TextField), 'plan');
      await tester.pump(const Duration(milliseconds: 200));
      expect(api.searched.last, ('plan', 'did:ad:work'));

      await tester.tap(find.byTooltip('Search all drives'));
      await tester.pump(const Duration(milliseconds: 200));
      expect(find.text('In: Work'), findsNothing);
      expect(api.searched.last, ('plan', null));
    });

    testWidgets('tapping a drive in the results opens it, no scope',
        (tester) async {
      final api = _BarApi()
        ..searchHits = const [
          (
            subject: 'did:ad:work',
            title: 'Work drive',
            className: 'Drive',
            drive: 'did:ad:home',
            score: 1.0,
            emoji: null
          ),
        ];
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'wor');
      await tester.pump(const Duration(milliseconds: 200));
      final searches = api.searched.length;
      await tester.tap(find.text('Work drive'));
      await tester.pumpAndSettle();
      expect(find.text('In: Work'), findsNothing);
      expect(api.searched.length, searches, reason: 'not searched again');
      expect(find.byKey(const Key('search-scope')), findsNothing);
      expect(find.byType(SearchScreen), findsNothing,
          reason: 'the drive page is on top of the search');
    });

    testWidgets('the search-in icon of a drive result scopes the search',
        (tester) async {
      final api = _BarApi()
        ..searchHits = const [
          (
            subject: 'did:ad:work',
            title: 'Work drive',
            className: 'Drive',
            drive: 'did:ad:home',
            score: 1.0,
            emoji: null
          ),
        ];
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('search-scope')), findsNothing);
      await tester.enterText(find.byType(TextField), 'wor');
      await tester.pump(const Duration(milliseconds: 200));
      await tester.tap(find.byTooltip('Search in Work drive'));
      await tester.pump(const Duration(milliseconds: 200));
      expect(find.byType(SearchScreen), findsOneWidget);
      expect(find.text('In: Work'), findsOneWidget);
      expect(api.searched.last, ('wor', 'did:ad:work'));
    });

    testWidgets('All drives searches everywhere', (tester) async {
      final api = _BarApi();
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'Search'), 'All drives');
      expect(tester.widget<SearchScreen>(find.byType(SearchScreen)).scopeDrive,
          isNull);
      expect(find.byKey(const Key('search-scope')), findsNothing);
    });
  });

  testWidgets('the bar is drawn on the bar surface, not the page colour',
      (tester) async {
    await tester.pumpWidget(_shell(_BarApi()));
    await tester.pumpAndSettle();
    final material = tester.widget<Material>(find
        .ancestor(of: find.byTooltip('Search'), matching: find.byType(Material))
        .last);
    expect(material.color, AppColors.light.barSurface);
    expect(material.color, isNot(AppColors.light.bgBody));
  });

  group('Where you are', () {
    testWidgets('the current button is in the main colour, with no dot',
        (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      Color? iconColor(String tooltip) => tester
          .widget<Icon>(find
              .descendant(
                  of: find.byWidgetPredicate(
                      (w) => w is HoldFan && w.tooltip == tooltip),
                  matching: find.byType(Icon))
              .first)
          .color;
      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(iconColor('Search'), AppColors.light.main);
      expect(iconColor('New'), isNot(AppColors.light.main));
      // No dot widget (a small circle) is drawn under the current button.
      expect(
          find.byWidgetPredicate((w) =>
              w is Container &&
              w.decoration is BoxDecoration &&
              (w.decoration as BoxDecoration).shape == BoxShape.circle &&
              w.constraints?.maxWidth == 4),
          findsNothing);
    });

    testWidgets('the button of the page on top is the current one',
        (tester) async {
      await tester
          .pumpWidget(_shell(_BarApi(), profile: (_) => const Text('Me')));
      await tester.pumpAndSettle();
      expect(_current('Home'), isTrue);

      await tester.tap(find.byTooltip('Search'));
      await tester.pumpAndSettle();
      expect(_current('Search'), isTrue);
      expect(_current('Home'), isFalse);

      await tapNewChat(tester);
      await tester.pumpAndSettle();
      expect(_current('New'), isTrue);
      expect(_current('Search'), isFalse);

      await tester.tap(find.byTooltip('Profile'));
      await tester.pumpAndSettle();
      expect(_current('Profile'), isTrue);
      expect(_controller(tester).topKind, ShellPage.profile);

      await tester.tap(find.byTooltip('Settings'));
      await tester.pumpAndSettle();
      expect(_current('Settings'), isTrue);

      await tester.tap(find.byTooltip('Home'));
      await tester.pumpAndSettle();
      expect(_current('Home'), isTrue);
      expect(find.byType(ResourceView), findsNothing);
    });

    testWidgets('tapping the current button does nothing', (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Settings'));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Settings'));
      await tester.pumpAndSettle();
      expect(find.byType(ResourceView), findsOneWidget);
      // Choosing AI chat from the list while a new chat is on top: the same.
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New'), 'AI chat');
      expect(find.byType(ChatScreen), findsOneWidget);
    });

    testWidgets('a page further down is popped back to, not pushed again',
        (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Settings'));
      await tester.pumpAndSettle();
      final shell = _controller(tester);
      shell.navigatorKey.currentState!.push(MaterialPageRoute<void>(
          builder: (_) => const Scaffold(body: Text('Deeper'))));
      await tester.pumpAndSettle();
      expect(_current('Settings'), isFalse);

      await tester.tap(find.byTooltip('Settings'));
      await tester.pumpAndSettle();
      expect(find.text('Deeper'), findsNothing);
      expect(_current('Settings'), isTrue);
      expect(find.byType(ResourceView, skipOffstage: false), findsOneWidget);
      expect(shell.topKind, ShellPage.settings);
    });

    testWidgets('a double tap pushes once', (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await tapNewChat(tester);
      await tester.pump(const Duration(milliseconds: 50));
      await tester.tap(find.byTooltip('New'), warnIfMissed: false);
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen, skipOffstage: false), findsOneWidget);
      // And a quick tap on another button right after a push is ignored too.
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Settings'));
      await tester.pump(const Duration(milliseconds: 50));
      await tester.tap(find.byTooltip('Search'), warnIfMissed: false);
      await tester.pumpAndSettle();
      expect(find.byType(SearchScreen, skipOffstage: false), findsNothing);
    });

    testWidgets('a new chat that got its first message is no longer "new"',
        (tester) async {
      final api = _BarApi(
        ai: HostedAi(
          status: {'enabled': true, 'consent': true, 'model': 'm'},
          stream: (messages, model) => Stream.value('ok'),
          enable: () async => {},
        ),
      );
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'Hi');
      await tester.pump();
      await tester.tap(find.byTooltip('Send'));
      await tester.pumpAndSettle();
      expect(_current('New'), isFalse);
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen, skipOffstage: false), findsNWidgets(2));
    });
  });

  group('New (+) always makes a new chat', () {
    HostedAi ai() => HostedAi(
          status: {'enabled': true, 'consent': true, 'model': 'm'},
          stream: (messages, model) => Stream.value('ok'),
          enable: () async => {},
        );

    for (final (name, size) in [
      ('phone', null),
      ('tablet', const Size(1280, 800)),
    ]) {
      testWidgets('from inside a chat with messages ($name)', (tester) async {
        if (size != null) {
          tester.view.devicePixelRatio = 2;
          tester.view.physicalSize = size * 2;
          addTearDown(tester.view.reset);
        }
        // The chat is still being created (a slow host): it has a message
        // on screen but no subject yet.
        final api = _SlowChatApi(ai: ai());
        await tester.pumpWidget(_shell(api));
        await tester.pumpAndSettle();
        await tapNewChat(tester);
        await tester.pumpAndSettle();
        await tester.enterText(find.byType(TextField), 'Hi there');
        await tester.pump();
        await tester.tap(find.byTooltip('Send'));
        await tester.pump(const Duration(milliseconds: 300));
        expect(find.text('Hi there'), findsOneWidget);

        await tapNewChat(tester);
        await tester.pumpAndSettle();
        // A new, empty chat is the one shown.
        expect(find.text('New chat'), findsWidgets);
        expect(find.text('Hi there'), findsNothing);
        final shown = tester.widget<ChatScreen>(find.byType(ChatScreen).last);
        expect(shown.subject, isNull);
        expect(_controller(tester).topKind, ShellPage.newChat);
        api.gate.complete();
        await tester.pumpAndSettle();
      });
    }

    testWidgets('on an empty new chat it stays the one (no second)',
        (tester) async {
      await tester.pumpWidget(_shell(_BarApi(ai: ai())));
      await tester.pumpAndSettle();
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      FocusManager.instance.primaryFocus?.unfocus();
      await tester.pump();
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen, skipOffstage: false), findsOneWidget);
      // Its field has the cursor.
      final field = tester.widget<TextField>(find.byType(TextField));
      expect(field.focusNode?.hasFocus, isTrue);
    });

    testWidgets('on a voice chat it opens a typed one', (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New'), 'AI voice');
      expect(_controller(tester).topKind, ShellPage.voiceChat);
      await tapNewChat(tester);
      await tester.pumpAndSettle();
      expect(_controller(tester).topKind, ShellPage.newChat);
      expect(tester.widget<ChatScreen>(find.byType(ChatScreen).last).voiceMode,
          isFalse);
    });
  });

  group('Voice mode', () {
    HostedAi ai() => HostedAi(
          status: {'enabled': true, 'consent': true, 'model': 'm'},
          stream: (messages, model) => Stream.fromIterable(['Ho', 'i!']),
          enable: () async => {},
        );

    testWidgets('listens, sends, speaks the answer and listens again',
        (tester) async {
      final api = FakeApi(ai: ai());
      final input = FakeSpeechInput();
      final output = FakeSpeechOutput();
      await tester.pumpWidget(app(ChatScreen(
          api: api,
          voiceMode: true,
          speechInput: input,
          speechOutput: output)));
      await _settle(tester);
      expect(input.starts, 1);
      expect(find.text('Listening…'), findsOneWidget);

      input.onText!('Hallo', false);
      input.onText!('Hallo daar', true);
      await _settle(tester);
      expect(api.added, [
        ('did:ad:new-chat', 'user', 'Hallo daar'),
        ('did:ad:new-chat', 'assistant', 'Hoi!'),
      ]);
      expect(output.spoken, ['Hoi!']);
      expect(input.starts, 2);
      expect(find.text('Listening…'), findsOneWidget);

      // A second turn.
      input.onText!('Dank je', true);
      await _settle(tester);
      expect(output.spoken, ['Hoi!', 'Hoi!']);
      expect(input.starts, 3);

      await tester.tap(find.byKey(const Key('voice-stop')));
      await _settle(tester);
      expect(input.listening, isFalse);
      expect(find.byKey(const Key('voice-talk')), findsOneWidget);
      // A late result of the stopped listen is not sent.
      input.onText!('Nog iets', true);
      await _settle(tester);
      expect(api.added.length, 4);
      expect(input.starts, 3);
    });

    testWidgets('reads aloud whatever the saved setting', (tester) async {
      SharedPreferences.setMockInitialValues({'chat_read_aloud': false});
      final output = FakeSpeechOutput();
      final input = FakeSpeechInput();
      await tester.pumpWidget(app(ChatScreen(
          api: FakeApi(ai: ai()),
          voiceMode: true,
          speechInput: input,
          speechOutput: output)));
      await _settle(tester);
      input.onText!('Vraag', true);
      await _settle(tester);
      expect(output.spoken, ['Hoi!']);
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getBool('chat_read_aloud'), isFalse);
    });

    testWidgets('an error ends the loop and is shown', (tester) async {
      final input = FakeSpeechInput();
      await tester.pumpWidget(app(ChatScreen(
          api: FakeApi(ai: ai()),
          voiceMode: true,
          speechInput: input,
          speechOutput: FakeSpeechOutput())));
      await _settle(tester);
      input.onError!('error_network');
      await _settle(tester);
      expect(find.text('No internet connection for speech recognition.'),
          findsOneWidget);
      expect(find.byKey(const Key('voice-talk')), findsOneWidget);
      expect(input.starts, 1);

      // Talk starts it again.
      await tester.tap(find.byKey(const Key('voice-talk')));
      await _settle(tester);
      expect(input.starts, 2);
    });

    testWidgets('nothing heard pauses the loop', (tester) async {
      final input = FakeSpeechInput();
      final api = FakeApi(ai: ai());
      await tester.pumpWidget(app(ChatScreen(
          api: api,
          voiceMode: true,
          speechInput: input,
          speechOutput: FakeSpeechOutput())));
      await _settle(tester);
      input.onText!('', true);
      await _settle(tester);
      expect(api.added, isEmpty);
      expect(input.starts, 1);
      expect(find.text('Voice paused'), findsOneWidget);
    });

    testWidgets('leaving the app ends the loop', (tester) async {
      final input = FakeSpeechInput();
      final output = FakeSpeechOutput();
      await tester.pumpWidget(app(ChatScreen(
          api: FakeApi(ai: ai()),
          voiceMode: true,
          speechInput: input,
          speechOutput: output)));
      await _settle(tester);
      for (final state in [
        AppLifecycleState.inactive,
        AppLifecycleState.hidden,
        AppLifecycleState.paused,
        AppLifecycleState.hidden,
        AppLifecycleState.inactive,
        AppLifecycleState.resumed,
      ]) {
        tester.binding.handleAppLifecycleStateChanged(state);
        await tester.pump();
      }
      await _settle(tester);
      expect(input.listening, isFalse);
      expect(find.byKey(const Key('voice-talk')), findsOneWidget);
      input.onText!('late', true);
      await _settle(tester);
      expect(input.starts, 1);
    });
  });
}
