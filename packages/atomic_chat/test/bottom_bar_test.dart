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

ShellController _controller(WidgetTester tester) =>
    tester.widget<ShellScope>(find.byType(ShellScope)).controller;

/// Touch and hold the bar button with [tooltip]; the fan is open after.
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

  group('wide screen', () {
    void wide(WidgetTester tester) {
      tester.view.physicalSize = const Size(1800, 2880);
      tester.view.devicePixelRatio = 2;
      addTearDown(tester.view.reset);
    }

    testWidgets('the More menu is asked to open at the More button',
        (tester) async {
      wide(tester);
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      Rect? anchor;
      final route = ModalRoute.of(tester.element(find.byType(ChatsScreen)))!;
      _controller(tester).registerMenu(route, (a) => anchor = a);
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('More'));
      await tester.pump();
      final button = tester.getRect(find.byTooltip('More'));
      expect(anchor, isNotNull);
      expect(anchor!.right, closeTo(button.right, 8));
      // The right end of a 900 wide screen, not its left.
      expect(anchor!.center.dx, greaterThan(700));
    });

    testWidgets('the + and Search fans open over their own buttons',
        (tester) async {
      wide(tester);
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      for (final (tooltip, item) in [
        ('New chat', 'AI chat'),
        ('Search', 'All drives')
      ]) {
        final button = tester.getRect(find
            .byWidgetPredicate((w) => w is HoldFan && w.tooltip == tooltip));
        final gesture = await _hold(tester, tooltip);
        final pill = tester.getRect(find.text(item).last);
        expect((pill.center.dx - button.center.dx).abs(), lessThan(150),
            reason: tooltip);
        await gesture.moveTo(const Offset(1, 1));
        await gesture.up();
        await tester.pumpAndSettle();
      }
    });
  });

  group('New (+)', () {
    testWidgets('a tap still opens a new chat; holding offers the four kinds',
        (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      final gesture = await _hold(tester, 'New chat');
      for (final t in ['AI chat', 'AI voice', 'Document', 'Other']) {
        expect(find.text(t), findsOneWidget);
      }
      await gesture.moveTo(const Offset(1, 1));
      await gesture.up();
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen), findsNothing);

      await tester.tap(find.byTooltip('New chat'));
      await tester.pumpAndSettle();
      final chat = tester.widget<ChatScreen>(find.byType(ChatScreen));
      expect(chat.subject, isNull);
      expect(chat.voiceMode, isFalse);
    });

    testWidgets('AI voice opens a new chat in voice mode', (tester) async {
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New chat'), 'AI voice');
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
      await _pick(tester, await _hold(tester, 'New chat'), 'Document');
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
      await _pick(tester, await _hold(tester, 'New chat'), 'Document');
      await tester.tap(find.text('Create'));
      await tester.pumpAndSettle();
      expect(find.text('Drive is read-only'), findsOneWidget);
      expect(find.text('New document'), findsOneWidget);
      expect(find.byType(ResourceView), findsNothing);
    });

    testWidgets('Other opens the web New page in the last drive',
        (tester) async {
      SharedPreferences.setMockInitialValues(
          {newResourceDriveKey: 'did:ad:work'});
      await tester.pumpWidget(_shell(_BarApi()));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New chat'), 'Other');
      final view = tester.widget<ResourceView>(find.byType(ResourceView));
      expect(Uri.parse(view.path!).path, '/app/new');
      expect(Uri.parse(view.path!).queryParameters['parentSubject'],
          'did:ad:work');
    });
  });

  group('Search hold', () {
    testWidgets('a drive from the fan scopes the search, and x clears it',
        (tester) async {
      final api = _BarApi();
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      final gesture = await _hold(tester, 'Search');
      expect(find.text('All drives'), findsOneWidget);
      expect(find.text('Home'), findsWidgets);
      await _pick(tester, gesture, '💼 Work');

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

    testWidgets('picking a drive in the results filters the search to it',
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
      await tester.tap(find.text('Work drive'));
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
      expect(iconColor('New chat'), isNot(AppColors.light.main));
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

      await tester.tap(find.byTooltip('New chat'));
      await tester.pumpAndSettle();
      expect(_current('New chat'), isTrue);
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
      // Choosing AI chat from the fan while a new chat is on top: the same.
      await tester.tap(find.byTooltip('New chat'));
      await tester.pumpAndSettle();
      await _pick(tester, await _hold(tester, 'New chat'), 'AI chat');
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
      await tester.tap(find.byTooltip('New chat'));
      await tester.pump(const Duration(milliseconds: 50));
      await tester.tap(find.byTooltip('New chat'), warnIfMissed: false);
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen, skipOffstage: false), findsOneWidget);
      // And a quick tap on another button right after a push is ignored too.
      await tester.tap(find.byTooltip('Home'));
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
      await tester.tap(find.byTooltip('New chat'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'Hi');
      await tester.pump();
      await tester.tap(find.byTooltip('Send'));
      await tester.pumpAndSettle();
      expect(_current('New chat'), isFalse);
      await tester.tap(find.byTooltip('New chat'));
      await tester.pumpAndSettle();
      expect(find.byType(ChatScreen, skipOffstage: false), findsNWidgets(2));
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
