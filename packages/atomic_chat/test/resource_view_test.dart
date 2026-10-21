import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'unimplemented_api.dart';

/// The page in a web view, without the web view: records what it is asked to
/// run, and answers a flush only when the test says so.
/// Opens whatever the page asks for, and has no chat to show.
class _OpeningApi extends UnimplementedApi {
  const _OpeningApi();
  @override
  void noteOpened(String drive, String subject) {}
  @override
  Future<List<ChatRoomMessage>> chatRoomMessages(String subject) async =>
      const [];
}

class FakePage implements EmbedPage {
  final void Function(String message) send;
  final scripts = <String>[];
  FakePage(this.send);

  /// Flushes asked for and not answered yet.
  final waiting = <int>[];

  @override
  Future<void> runJavaScript(String script) async {
    scripts.add(script);
    final flush = RegExp(r'flush:(\d+)').firstMatch(script);
    if (script.contains('atomicEmbed.flush(') && flush != null) {
      waiting.add(int.parse(flush.group(1)!));
    }
  }

  @override
  Future<Object> runJavaScriptReturningResult(String script) async => false;

  @override
  Widget build() => const Center(child: Text('the page'));

  /// What the page posts once its flush resolved.
  void answerFlushes() {
    for (final id in waiting) {
      send(jsonEncode({'method': 'flushed', 'flush': id}));
    }
    waiting.clear();
  }

  bool get askedToFlush => scripts.any((s) => s.contains('atomicEmbed.flush('));
}

void main() {
  late FakePage page;

  setUp(() {
    ResourceView.pageFactory = (send) => page = FakePage(send);
    ResourceView.flushTimeout = const Duration(seconds: 2);
  });
  tearDown(() => ResourceView.pageFactory = null);

  Future<NavigatorState> open(WidgetTester tester,
      {bool slideBack = false}) async {
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: const Scaffold(body: Text('home')),
    ));
    final navigator = tester.state<NavigatorState>(find.byType(Navigator));
    Widget page(BuildContext _) =>
        const ResourceView(api: _OpeningApi(), drive: 'd', subject: 's');
    navigator.push(slideBack
        ? SlideBackRoute<void>(builder: page)
        : MaterialPageRoute<void>(builder: page));
    await tester.pumpAndSettle();
    expect(find.text('the page'), findsOneWidget);
    return navigator;
  }

  testWidgets('openNative opens the native view and answers the page',
      (tester) async {
    await open(tester);
    page.scripts.clear();

    page.send(jsonEncode({
      'id': 7,
      'method': 'openNative',
      'args': ['chatroom', 'did:ad:room', 'Standup'],
    }));
    await tester.pumpAndSettle();

    // The room is on top, and the page was told it was taken.
    expect(find.byType(ChatRoomScreen), findsOneWidget);
    expect(page.scripts, contains('window.__atomicReply(7,true,"true")'));
    // Back on the page, it reads the room again (it may have been renamed).
    tester.state<NavigatorState>(find.byType(Navigator).first).pop();
    await tester.pumpAndSettle();
    expect(
        page.scripts, contains('window.atomicEmbed?.changed(["did:ad:room"])'));
    // Closed without an answer to its flush: wait the timers out.
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 6));
  });

  testWidgets('a theme chosen on the page becomes the app\'s', (tester) async {
    SharedPreferences.setMockInitialValues({});
    addTearDown(() => AppThemeMode.mode.value = ThemeMode.system);
    await open(tester);
    page.scripts.clear();

    page.send(jsonEncode({
      'id': 9,
      'method': 'theme',
      'args': ['light'],
    }));
    await tester.pumpAndSettle();
    expect(AppThemeMode.mode.value, ThemeMode.light);
    expect(page.scripts, contains('window.__atomicReply(9,true,"true")'));
    final saved = await SharedPreferences.getInstance();
    expect(saved.getString(AppThemeMode.key), 'light');

    page.send(jsonEncode({
      'id': 10,
      'method': 'theme',
      'args': ['auto'],
    }));
    await tester.pumpAndSettle();
    expect(AppThemeMode.mode.value, ThemeMode.system);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 6));
  });

  testWidgets(
      '"Show icons in the sidebar" switched on the page becomes the app\'s',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    addTearDown(() => AppSidebarIcons.show.value = true);
    await open(tester);
    expect(AppSidebarIcons.show.value, isTrue);
    page.scripts.clear();

    page.send(jsonEncode({
      'id': 11,
      'method': 'sidebarIcons',
      'args': [false],
    }));
    await tester.pumpAndSettle();
    expect(AppSidebarIcons.show.value, isFalse);
    expect(page.scripts, contains('window.__atomicReply(11,true,"true")'));
    final saved = await SharedPreferences.getInstance();
    expect(saved.getBool(AppSidebarIcons.key), isFalse);
    // The page that said it is not told back what it said.
    expect(page.scripts.where((s) => s.contains('setSidebarIcons')), isEmpty);

    // A change from elsewhere (the app) is passed on to the page.
    AppSidebarIcons.show.value = true;
    await tester.pumpAndSettle();
    expect(
        page.scripts, contains('window.atomicEmbed?.setSidebarIcons?.(true)'));
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 6));
  });

  test('the choice is saved and loaded, on by default', () async {
    SharedPreferences.setMockInitialValues({});
    addTearDown(() => AppSidebarIcons.show.value = true);
    await AppSidebarIcons.load();
    expect(AppSidebarIcons.show.value, isTrue);
    await AppSidebarIcons.choose(false);
    AppSidebarIcons.show.value = true;
    await AppSidebarIcons.load();
    expect(AppSidebarIcons.show.value, isFalse);
    expect(AppSidebarIcons.parse(['x']), isNull);
    expect(AppSidebarIcons.parse([true]), isTrue);
  });

  testWidgets('openNative for a kind the app has no view for says false',
      (tester) async {
    await open(tester);
    page.scripts.clear();

    page.send(jsonEncode({
      'id': 8,
      'method': 'openNative',
      'args': ['hologram', 'did:ad:x', ''],
    }));
    await tester.pumpAndSettle();

    expect(find.byType(ChatRoomScreen), findsNothing);
    expect(find.text('the page'), findsOneWidget);
    expect(page.scripts.last, 'window.__atomicReply(8,true,"false")');
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 6));
  });

  testWidgets('a resource the page settles on goes to the store with the drive',
      (tester) async {
    final calls = <(String, String)>[];
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: ResourceView(
        api: const _OpeningApi(),
        drive: 'did:ad:drive',
        subject: 'did:ad:folder',
        call: (method, args) async {
          calls.add((method, args));
          return 'true';
        },
      ),
    ));
    await tester.pumpAndSettle();

    page.send(jsonEncode({
      'id': 3,
      'method': 'opened',
      'args': ['did:ad:child'],
    }));
    await tester.pumpAndSettle();

    expect(calls, [('opened', '["did:ad:child","did:ad:drive"]')]);
    expect(page.scripts, contains('window.__atomicReply(3,true,"true")'));
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 6));
  });

  testWidgets('back waits until the page has handed over its edits',
      (tester) async {
    final navigator = await open(tester);

    await navigator.maybePop();
    await tester.pump(const Duration(milliseconds: 500));

    // Asked, with the page told it is leaving, and still open.
    expect(page.askedToFlush, isTrue);
    expect(page.scripts.last, contains('atomicEmbed.flush(true)'));
    expect(find.text('the page'), findsOneWidget);

    page.answerFlushes();
    await tester.pumpAndSettle();
    expect(find.text('the page'), findsNothing);
    expect(find.text('home'), findsOneWidget);
  });

  testWidgets('back still leaves when the page never answers', (tester) async {
    final navigator = await open(tester);

    await navigator.maybePop();
    await tester.pump(const Duration(milliseconds: 1900));
    expect(find.text('the page'), findsOneWidget);

    await tester.pump(const Duration(milliseconds: 200));
    await tester.pumpAndSettle();
    expect(find.text('the page'), findsNothing);
  });

  testWidgets('a second back while waiting does not pop twice', (tester) async {
    final navigator = await open(tester);

    await navigator.maybePop();
    await navigator.maybePop();
    await tester.pump();
    page.answerFlushes();
    await tester.pumpAndSettle();
    expect(find.text('home'), findsOneWidget);
    expect(navigator.canPop(), isFalse);
  });

  testWidgets('swipe back slides out, then waits for the page', (tester) async {
    await open(tester, slideBack: true);

    await tester.drag(find.text('the page'), const Offset(700, 0));
    await tester.pump(const Duration(milliseconds: 600));
    expect(page.askedToFlush, isTrue);
    // Out of sight, but still there: its last commit may be on its way.
    expect(find.text('the page', skipOffstage: false), findsOneWidget);

    page.answerFlushes();
    await tester.pumpAndSettle();
    expect(find.text('the page', skipOffstage: false), findsNothing);
    expect(find.text('home'), findsOneWidget);
  });

  testWidgets('a page opened over it, or the app going away, flushes',
      (tester) async {
    final navigator = await open(tester);

    navigator.push(MaterialPageRoute<void>(
        builder: (_) => const Scaffold(body: Text('search'))));
    await tester.pumpAndSettle();
    expect(page.askedToFlush, isTrue);
    expect(page.scripts.last, contains('atomicEmbed.flush(false)'));

    page.scripts.clear();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump();
    expect(page.askedToFlush, isTrue);
    page.answerFlushes();
    await tester.pumpAndSettle();

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    navigator.pop();
    await tester.pumpAndSettle();
    await navigator.maybePop();
    await tester.pump();
    page.answerFlushes();
    await tester.pumpAndSettle();
    expect(find.text('home'), findsOneWidget);
  });
}
