import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// The shell at phone, tablet (portrait, landscape) and phone-sideways
/// sizes, and resizing between them.

const _phone = Size(393, 851);
const _portrait = Size(800, 1280);
const _landscape = Size(1280, 800);
const _phoneSideways = Size(851, 393);

void _size(WidgetTester tester, Size size) {
  tester.view.devicePixelRatio = 2;
  tester.view.physicalSize = size * 2;
  addTearDown(tester.view.reset);
}

RecentResource _r(String subject, String title) => (
      subject: subject,
      title: title,
      className: 'document-v2',
      openedAt: 1,
      emoji: null,
    );

FakeApi _api() => FakeApi(recent: [
      _r('did:ad:plans', 'Plans'),
      _r('did:ad:notes', 'Notes'),
    ]);

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      home: ChatsScreen(drive: 'did:ad:drive', api: api),
    ));

ShellController _controller(WidgetTester tester) =>
    tester.widget<ShellScope>(find.byType(ShellScope)).controller;

/// A page that has something typed in it, to see it survive a resize.
class _TypingPage implements EmbedPage {
  final controller = TextEditingController();

  @override
  Future<void> runJavaScript(String script) async {}
  @override
  Future<Object> runJavaScriptReturningResult(String script) async => false;
  @override
  Widget build() => Align(
        alignment: Alignment.topLeft,
        child: SizedBox(
            width: 200,
            child: TextField(
                key: const Key('page-field'), controller: controller)),
      );
}

final _pages = <_TypingPage>[];

Future<void> _settle(WidgetTester tester) async {
  await tester.pumpAndSettle();
  await tester.pump(const Duration(milliseconds: 50));
}

Future<void> _done(WidgetTester tester) async {
  // Close everything, so no timer outlives the test.
  await tester.pumpWidget(const SizedBox());
  await tester.pump(const Duration(seconds: 1));
}

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
    _pages.clear();
    ResourceView.pageFactory = (send) {
      final page = _TypingPage();
      _pages.add(page);
      return page;
    };
    ResourceView.flushTimeout = const Duration(milliseconds: 1);
    ResourceView.releaseDelay = const Duration(milliseconds: 1);
  });
  tearDown(() {
    ResourceView.pageFactory = null;
    ResourceView.flushTimeout = const Duration(seconds: 2);
    ResourceView.releaseDelay = const Duration(seconds: 3);
  });

  testWidgets('a phone keeps the bottom bar and full-screen pages',
      (tester) async {
    _size(tester, _phone);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    expect(find.byType(AppBottomBar), findsOneWidget);
    expect(find.byType(AppNavRail), findsNothing);
    expect(find.byKey(const Key('nothing-open')), findsNothing);
    expect(_controller(tester).layout, ShellLayout.bar);

    await tester.tap(find.text('Plans'));
    await _settle(tester);
    // Over the home, which is no longer on screen.
    expect(find.byType(ResourceView), findsOneWidget);
    expect(find.text('Notes'), findsNothing);
    expect(tester.getSize(find.byType(ResourceView)).width, _phone.width);
    // The bar's last button is the resource's menu.
    expect(
        find.descendant(
            of: find.byType(AppBottomBar), matching: find.byTooltip('More')),
        findsOneWidget);
    expect(find.byKey(const Key('detail-more')), findsNothing);
    await _done(tester);
  });

  for (final (name, size) in [
    ('portrait', _portrait),
    ('landscape', _landscape),
    ('a phone sideways', _phoneSideways),
  ]) {
    testWidgets('a tablet ($name): rail, list pane and detail pane',
        (tester) async {
      _size(tester, size);
      final api = _api();
      await tester.pumpWidget(_shell(api));
      await _settle(tester);
      expect(find.byType(AppBottomBar), findsNothing);
      expect(find.byType(AppNavRail), findsOneWidget);
      expect(_controller(tester).layout, ShellLayout.split);
      // Nothing opened yet.
      expect(find.byKey(const Key('nothing-open')), findsOneWidget);
      final list = tester.getRect(find.byType(ChatsScreen));
      expect(list.left, AppNavRail.width);
      expect(list.width, inInclusiveRange(280, 380));

      // A row opens in the detail pane, next to the list, and is marked.
      await tester.tap(find.text('Plans'));
      await _settle(tester);
      final detail = tester.getRect(find.byType(ResourceView));
      expect(detail.left, greaterThan(list.right));
      expect(detail.right, size.width);
      expect(find.text('Notes'), findsOneWidget);
      ListTile tile(String title) => tester.widget<ListTile>(
          find.ancestor(of: find.text(title), matching: find.byType(ListTile)));
      expect(tile('Plans').selected, isTrue);
      expect(tile('Notes').selected, isFalse);

      // Another row takes its place; nothing piles up.
      await tester.tap(find.text('Notes'));
      await _settle(tester);
      expect(find.byType(ResourceView), findsOneWidget);
      expect(tile('Plans').selected, isFalse);
      expect(tile('Notes').selected, isTrue);
      expect(_controller(tester).pages, hasLength(1));
      expect(api.opened, ['did:ad:plans', 'did:ad:notes']);

      // A page of the rail in its place: no row is marked.
      await tester.tap(find.byTooltip('Settings'));
      await _settle(tester);
      expect(tile('Notes').selected, isFalse);
      await tester.tap(find.text('Notes'));
      await _settle(tester);
      expect(tile('Notes').selected, isTrue);

      // Back goes back inside the pane: to nothing opened.
      await tester.binding.handlePopRoute();
      await _settle(tester);
      expect(find.byType(ResourceView), findsNothing);
      expect(find.byKey(const Key('nothing-open')), findsOneWidget);
      expect(tile('Notes').selected, isFalse);
      await _done(tester);
    });
  }

  testWidgets('the resource menu is at the detail pane\'s top right',
      (tester) async {
    _size(tester, _landscape);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    await tester.tap(find.text('Plans'));
    await _settle(tester);
    // The page's menu: registered by the view once the page is up.
    expect(find.byKey(const Key('detail-more')), findsOneWidget);
    final more = tester.getRect(find.byKey(const Key('detail-more')));
    expect(more.right, _landscape.width);
    expect(more.top, 0);
    expect(more.height, greaterThanOrEqualTo(36));
    // No second one in the rail.
    expect(
        find.descendant(
            of: find.byType(AppNavRail), matching: find.byTooltip('More')),
        findsNothing);
    await _done(tester);
  });

  testWidgets('the rail opens Settings, Profile and a new chat in the detail',
      (tester) async {
    _size(tester, _portrait);
    await tester.pumpWidget(app(AppShell(
      api: _api(),
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      profile: (_) => const Scaffold(body: Text('the profile')),
      home: ChatsScreen(drive: 'did:ad:drive', api: _api()),
    )));
    await _settle(tester);
    await tester.tap(find.byTooltip('Settings'));
    await _settle(tester);
    expect(_controller(tester).topKind, ShellPage.settings);
    expect(find.byType(ChatsScreen), findsOneWidget);
    await tester.tap(find.byTooltip('Profile'));
    await _settle(tester);
    expect(find.text('the profile'), findsOneWidget);
    // In place of Settings, not over it.
    expect(_controller(tester).pages, hasLength(1));
    await tapNewChat(tester);
    await _settle(tester);
    expect(find.byType(ChatScreen), findsOneWidget);
    expect(_controller(tester).pages, hasLength(1));
    expect(find.byKey(const ValueKey('current:New')), findsOneWidget);
    // Home on the home closes what is open.
    await tester.tap(find.byTooltip('Home'));
    await _settle(tester);
    expect(find.byKey(const Key('nothing-open')), findsOneWidget);
    await _done(tester);
  });

  testWidgets('search is the list pane; back returns to the home',
      (tester) async {
    _size(tester, _landscape);
    final api = FakeApi(recent: [
      _r('did:ad:plans', 'Plans')
    ], hits: const [
      (
        subject: 'did:ad:found',
        title: 'Found it',
        className: 'document-v2',
        drive: 'did:ad:drive',
        score: 1.0,
        emoji: null
      ),
    ]);
    await tester.pumpWidget(_shell(api));
    await _settle(tester);
    await tester.tap(find.byTooltip('Search'));
    await _settle(tester);
    expect(find.byType(SearchScreen), findsOneWidget);
    expect(find.byKey(const ValueKey('current:Search')), findsOneWidget);
    final pane = tester.getRect(find.byType(SearchScreen));
    expect(pane.left, AppNavRail.width);
    await tester.enterText(find.byType(TextField), 'fou');
    await tester.pump(const Duration(milliseconds: 200));
    await _settle(tester);
    await tester.tap(find.text('Found it'));
    await _settle(tester);
    // The hit opens next to the search, which stays.
    expect(find.byType(ResourceView), findsOneWidget);
    expect(find.byType(SearchScreen), findsOneWidget);
    expect(find.text('Found it'), findsOneWidget);
    ListTile tile(String title) => tester.widget<ListTile>(
        find.ancestor(of: find.text(title), matching: find.byType(ListTile)));
    expect(tile('Found it').selected, isTrue);
    // Settings in its place: the hit is no longer marked; opened again it is.
    await tester.tap(find.byTooltip('Settings'));
    await _settle(tester);
    expect(tile('Found it').selected, isFalse);
    await tester.tap(find.text('Found it'));
    await _settle(tester);
    expect(tile('Found it').selected, isTrue);

    // Back: the page first, then the search goes back to the home.
    await tester.binding.handlePopRoute();
    await _settle(tester);
    expect(find.byType(ResourceView), findsNothing);
    expect(find.byType(SearchScreen), findsOneWidget);
    await tester.binding.handlePopRoute();
    await _settle(tester);
    expect(find.byType(SearchScreen), findsNothing);
    expect(find.text('Plans'), findsOneWidget);
    await _done(tester);
  });

  testWidgets('a rotation keeps the open resource and what was typed in it',
      (tester) async {
    _size(tester, _landscape);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    final home = tester.state(find.byType(ChatsScreen));
    await tester.tap(find.text('Plans'));
    await _settle(tester);
    await tester.enterText(find.byKey(const Key('page-field')), 'draft');
    final view = tester.state(find.byType(ResourceView));
    final field = tester.state(find.byKey(const Key('page-field')));

    for (final size in [_portrait, _phone, _landscape, _phone]) {
      tester.view.physicalSize = size * 2;
      await _settle(tester);
      expect(tester.state(find.byType(ResourceView)), same(view),
          reason: '$size');
      expect(tester.state(find.byKey(const Key('page-field'))), same(field));
      expect(find.text('draft'), findsOneWidget);
      expect(_pages, hasLength(1), reason: 'one page, never made again');
    }
    // On the phone the resource is the whole screen, over the home.
    expect(find.byType(AppBottomBar), findsOneWidget);
    expect(tester.getSize(find.byType(ResourceView)).width, _phone.width);
    // Back to the home, the same one.
    await tester.binding.handlePopRoute();
    await _settle(tester);
    expect(find.text('Plans'), findsOneWidget);
    expect(tester.state(find.byType(ChatsScreen)), same(home));

    tester.view.physicalSize = _landscape * 2;
    await _settle(tester);
    expect(tester.state(find.byType(ChatsScreen)), same(home));
    expect(find.byKey(const Key('nothing-open')), findsOneWidget);
    await _done(tester);
  });

  testWidgets('a search moves between the list pane and a page on a resize',
      (tester) async {
    _size(tester, _landscape);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    await tester.tap(find.byTooltip('Search'));
    await _settle(tester);
    await tester.enterText(find.byType(TextField), 'pla');
    await _settle(tester);

    tester.view.physicalSize = _phone * 2;
    await _settle(tester);
    // A page of its own on the phone, with the text.
    expect(find.byType(SearchScreen), findsOneWidget);
    expect(ShellPage.isSearch(_controller(tester).topKind), isTrue);
    expect(find.widgetWithText(TextField, 'pla'), findsOneWidget);
    await tester.enterText(find.byType(TextField), 'plan');
    await _settle(tester);

    tester.view.physicalSize = _portrait * 2;
    await _settle(tester);
    expect(find.byType(SearchScreen), findsOneWidget);
    expect(_controller(tester).pages, isEmpty);
    expect(find.widgetWithText(TextField, 'plan'), findsOneWidget);
    expect(tester.getRect(find.byType(SearchScreen)).left, AppNavRail.width);
    await _done(tester);
  });

  testWidgets('between phone and tablet (rail without list pane)',
      (tester) async {
    _size(tester, const Size(640, 900));
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    expect(find.byType(AppNavRail), findsOneWidget);
    expect(_controller(tester).layout, ShellLayout.rail);
    expect(find.byKey(const Key('nothing-open')), findsNothing);
    await tester.tap(find.text('Plans'));
    await _settle(tester);
    // Over the home, beside the rail.
    expect(find.text('Notes'), findsNothing);
    expect(tester.getRect(find.byType(ResourceView)).left, AppNavRail.width);
    await _done(tester);
  });

  testWidgets('the rail fits a phone sideways at a large font', (tester) async {
    _size(tester, _phoneSideways);
    tester.platformDispatcher.textScaleFactorTestValue = 1.3;
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    expect(tester.takeException(), isNull);
    for (final label in ['Home', 'Search', 'New', 'Profile', 'Settings']) {
      expect(
          find.descendant(
              of: find.byType(AppNavRail), matching: find.text(label)),
          findsOneWidget);
    }
    // Every button is a full 48 dp target.
    for (final tip in ['Home', 'Profile', 'Settings']) {
      final button = find.ancestor(
          of: find.byTooltip(tip), matching: find.byType(IconButton));
      expect(tester.getSize(button).height, greaterThanOrEqualTo(48),
          reason: tip);
    }
    for (final tip in ['Search', 'New']) {
      final fan =
          find.byWidgetPredicate((w) => w is HoldFan && w.tooltip == tip);
      expect(tester.getSize(fan).height, greaterThanOrEqualTo(48), reason: tip);
    }
    await _done(tester);
  });

  testWidgets('a text-heavy page is at most 720 wide, centred', (tester) async {
    _size(tester, const Size(2000, 1200));
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    await tapNewChat(tester);
    await _settle(tester);
    final composer = tester.getRect(find
        .descendant(
            of: find.byType(ListAndField), matching: find.byType(Column))
        .first);
    expect(composer.width, ReadableWidth.maxWidth);
    await _done(tester);
  });
}
