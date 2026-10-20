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
    expect(find.byKey(const Key('list-toggle')), findsNothing);
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
    await _done(tester);
  });

  for (final (name, size) in [
    ('portrait', _portrait),
    ('landscape', _landscape),
    ('a phone sideways', _phoneSideways),
  ]) {
    testWidgets('a tablet ($name): the bar under a list and a detail pane',
        (tester) async {
      _size(tester, size);
      final api = _api();
      await tester.pumpWidget(_shell(api));
      await _settle(tester);
      // The bar is under the list pane only, as wide as it.
      final bar = tester.getRect(find.byType(AppBottomBar));
      expect(bar.left, 0);
      expect(bar.bottom, size.height);
      expect(_controller(tester).layout, ShellLayout.split);
      // Nothing opened yet.
      expect(find.byKey(const Key('nothing-open')), findsOneWidget);
      final list = tester.getRect(find.byType(ChatsScreen));
      expect(list.left, 0);
      expect(list.width, inInclusiveRange(320, 400));
      expect(list.bottom, bar.top);
      expect(bar.width, list.width);

      // A row opens in the detail pane, next to the list, and is marked.
      await tester.tap(find.text('Plans'));
      await _settle(tester);
      final detail = tester.getRect(find.byType(ResourceView));
      expect(detail.left, greaterThan(list.right));
      expect(detail.right, size.width);
      // The pages run to the bottom of the window.
      expect(detail.bottom, size.height);
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

      // A page of the bar in its place: no row is marked.
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

  testWidgets('the resource menu is in the bar, after Settings',
      (tester) async {
    _size(tester, _landscape);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    expect(find.byTooltip('More'), findsNothing);
    await tester.tap(find.text('Plans'));
    await _settle(tester);
    // The page's menu: registered by the view once the page is up.
    final bar = find.byType(AppBottomBar);
    final more = find.descendant(of: bar, matching: find.byTooltip('More'));
    expect(more, findsOneWidget);
    final settings =
        find.descendant(of: bar, matching: find.byTooltip('Settings'));
    expect(settings, findsOneWidget);
    expect(tester.getRect(more).left,
        greaterThanOrEqualTo(tester.getRect(settings).right - 1));
    await _done(tester);
  });

  testWidgets('a tap on the bar\'s New lists the kinds above it, on screen',
      (tester) async {
    _size(tester, _landscape);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    final button = tester.getRect(find.descendant(
        of: find.byType(AppBottomBar), matching: find.byTooltip('New')));
    await tester.tap(find.byTooltip('New'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 120));
    var lastTop = -1.0;
    for (final t in ['AI chat', 'AI voice', 'Document', 'Other…']) {
      final r = tester.getRect(find.text(t));
      expect(r.bottom, lessThan(button.top), reason: t);
      expect(r.right, lessThanOrEqualTo(_landscape.width), reason: t);
      expect(r.top, greaterThan(lastTop), reason: t);
      lastTop = r.top;
    }
    // A fresh chat from the list opens in the detail pane.
    await tester.tap(find.text('AI chat'));
    await _settle(tester);
    expect(find.byType(ChatScreen), findsOneWidget);
    expect(tester.getRect(find.byType(ChatScreen)).left,
        greaterThan(tester.getRect(find.byType(ChatsScreen)).right));
    expect(find.text('AI voice'), findsNothing);
    await _done(tester);
  });

  testWidgets('the bar opens Settings, Profile and a new chat in the detail',
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
    expect(pane.left, 0);
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
    // The phone's bar: the menu in Settings' place, not next to it.
    expect(find.byTooltip('More'), findsOneWidget);
    expect(find.byTooltip('Settings'), findsNothing);
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
    expect(tester.getRect(find.byType(SearchScreen)).left, 0);
    await _done(tester);
  });

  testWidgets('from 600 wide the list and detail panes, at 599 the phone',
      (tester) async {
    _size(tester, const Size(640, 900));
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    expect(_controller(tester).layout, ShellLayout.split);
    expect(tester.getSize(find.byType(ChatsScreen)).width, 320);
    await tester.tap(find.text('Plans'));
    await _settle(tester);
    // Next to the list.
    expect(find.text('Notes'), findsOneWidget);
    expect(tester.getRect(find.byType(ResourceView)).left, greaterThan(320));
    tester.view.physicalSize = const Size(599, 900) * 2;
    await _settle(tester);
    expect(_controller(tester).layout, ShellLayout.bar);
    expect(find.text('Notes'), findsNothing);
    await _done(tester);
  });

  testWidgets('the bar fits a phone sideways at a large font', (tester) async {
    _size(tester, _phoneSideways);
    tester.platformDispatcher.textScaleFactorTestValue = 1.3;
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    expect(tester.takeException(), isNull);
    // Every button is a full 48 dp target.
    for (final tip in ['Home', 'Profile', 'Settings']) {
      final button = find.ancestor(
          of: find.byTooltip(tip), matching: find.byType(IconButton));
      expect(tester.getSize(button.first).height, greaterThanOrEqualTo(48),
          reason: tip);
    }
    for (final tip in ['Search', 'New']) {
      final button = find.descendant(
          of: find.byType(AppBottomBar),
          matching:
              find.byWidgetPredicate((w) => w is HoldFan && w.tooltip == tip));
      expect(tester.getSize(button).height, greaterThanOrEqualTo(48),
          reason: tip);
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

  group('the bar is under the list pane only', () {
    for (final (name, size) in [
      ('portrait', _portrait),
      ('landscape', _landscape),
    ]) {
      testWidgets('$name: the bar is as wide as the list, the pages are full',
          (tester) async {
        _size(tester, size);
        await tester.pumpWidget(_shell(_api()));
        await _settle(tester);
        await tester.tap(find.text('Plans'));
        await _settle(tester);
        final bar = tester.getRect(find.byType(AppBottomBar));
        final list = tester.getRect(find.byType(ChatsScreen));
        expect(bar.left, 0);
        expect(bar.width, list.width);
        expect(bar.bottom, size.height);
        final detail = tester.getRect(find.byType(ResourceView));
        expect(detail.bottom, size.height);
        expect(detail.right, size.width);
        // Folded: a compact bar floats at the bottom of the pages; they end
        // above it.
        await tester.tap(find.byKey(const Key('list-toggle')));
        await _settle(tester);
        final compact = tester.getRect(find.byType(AppBottomBar));
        expect(compact.width, lessThanOrEqualTo(420));
        expect(compact.bottom, size.height);
        expect(compact.center.dx, closeTo(size.width / 2, 1));
        expect(tester.getRect(find.byType(ResourceView)).bottom,
            closeTo(compact.top, 1));
        // A resize keeps the fold and the bar.
        tester.view.physicalSize = (size.flipped) * 2;
        await _settle(tester);
        expect(_controller(tester).listCollapsed.value, isTrue);
        expect(find.byType(AppBottomBar), findsOneWidget);
        await _done(tester);
      });
    }
  });

  group('the folded list opens with one gesture', () {
    Future<void> folded(WidgetTester tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      await tester.tap(find.byKey(const Key('list-toggle')));
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isTrue);
    }

    testWidgets('a drag from the edge follows the finger and opens',
        (tester) async {
      await folded(tester);
      final g = await tester.startGesture(const Offset(10, 300));
      await g.moveBy(const Offset(100, 0));
      await tester.pump();
      await g.moveBy(const Offset(100, 0));
      await tester.pump();
      // The list is as wide as the finger went.
      expect(tester.getRect(find.byType(ChatsScreen).hitTestable()).right,
          closeTo(200, 30));
      await g.up();
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isFalse);
      expect(tester.getRect(find.byType(ChatsScreen)).width, 400);
      await _done(tester);
    });

    testWidgets('a short drag settles back folded', (tester) async {
      await folded(tester);
      final g = await tester.startGesture(const Offset(10, 300));
      await g.moveBy(const Offset(40, 0));
      await tester.pump(const Duration(milliseconds: 300));
      await g.moveBy(const Offset(40, 0));
      await tester.pump(const Duration(milliseconds: 300));
      await g.up();
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isTrue);
      expect(find.byType(ChatsScreen).hitTestable(), findsNothing);
      await _done(tester);
    });

    testWidgets('a fling opens it', (tester) async {
      await folded(tester);
      // 90 dp in 40 ms: far short of a third of the list, but a fling.
      await tester.timedDragFrom(const Offset(10, 300), const Offset(90, 0),
          const Duration(milliseconds: 40));
      expect(_controller(tester).listCollapsed.value, isFalse);
      await _done(tester);
    });

    testWidgets('a tap on the tab opens it', (tester) async {
      await folded(tester);
      await tester.tap(find.byTooltip('Show list'));
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isFalse);
      await _done(tester);
    });
  });

  group('the list pane folds away', () {
    double listShown(WidgetTester tester) {
      final r = tester.getRect(find.byType(ChatsScreen).hitTestable());
      return r.right.clamp(0, double.infinity).toDouble();
    }

    for (final (name, size) in [
      ('portrait', _portrait),
      ('landscape', _landscape),
    ]) {
      testWidgets('$name: the handle folds and unfolds it, quickly',
          (tester) async {
        _size(tester, size);
        await tester.pumpWidget(_shell(_api()));
        await _settle(tester);
        await tester.tap(find.text('Plans'));
        await _settle(tester);
        final view = tester.state(find.byType(ResourceView));
        expect(find.byTooltip('Hide list'), findsOneWidget);

        await tester.tap(find.byKey(const Key('list-toggle')));
        await tester.pump();
        await tester.pump(const Duration(milliseconds: 70));
        // Half-way: moving.
        final mid = tester.getRect(find.byType(ResourceView)).left;
        expect(mid, greaterThan(1));
        await tester.pump(const Duration(milliseconds: 90));
        // Done within 150 ms: the page has the whole width.
        expect(tester.getRect(find.byType(ResourceView)).left, 0);
        expect(tester.getRect(find.byType(ResourceView)).width, size.width);
        expect(find.byType(ChatsScreen).hitTestable(), findsNothing);
        expect(_controller(tester).listCollapsed.value, isTrue);
        expect(tester.state(find.byType(ResourceView)), same(view));
        final prefs = await SharedPreferences.getInstance();
        expect(prefs.getBool(listCollapsedKey), isTrue);

        await tester.tap(find.byTooltip('Show list'));
        await _settle(tester);
        expect(find.text('Notes'), findsOneWidget);
        expect(tester.getRect(find.byType(ResourceView)).left,
            greaterThanOrEqualTo(320));
        expect(prefs.getBool(listCollapsedKey), isFalse);
        await _done(tester);
      });
    }

    testWidgets('folded stays folded through rotation and a phone size',
        (tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      final home = tester.state(find.byType(ChatsScreen));
      await tester.tap(find.byKey(const Key('list-toggle')));
      await _settle(tester);
      for (final size in [_portrait, _phone, _landscape]) {
        tester.view.physicalSize = size * 2;
        await _settle(tester);
        expect(tester.state(find.byType(ChatsScreen, skipOffstage: false)),
            same(home));
        if (size == _phone) {
          // The phone shows the home itself.
          expect(find.text('Plans'), findsOneWidget);
        } else {
          expect(find.text('Plans').hitTestable(), findsNothing,
              reason: '$size');
          expect(find.byKey(const Key('nothing-open')), findsOneWidget);
        }
      }
      // Home in the bar brings it back.
      await tester.tap(find.byTooltip('Home'));
      await _settle(tester);
      expect(find.text('Plans').hitTestable(), findsOneWidget);
      expect(listShown(tester), greaterThanOrEqualTo(320));
      await _done(tester);
    });

    testWidgets('a new shell starts folded when the device left it so',
        (tester) async {
      SharedPreferences.setMockInitialValues({listCollapsedKey: true});
      _size(tester, _portrait);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      expect(find.text('Plans').hitTestable(), findsNothing);
      // Search in the bar unfolds it, with the search.
      await tester.tap(find.byTooltip('Search'));
      await _settle(tester);
      expect(find.byType(SearchScreen).hitTestable(), findsOneWidget);
      expect(_controller(tester).listCollapsed.value, isFalse);
      await _done(tester);
    });

    testWidgets('dragging the divider resizes it, far left folds it',
        (tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      final before = tester.getSize(find.byType(ChatsScreen)).width;
      final handle = tester.getCenter(find.byKey(const Key('list-toggle')));
      await tester.dragFrom(handle, const Offset(60, 0));
      await _settle(tester);
      final wider = tester.getSize(find.byType(ChatsScreen)).width;
      expect(wider, closeTo(before + 60, 20));
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getDouble(listWidthKey), closeTo(wider, 1));
      await tester.dragFrom(
          tester.getCenter(find.byKey(const Key('list-toggle'))),
          Offset(-wider + 20, 0));
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isTrue);
      await _done(tester);
    });
  });

  group('section buttons', () {
    for (final (name, size) in [
      ('portrait', _portrait),
      ('landscape', _landscape),
    ]) {
      testWidgets('$name: All lists the section in the detail pane',
          (tester) async {
        _size(tester, size);
        await tester.pumpWidget(_shell(_api()));
        await _settle(tester);
        await tester.tap(find.byKey(const ValueKey('section-all-recents')));
        await _settle(tester);
        final list = tester.getRect(find.byType(ChatsScreen));
        // A page in the detail pane, titled, next to the home.
        final title = find.descendant(
            of: find.byType(AppTopBar), matching: find.text('Recents'));
        expect(title, findsOneWidget);
        expect(tester.getRect(title).left, greaterThan(list.right));
        expect(_controller(tester).topKind, ShellPage.listOf('recents'));
        // A row of it opens over it; back returns to the list.
        await tester.tap(find.text('Notes').last);
        await _settle(tester);
        expect(find.byType(ResourceView), findsOneWidget);
        await tester.binding.handlePopRoute();
        await _settle(tester);
        expect(title, findsOneWidget);
        await tester.binding.handlePopRoute();
        await _settle(tester);
        expect(find.byKey(const Key('nothing-open')), findsOneWidget);
        await _done(tester);
      });
    }

    testWidgets('a phone: All is a page of its own with a back button',
        (tester) async {
      _size(tester, _phone);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      await tester.tap(find.byKey(const ValueKey('section-all-recents')));
      await _settle(tester);
      expect(
          find.descendant(
              of: find.byType(AppTopBar), matching: find.text('Recents')),
          findsOneWidget);
      expect(find.byType(BackButton), findsOneWidget);
      await _done(tester);
    });

    testWidgets('Search on AI chats searches chats; on Drives drives',
        (tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      await tester.tap(find.byKey(const ValueKey('section-search-drives')));
      await _settle(tester);
      expect(find.byType(SearchScreen), findsOneWidget);
      expect(find.byKey(const Key('search-kind')), findsOneWidget);
      expect(_controller(tester).search.kind, SearchKind.drives);
      // The kind chip lets go of the kind.
      await tester.tap(find.byTooltip('Search everything'));
      await _settle(tester);
      expect(find.byKey(const Key('search-kind')), findsNothing);
      await _done(tester);
    });

    testWidgets('+ on Recents lists the kinds; on AI chats a new chat',
        (tester) async {
      _size(tester, _portrait);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      await tester.tap(find.byKey(const ValueKey('section-new-recents')));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 120));
      expect(find.text('Document'), findsOneWidget);
      await tester.tapAt(const Offset(5, 5));
      await _settle(tester);
      expect(find.byKey(const ValueKey('section-new-activity')), findsNothing);
      expect(find.byKey(const ValueKey('section-new-notifications')),
          findsNothing);
      await _done(tester);
    });

    for (final (name, size) in [
      ('a phone', _phone),
      ('a narrow phone at font 1.3', const Size(360, 740)),
      ('a tablet list pane at font 1.3', _portrait),
    ]) {
      testWidgets('headings fit: $name', (tester) async {
        _size(tester, size);
        if (name.contains('1.3')) {
          tester.platformDispatcher.textScaleFactorTestValue = 1.3;
          addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
        }
        await tester.pumpWidget(_shell(_api()));
        await _settle(tester);
        expect(tester.takeException(), isNull);
        final heading = find.byKey(const ValueKey('section-heading-recents'));
        final all = find.byKey(const ValueKey('section-all-recents'));
        expect(
            tester.getRect(heading).right,
            lessThanOrEqualTo(tester
                .getRect(find.byKey(const ValueKey('section-search-recents')))
                .left));
        expect(tester.getSize(all), const Size(48, 48));
        // The buttons sit at the right edge, in every section alike.
        final list = tester.getRect(find.byType(ChatsScreen));
        expect(tester.getRect(all).right, closeTo(list.right - 4, 1));
        expect(
            tester
                .getRect(find.byKey(const ValueKey('section-search-activity')))
                .right,
            closeTo(list.right - 4, 1));
        await _done(tester);
      });
    }

    testWidgets('a press on a heading washes the title, not the row',
        (tester) async {
      _size(tester, _phone);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      final heading = find.byKey(const ValueKey('section-heading-recents'));
      final ink = find.descendant(of: heading, matching: find.byType(InkWell));
      expect(tester.getSize(ink).width, lessThan(_phone.width / 2));
      expect(tester.widget<InkWell>(ink).borderRadius, isNotNull);
      // A tap still folds it.
      await tester.tap(heading);
      await _settle(tester);
      expect(find.text('Plans'), findsNothing);
      await tester.tap(heading);
      await _settle(tester);
      expect(find.text('Plans'), findsOneWidget);
      await _done(tester);
    });
  });
}
