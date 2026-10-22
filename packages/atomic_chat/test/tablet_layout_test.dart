import 'dart:math' as math;

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/gestures.dart' show PointerDeviceKind;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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
      classUrl: '',
      openedAt: 1,
      emoji: null,
      picture: null,
    );

FakeApi _api() => FakeApi(favoriteList: [
      _r('did:ad:plans', 'Plans'),
      _r('did:ad:notes', 'Notes'),
    ]);

/// Six favorites: more than a section shows, so it has a Show all row.
FakeApi _manyApi() => FakeApi(favoriteList: [
      _r('did:ad:plans', 'Plans'),
      _r('did:ad:a', 'Alpha'),
      _r('did:ad:b', 'Beta'),
      _r('did:ad:c', 'Gamma'),
      _r('did:ad:notes', 'Notes'),
      _r('did:ad:e', 'Epsilon'),
    ]);

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      profile: (_) => const Scaffold(body: Text('profile page')),
      home: ChatsScreen(drive: 'did:ad:drive', api: api),
    ));

ShellController _controller(WidgetTester tester) =>
    tester.widget<ShellScope>(find.byType(ShellScope).first).controller;

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
      // Favorites on top: on a short window the rest would push it under
      // the bar.
      SharedPreferences.setMockInitialValues({
        homeHiddenKey: ['drives', 'chats', 'activity', 'notifications'],
      });
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
      await tester.ensureVisible(find.text('Plans'));
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
      await tester.ensureVisible(find.text('Notes'));
      await tester.tap(find.text('Notes'));
      await _settle(tester);
      expect(find.byType(ResourceView), findsOneWidget);
      expect(tile('Plans').selected, isFalse);
      expect(tile('Notes').selected, isTrue);
      expect(_controller(tester).pages, hasLength(1));
      // Plans counts as visited once Notes took its place; Notes is open.
      expect(api.opened, ['did:ad:plans']);

      // A page of the bar in its place: no row is marked.
      await tester.tap(find.byTooltip('Profile'));
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

  testWidgets('the resource menu is in its pane, not in the sidebar bar',
      (tester) async {
    _size(tester, _landscape);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    expect(find.byTooltip('More'), findsNothing);
    await tester.tap(find.text('Plans'));
    await _settle(tester);
    // The page's menu: registered by the view once the page is up.
    final bar = find.byType(AppBottomBar);
    expect(find.descendant(of: bar, matching: find.byTooltip('More')),
        findsNothing);
    final more = find.byTooltip('More');
    expect(more, findsOneWidget);
    final pane = tester.getRect(find.byType(ResourceView));
    // As big as the web header it sits in, centred on its centre line.
    final r = tester.getRect(more);
    expect(r.width, lessThanOrEqualTo(kEmbedNavBarHeight));
    expect(r.height, lessThanOrEqualTo(kEmbedNavBarHeight));
    expect(r.center.dy, closeTo(pane.top + kEmbedNavBarHeight / 2, 0.5));
    expect(r.right, closeTo(pane.right - kEmbedNavBarTrailingInset, 0.5));
    expect(tester.getSize(find.byIcon(Icons.more_vert)).width, 20);
    await _done(tester);
  });

  for (final (width, scale) in [
    (304.0, 1.0),
    (400.0, 1.0),
    (520.0, 1.0),
    (304.0, 1.3),
    (568.0, 1.3), // the rubber band's overshoot
  ]) {
    testWidgets('the bar: five evenly spread buttons at $width dp, text $scale',
        (tester) async {
      SharedPreferences.setMockInitialValues({listWidthKey: width});
      _size(tester, _landscape);
      tester.platformDispatcher.textScaleFactorTestValue = scale;
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      final bar = find.byType(AppBottomBar);
      List<Rect> buttons() => [
            for (final tip in [
              'Home',
              'Search',
              'New',
              'Profile',
              'Close sidebar',
            ])
              tester.getRect(find.descendant(
                  of: bar, matching: find.byTooltip(tip).first)),
          ];
      final before = buttons();
      // Every button is whole, 48 dp, inside the bar, in order, centred in
      // the bar's height; no placeholder and no menu.
      final barRect = tester.getRect(bar);
      for (final r in before) {
        expect(r.width, greaterThanOrEqualTo(24));
        expect(r.left, greaterThanOrEqualTo(barRect.left));
        expect(r.right, lessThanOrEqualTo(barRect.right));
        expect(r.center.dy, closeTo(before.first.center.dy, 0.5));
      }
      for (var i = 1; i < before.length; i++) {
        expect(before[i].left, greaterThanOrEqualTo(before[i - 1].right - 0.5),
            reason: 'no overlap at $i');
      }
      expect(find.descendant(of: bar, matching: find.byTooltip('More')),
          findsNothing);
      final gaps = [
        for (var i = 1; i < before.length; i++)
          before[i].center.dx - before[i - 1].center.dx
      ];
      for (final g in gaps) {
        expect(g, closeTo(gaps.first, 1), reason: '$gaps');
      }

      // A resource opening moves none of them.
      await tester.tap(find.text('Plans'));
      await _settle(tester);
      expect(find.byTooltip('More'), findsOneWidget);
      final after = buttons();
      for (var i = 0; i < before.length; i++) {
        expect(after[i].center.dx, closeTo(before[i].center.dx, 0.5));
        expect(after[i].center.dy, closeTo(before[i].center.dy, 0.5));
      }
      await _done(tester);
    });
  }

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
    for (final t in [
      'AI chat',
      'AI voice',
      'Document',
      'New chat room',
      'New drive',
      'Other…'
    ]) {
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

  testWidgets('the bar opens Profile and a new chat in the detail',
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
    expect(find.byTooltip('Settings'), findsNothing);
    await tester.tap(find.byTooltip('Profile'));
    await _settle(tester);
    expect(find.text('the profile'), findsOneWidget);
    expect(find.byType(ChatsScreen), findsOneWidget);
    expect(_controller(tester).pages, hasLength(1));
    await tapNewChat(tester);
    await _settle(tester);
    expect(find.byType(ChatScreen), findsOneWidget);
    expect(_controller(tester).pages, hasLength(1));
    expect(find.byKey(const ValueKey('current:New')), findsOneWidget);
    // Back closes what is open.
    await tester.binding.handlePopRoute();
    await _settle(tester);
    expect(find.byKey(const Key('nothing-open')), findsOneWidget);
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
    // The phone's bar: the menu is the last slot, not next to a Settings button.
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

  testWidgets('a phone\'s search moves to the list pane on a resize',
      (tester) async {
    _size(tester, _phone);
    await tester.pumpWidget(_shell(_api()));
    await _settle(tester);
    await tester.tap(find.byTooltip('Search'));
    await _settle(tester);
    await tester.enterText(find.byType(TextField), 'pla');
    await _settle(tester);
    expect(ShellPage.isSearch(_controller(tester).topKind), isTrue);

    tester.view.physicalSize = _portrait * 2;
    await _settle(tester);
    expect(find.byType(SearchScreen), findsOneWidget);
    expect(_controller(tester).pages, isEmpty);
    expect(find.widgetWithText(TextField, 'pla'), findsOneWidget);
    expect(tester.getRect(find.byType(SearchScreen)).left, 0);
    // Its back returns the sidebar to the home.
    await tester.tap(find.byType(BackButton));
    await _settle(tester);
    expect(find.byType(SearchScreen), findsNothing);
    expect(find.text('Plans').hitTestable(), findsOneWidget);
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
    for (final tip in ['Profile']) {
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
    // The list runs the whole pane, so its scrollbar sits at the edge; its
    // content is centred at most 720 wide (readable_scrollbar_test).
    final strip = tester.getRect(find.byType(ListAndField));
    expect(strip.width, greaterThan(ReadableWidth.maxWidth));
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
        // Folded: the bar goes with the list, the pages have the window.
        await tester.tap(find.byKey(const Key('list-toggle')));
        await _settle(tester);
        expect(find.byType(AppBottomBar).hitTestable(), findsNothing);
        expect(tester.getRect(find.byType(ResourceView)), Offset.zero & size);
        // A resize keeps the fold; unfolded, the bar is back.
        tester.view.physicalSize = (size.flipped) * 2;
        await _settle(tester);
        expect(_controller(tester).listCollapsed.value, isTrue);
        await tester.tap(find.byTooltip('Show list'));
        await _settle(tester);
        expect(tester.getRect(find.byType(AppBottomBar)).width,
            tester.getRect(find.byType(ChatsScreen)).width);
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

        await tester.tap(find.byTooltip('Show list'));
        await _settle(tester);
        expect(find.text('Notes'), findsOneWidget);
        expect(tester.getRect(find.byType(ResourceView)).left,
            greaterThanOrEqualTo(320));
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
      // The tab at the left edge brings it back.
      await tester.tap(find.byTooltip('Show list'));
      await _settle(tester);
      expect(find.text('Plans').hitTestable(), findsOneWidget);
      expect(listShown(tester), greaterThanOrEqualTo(320));
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

  group('the divider is a quiet hairline', () {
    Widget themed(Brightness b) => app(
        AppShell(
          api: _api(),
          drive: 'did:ad:drive',
          warmPool: (_) => null,
          profile: (_) => const Scaffold(body: Text('profile page')),
          home: ChatsScreen(drive: 'did:ad:drive', api: _api()),
        ),
        brightness: b);

    ColoredBox line(WidgetTester tester) =>
        tester.widget<ColoredBox>(find.byKey(const Key('pane-divider')));
    double grabber(WidgetTester tester) => tester
        .widget<AnimatedOpacity>(find.byKey(const Key('pane-grabber')))
        .opacity;

    for (final b in Brightness.values) {
      testWidgets('${b.name}: faint 1 dp line, grabber hidden at rest',
          (tester) async {
        _size(tester, _landscape);
        await tester.pumpWidget(themed(b));
        await _settle(tester);
        expect(line(tester).color.a, lessThanOrEqualTo(0.12));
        expect(line(tester).color.a, greaterThan(0));
        expect(tester.getSize(find.byKey(const Key('pane-divider'))).width,
            lessThanOrEqualTo(1));
        expect(grabber(tester), lessThanOrEqualTo(0.2));
        await _done(tester);
      });
    }

    testWidgets('hover and drag bring the grabber and line up', (tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(themed(Brightness.light));
      await _settle(tester);
      final mouse = await tester.createGesture(kind: PointerDeviceKind.mouse);
      await mouse.addPointer(location: Offset.zero);
      await mouse
          .moveTo(tester.getCenter(find.byKey(const Key('list-toggle'))));
      await _settle(tester);
      expect(grabber(tester), greaterThan(0.2));
      await mouse.moveTo(Offset.zero);
      await _settle(tester);
      expect(grabber(tester), lessThanOrEqualTo(0.2));
      final drag = await tester
          .startGesture(tester.getCenter(find.byKey(const Key('list-toggle'))));
      await drag.moveBy(const Offset(40, 0));
      await tester.pump(const Duration(milliseconds: 200));
      expect(grabber(tester), greaterThan(0.2));
      expect(line(tester).color.a, closeTo(0.18, 0.01));
      await drag.up();
      await _settle(tester);
      expect(line(tester).color.a, lessThanOrEqualTo(0.12));
      await _done(tester);
    });
  });

  group('the divider is a rubber band past its bounds', () {
    // Where the divider is: the pane's shown width (the list inside keeps at
    // least its minimum while it is pulled narrower).
    double listWidth(WidgetTester tester) =>
        tester.getCenter(find.byKey(const Key('list-toggle'))).dx;

    Future<TestGesture> grab(WidgetTester tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      final g = await tester
          .startGesture(tester.getCenter(find.byKey(const Key('list-toggle'))));
      // The first move only gets past the touch slop.
      await g.moveBy(const Offset(30, 0));
      await tester.pump();
      await g.moveBy(const Offset(-30, 0));
      await tester.pump();
      return g;
    }

    testWidgets('inside the range it follows the finger 1:1', (tester) async {
      final g = await grab(tester);
      final start = listWidth(tester);
      for (var i = 0; i < 4; i++) {
        await g.moveBy(const Offset(10, 0));
        await tester.pump();
        expect(listWidth(tester), closeTo(start + 10.0 * (i + 1), 0.01));
      }
      await g.up();
      await _settle(tester);
      expect(listWidth(tester), closeTo(start + 40, 0.01));
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getDouble(listWidthKey), closeTo(start + 40, 0.01));
      await _done(tester);
    });

    testWidgets('far past the widest it gives less and less, then springs back',
        (tester) async {
      final g = await grab(tester);
      final start = listWidth(tester);
      final room = _landscape.width;
      final max = math.max(304.0, math.min(520.0, room - 280));
      final shown = <double>[];
      for (var i = 0; i < 30; i++) {
        await g.moveBy(const Offset(20, 0));
        await tester.pump();
        shown.add(listWidth(tester));
      }
      expect(start + 600, greaterThan(max));
      final over = shown.map((w) => w - max).toList();
      expect(over.last, greaterThan(20));
      expect(shown.every((w) => w <= max + 48), isTrue);
      // Every 20 dp of finger moves the pane less than the one before.
      final steps = [
        for (var i = 1; i < shown.length; i++) shown[i] - shown[i - 1]
      ].where((d) => d > 0).toList();
      for (var i = 1; i < steps.length; i++) {
        expect(steps[i], lessThanOrEqualTo(steps[i - 1] + 1e-9));
      }
      expect(steps.last, lessThan(1));
      await g.up();
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 60));
      // On its way back, not yet there.
      expect(listWidth(tester), lessThan(shown.last));
      await _settle(tester);
      expect(listWidth(tester), closeTo(max, 0.01));
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getDouble(listWidthKey), closeTo(max, 0.01));
      await _done(tester);
    });

    testWidgets('narrower than the least it follows the finger down to 0',
        (tester) async {
      final g = await grab(tester);
      final start = listWidth(tester);
      for (var target = 400.0; target >= 0; target -= 50) {
        await g.moveBy(Offset(target - listWidth(tester), 0));
        await tester.pump();
        expect(listWidth(tester), closeTo(target, 0.6), reason: '$target');
      }
      expect(start, greaterThan(0));
      expect(listWidth(tester), closeTo(0, 0.6));
      await g.up();
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isTrue);
      await _done(tester);
    });

    testWidgets('released below the fold threshold it folds', (tester) async {
      final g = await grab(tester);
      await g.moveBy(Offset(100 - listWidth(tester), 0));
      await tester.pump();
      expect(listWidth(tester), closeTo(100, 0.6));
      await g.up();
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isTrue);
      expect(find.byKey(const Key('list-toggle')), findsOneWidget);
      await _done(tester);
    });

    testWidgets('released at 250 it springs back to the least, not folded',
        (tester) async {
      final g = await grab(tester);
      await g.moveBy(Offset(250 - listWidth(tester), 0));
      await tester.pump();
      expect(listWidth(tester), closeTo(250, 0.6));
      await g.up();
      await _settle(tester);
      expect(listWidth(tester), closeTo(304, 0.01));
      expect(_controller(tester).listCollapsed.value, isFalse);
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getDouble(listWidthKey), closeTo(304, 0.01));
      await _done(tester);
    });

    testWidgets('a left fling from the least folds', (tester) async {
      SharedPreferences.setMockInitialValues({listWidthKey: 304.0});
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      await tester.fling(
          find.byKey(const Key('list-toggle')), const Offset(-60, 0), 1500);
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isTrue);
      await _done(tester);
    });

    test('the band is the identity inside, bounded outside, and invertible',
        () {
      expect(listRubberBand(400, 304, 520), 400);
      for (final raw in [521.0, 600.0, 700.0]) {
        final w = listRubberBand(raw, 304, 520);
        expect(w, greaterThan(520));
        expect(w, lessThanOrEqualTo(520 + listOvershootLimit));
        expect(listRubberBandInverse(w, 304, 520), closeTo(raw, 0.5));
      }
      expect(listRubberBand(0, 304, 520), greaterThanOrEqualTo(304 - 48));
      // Closing is never resisted: the divider uses 0 as its lower bound.
      expect(listRubberBand(100, 0, 520), 100);
    });
  });

  group('section headings and Show all', () {
    for (final (name, size) in [
      ('portrait', _portrait),
      ('landscape', _landscape),
    ]) {
      testWidgets('$name: Show all lists the section in the detail pane',
          (tester) async {
        _size(tester, size);
        await tester.pumpWidget(_shell(_manyApi()));
        await _settle(tester);
        await tester.ensureVisible(
            find.byKey(const ValueKey('section-show-all-favorites')));
        await tester.pump();
        await tester
            .tap(find.byKey(const ValueKey('section-show-all-favorites')));
        await _settle(tester);
        final list = tester.getRect(find.byType(ChatsScreen));
        // A page in the detail pane, titled, next to the home.
        final title = find.descendant(
            of: find.byType(AppTopBar), matching: find.text('Favorites'));
        expect(title, findsOneWidget);
        expect(tester.getRect(title).left, greaterThan(list.right));
        expect(_controller(tester).topKind, ShellPage.listOf('favorites'));
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

    testWidgets('a phone: Show all is a page of its own with a back button',
        (tester) async {
      _size(tester, _phone);
      await tester.pumpWidget(_shell(_manyApi()));
      await _settle(tester);
      await tester.ensureVisible(
          find.byKey(const ValueKey('section-show-all-favorites')));
      await tester.pump();
      await tester
          .tap(find.byKey(const ValueKey('section-show-all-favorites')));
      await _settle(tester);
      expect(
          find.descendant(
              of: find.byType(AppTopBar), matching: find.text('Favorites')),
          findsOneWidget);
      expect(find.byType(BackButton), findsOneWidget);
      await _done(tester);
    });

    testWidgets(
        'headings have no search, + or list buttons; <= 4 rows no '
        'Show all', (tester) async {
      _size(tester, _portrait);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      Finder inHome(Finder f) =>
          find.descendant(of: find.byType(ChatsScreen), matching: f);
      expect(inHome(find.byType(IconButton)), findsNothing);
      expect(inHome(find.byIcon(Icons.search)), findsNothing);
      expect(
          find.descendant(
              of: find.byKey(const Key('home-panels')),
              matching: find.byIcon(Icons.add)),
          findsNothing);
      expect(inHome(find.byIcon(Icons.format_list_bulleted)), findsNothing);
      expect(find.textContaining('Show all'), findsNothing);
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
        final heading = find.byKey(const ValueKey('home-panel-favorites'));
        expect(heading, findsOneWidget);
        expect(tester.getSize(heading).height, 48);
        await _done(tester);
      });
    }

    testWidgets('a heading is one tap target across the whole row',
        (tester) async {
      _size(tester, _phone);
      await tester.pumpWidget(_shell(_api()));
      await _settle(tester);
      final heading = find.byKey(const ValueKey('home-panel-favorites'));
      final ink = find.descendant(of: heading, matching: find.byType(InkWell));
      expect(tester.getSize(ink).width, _phone.width);
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

  group('the Samsung Galaxy Tab (SM-X810)', () {
    // 1752x2800 px at 340 dpi: about 824x1318 dp, 412x... in landscape.
    void samsung(WidgetTester tester, {bool landscape = false}) {
      tester.view.devicePixelRatio = 340 / 160;
      tester.view.physicalSize =
          landscape ? const Size(2800, 1752) : const Size(1752, 2800);
      // Gesture navigation: a handle strip under the window's content.
      tester.view.padding = const FakeViewPadding(bottom: 48 * 340 / 160);
      tester.view.viewPadding = const FakeViewPadding(bottom: 48 * 340 / 160);
      addTearDown(tester.view.reset);
    }

    _IdentityApi named() => _IdentityApi(const ProfileIdentity(name: 'Joep'));

    for (final landscape in [false, true]) {
      final name = landscape ? 'landscape' : 'portrait';
      testWidgets('$name, signed in: the list fills the sidebar above the bar',
          (tester) async {
        samsung(tester, landscape: landscape);
        await tester.pumpWidget(_shell(named()));
        await _settle(tester);
        final size = tester.view.physicalSize / tester.view.devicePixelRatio;
        // Open by default, the home's rows on screen.
        expect(_controller(tester).listCollapsed.value, isFalse);
        expect(find.text('Plans').hitTestable(), findsOneWidget);
        final list = tester.getRect(find.byType(ChatsScreen));
        final bar = tester.getRect(find.byType(AppBottomBar));
        // The bar: a row at the bottom of the sidebar, exactly its width,
        // with the system inset under its buttons in its own colour.
        expect(bar.left, 0);
        expect(bar.width, list.width);
        expect(bar.bottom, size.height);
        expect(list.bottom, bar.top);
        expect(list.height, greaterThan(size.height / 2));
        // A row of 56 dp above the inset; the first button at the left.
        expect(bar.height, 56 + 48);
        final home = tester.getRect(find.byTooltip('Home'));
        expect(home.left, lessThan(48));
        expect(home.center.dy, closeTo(bar.top + 28, 1));
        await _done(tester);
      });
    }

    testWidgets('folded: no bar, the pages have the whole window',
        (tester) async {
      samsung(tester);
      await tester.pumpWidget(_shell(named()));
      await _settle(tester);
      final size = tester.view.physicalSize / tester.view.devicePixelRatio;
      await tester.tap(find.text('Plans'));
      await _settle(tester);
      await tester.tap(find.byTooltip('Hide list'));
      await _settle(tester);
      expect(find.byType(AppBottomBar).hitTestable(), findsNothing);
      final page = tester.getRect(find.byType(ResourceView));
      expect(page, Offset.zero & size);
      // A way back to the list, at the left edge.
      expect(find.byTooltip('Show list'), findsOneWidget);
      await tester.tap(find.byTooltip('Show list'));
      await _settle(tester);
      expect(find.text('Plans').hitTestable(), findsOneWidget);
      expect(find.byType(AppBottomBar).hitTestable(), findsOneWidget);
      await _done(tester);
    });

    testWidgets('the sidebar header folds it', (tester) async {
      samsung(tester);
      await tester.pumpWidget(_shell(named()));
      await _settle(tester);
      expect(find.byKey(const Key('current-drive-header')), findsOneWidget);
      expect(find.byKey(const Key('atomic-wordmark')), findsNothing);
      await tester.tap(find.byTooltip('Close sidebar'));
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isTrue);
      expect(find.text('Plans').hitTestable(), findsNothing);
      await _done(tester);
    });

    testWidgets('a fold is not kept for the next start', (tester) async {
      SharedPreferences.setMockInitialValues({'shell_list_collapsed': true});
      samsung(tester);
      await tester.pumpWidget(_shell(named()));
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isFalse);
      expect(find.text('Plans').hitTestable(), findsOneWidget);
      await _done(tester);
    });

    testWidgets('Home, Search and the profile next to the sidebar',
        (tester) async {
      samsung(tester);
      await tester.pumpWidget(_shell(named()));
      await _settle(tester);
      expect(find.byKey(const ValueKey('current:Home')), findsOneWidget);
      // The profile opens next to the home's rows, marked while shown.
      await tester.tap(find.byTooltip('Joep'));
      await _settle(tester);
      expect(_controller(tester).topKind, ShellPage.profile);
      expect(find.byKey(const ValueKey('current:Profile')), findsOneWidget);
      expect(find.text('Plans').hitTestable(), findsOneWidget);
      // A row takes its place; the profile is no longer marked.
      await tester.tap(find.text('Plans'));
      await _settle(tester);
      expect(find.byKey(const ValueKey('current:Profile')), findsNothing);
      // Search over everything; back closes it, the page stays.
      await tester.tap(find.byTooltip('Search'));
      await _settle(tester);
      expect(find.byKey(const Key('search-palette')), findsOneWidget);
      expect(find.byKey(const ValueKey('current:Search')), findsOneWidget);
      expect(find.byKey(const ValueKey('current:Home')), findsNothing);
      await tester.binding.handlePopRoute();
      await _settle(tester);
      expect(find.byType(SearchScreen), findsNothing);
      expect(find.text('Plans').hitTestable(), findsOneWidget);
      expect(find.byType(ResourceView), findsOneWidget);
      expect(find.byKey(const ValueKey('current:Home')), findsOneWidget);
      // Home on the home closes the page.
      await tester.tap(find.byTooltip('Home'));
      await _settle(tester);
      expect(find.byKey(const Key('nothing-open')), findsOneWidget);
      await _done(tester);
    });

    testWidgets('folded: the button at the bottom left opens it',
        (tester) async {
      samsung(tester);
      await tester.pumpWidget(_shell(named()));
      await _settle(tester);
      final size = tester.view.physicalSize / tester.view.devicePixelRatio;
      await tester.tap(find.byTooltip('Close sidebar'));
      await _settle(tester);
      final open = tester.getRect(find.byTooltip('Show list'));
      expect(open.left, lessThan(24));
      // Above the system inset (48 dp), near the bottom.
      expect(open.bottom, lessThanOrEqualTo(size.height - 48));
      expect(open.bottom, greaterThan(size.height - 48 - 32));
      await tester.tap(find.byTooltip('Show list'));
      await _settle(tester);
      expect(_controller(tester).listCollapsed.value, isFalse);
      expect(find.text('Plans').hitTestable(), findsOneWidget);
      await _done(tester);
    });

    testWidgets('the avatar is not marked when its page is not open',
        (tester) async {
      samsung(tester);
      await tester.pumpWidget(_shell(_IdentityApi(const ProfileIdentity())));
      await _settle(tester);
      expect(find.byKey(const ValueKey('current:Profile')), findsNothing);
      final avatar = tester.widget<CircleAvatar>(find.descendant(
          of: find.byType(AppBottomBar), matching: find.byType(CircleAvatar)));
      final main =
          tester.element(find.byType(AppBottomBar)).appColors.mainSelectedBg;
      expect(avatar.backgroundColor, isNot(main));
      await _done(tester);
    });
  });

  group('the home page next to the sidebar is the activity feed', () {
    FakeApi withActivity({bool none = false}) => FakeApi(
          favoriteList: [_r('did:ad:plans', 'Plans')],
          driveList: const [],
          activityList: none
              ? const []
              : [
                  ActivityEntry(
                      subject: 'did:ad:budget',
                      drive: 'did:ad:drive',
                      kind: 'changed',
                      at: DateTime.now().millisecondsSinceEpoch,
                      actor: 'Polle',
                      name: 'Budget',
                      className: 'document-v2'),
                ],
        );

    testWidgets('nothing open: the feed, big; a row opens next to it',
        (tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(withActivity()));
      await _settle(tester);
      final feed = find.byKey(const Key('home-activity'));
      expect(feed, findsOneWidget);
      expect(find.descendant(of: feed, matching: find.text('Activity')),
          findsOneWidget);
      final row = find.descendant(of: feed, matching: find.text('Budget'));
      expect(row, findsOneWidget);
      // The scroll view spans the detail pane (scrollbar at its edge); the
      // content is at most 720 wide, centred.
      final list = tester.getRect(find.byType(ChatsScreen));
      expect(tester.getRect(feed).left, greaterThan(list.right));
      final feedRect = tester.getRect(feed);
      final title = tester
          .getRect(find.descendant(of: feed, matching: find.text('Activity')));
      expect(title.left - feedRect.left,
          greaterThanOrEqualTo((feedRect.width - 720) / 2));
      // Not a section of the sidebar as well.
      expect(find.byKey(const ValueKey('home-panel-activity')), findsNothing);
      await tester.tap(row);
      await _settle(tester);
      expect(find.byType(ResourceView), findsOneWidget);
      expect(feed, findsNothing);
      // Back: the feed again.
      await tester.binding.handlePopRoute();
      await _settle(tester);
      expect(feed, findsOneWidget);
      await _done(tester);
    });

    testWidgets('an empty feed says so', (tester) async {
      _size(tester, _portrait);
      await tester.pumpWidget(_shell(withActivity(none: true)));
      await _settle(tester);
      expect(find.textContaining('Nothing yet'), findsOneWidget);
      await _done(tester);
    });

    testWidgets('a phone keeps Activity as a section of the home',
        (tester) async {
      _size(tester, _phone);
      await tester.pumpWidget(_shell(withActivity()));
      await _settle(tester);
      expect(find.byKey(const Key('home-activity')), findsNothing);
      expect(find.byKey(const ValueKey('home-panel-activity')), findsOneWidget);
      await _done(tester);
    });
  });

  group('search on a tablet is a card over the window', () {
    FakeApi searchApi() => FakeApi(recent: [
          _r('did:ad:plans', 'Plans'),
          _r('did:ad:notes', 'Notes'),
        ], favoriteList: [
          _r('did:ad:plans', 'Plans'),
          _r('did:ad:notes', 'Notes'),
        ], hits: [
          (
            subject: 'did:ad:fox',
            title: 'Fox',
            className: 'document-v2',
            classUrl: '',
            drive: 'did:ad:drive',
            score: 2.0,
            emoji: null,
            picture: null
          ),
        ]);
    final palette = find.byKey(const Key('search-palette'));

    testWidgets('type, a result opens next to the sidebar and it closes',
        (tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(searchApi()));
      await _settle(tester);
      await tester.tap(find.byTooltip('Search'));
      await _settle(tester);
      expect(palette, findsOneWidget);
      final card = tester.getRect(palette);
      expect(card.width, lessThanOrEqualTo(640));
      expect(card.center.dx, closeTo(_landscape.width / 2, 1));
      expect(find.byKey(const ValueKey('current:Search')), findsOneWidget);
      // The sidebar is still the home.
      expect(_controller(tester).list.value, ShellPage.home);
      await tester.enterText(
          find.descendant(of: palette, matching: find.byType(TextField)),
          'fox');
      await _settle(tester);
      await tester
          .tap(find.descendant(of: palette, matching: find.text('Fox')));
      await _settle(tester);
      expect(palette, findsNothing);
      expect(find.byType(ResourceView), findsOneWidget);
      expect(tester.getRect(find.byType(ResourceView)).left,
          greaterThan(tester.getRect(find.byType(ChatsScreen)).right));
      expect(find.byKey(const ValueKey('current:Search')), findsNothing);
      await _done(tester);
    });

    testWidgets('a tap next to it closes it, nothing else changes',
        (tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(searchApi()));
      await _settle(tester);
      await tester.tap(find.text('Plans'));
      await _settle(tester);
      final view = tester.state(find.byType(ResourceView));
      final pages = _controller(tester).pages.length;
      await tester.tap(find.byTooltip('Search'));
      await _settle(tester);
      expect(palette, findsOneWidget);
      await tester.tapAt(Offset(_landscape.width - 10, _landscape.height - 10));
      await _settle(tester);
      expect(palette, findsNothing);
      expect(tester.state(find.byType(ResourceView)), same(view));
      expect(_controller(tester).pages, hasLength(pages));
      expect(_controller(tester).searching.value, isFalse);
      await _done(tester);
    });

    testWidgets('back closes it', (tester) async {
      _size(tester, _portrait);
      await tester.pumpWidget(_shell(searchApi()));
      await _settle(tester);
      await tester.tap(find.byTooltip('Search'));
      await _settle(tester);
      expect(palette, findsOneWidget);
      // Recently opened, before anything is typed.
      expect(find.descendant(of: palette, matching: find.text('Plans')),
          findsOneWidget);
      await tester.binding.handlePopRoute();
      await _settle(tester);
      expect(palette, findsNothing);
      expect(find.byKey(const Key('nothing-open')), findsOneWidget);
      await _done(tester);
    });

    testWidgets('Esc closes it', (tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(searchApi()));
      await _settle(tester);
      await tester.tap(find.byTooltip('Search'));
      await _settle(tester);
      await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      await _settle(tester);
      expect(palette, findsNothing);
      await _done(tester);
    });

    testWidgets('a phone keeps its search page', (tester) async {
      _size(tester, _phone);
      await tester.pumpWidget(_shell(searchApi()));
      await _settle(tester);
      await tester.tap(find.byTooltip('Search'));
      await _settle(tester);
      expect(palette, findsNothing);
      expect(find.byType(SearchScreen), findsOneWidget);
      await _done(tester);
    });
  });

  group('lists move when a page is left, not when it opens', () {
    setUp(resetDriveVisits);

    testWidgets(
        'drives: the last visited first in the switcher, also after a restart',
        (tester) async {
      _size(tester, _landscape);
      final api = _VisitApi();
      await tester.pumpWidget(_shell(api));
      await _settle(tester);

      Future<List<String>> switcher() async {
        await tester.tap(find.byKey(const Key('current-drive-switch')));
        await _settle(tester);
        final tops = {
          for (final d in ['a', 'b'])
            d: tester
                .getTopLeft(
                    find.byKey(ValueKey('drive-switcher-row-did:ad:$d')))
                .dy
        };
        return tops.keys.toList()..sort((x, y) => tops[x]!.compareTo(tops[y]!));
      }

      Future<void> close() async {
        await tester.binding.handlePopRoute();
        await _settle(tester);
      }

      expect(await switcher(), ['a', 'b']);
      // Picking Beta makes it the active drive and the first in the list.
      await tester
          .tap(find.byKey(const ValueKey('drive-switcher-switch-did:ad:b')));
      await _settle(tester);
      expect(api.activeSet, ['did:ad:b']);
      expect(find.byKey(const Key('drive-switcher')), findsNothing);
      expect(
          tester.widget<Text>(find.byKey(const Key('current-drive-name'))).data,
          'Beta');
      expect(await switcher(), ['b', 'a']);
      await close();

      // A fresh start reads the visits from the device.
      await _done(tester);
      resetDriveVisits();
      await warmDriveVisits();
      await tester.pumpWidget(_shell(_VisitApi()));
      await _settle(tester);
      expect(await switcher(), ['b', 'a']);
      await close();
      await _done(tester);
    });
  });

  group('Show mine', () {
    final chip = find.byKey(const Key('show-mine'));

    testWidgets('a tablet: the chip is on the Activity page, not the sidebar',
        (tester) async {
      _size(tester, _landscape);
      await tester.pumpWidget(_shell(_MineApi()));
      await _settle(tester);
      expect(chip, findsOneWidget);
      expect(find.byType(ChatsScreen).evaluate().length, 1);
      expect(
          find.descendant(
              of: find.byType(ChatsScreen),
              matching: find.widgetWithText(FilterChip, 'Show mine')),
          findsNothing);
      expect(
          find.descendant(
              of: find.byKey(const Key('home-activity')), matching: chip),
          findsOneWidget);
      expect(tester.widget<FilterChip>(chip).selected, isFalse);
      expect(find.text('My notes'), findsNothing);
      await tester.tap(chip);
      await _settle(tester);
      expect(tester.widget<FilterChip>(chip).selected, isTrue);
      expect(find.text('My notes'), findsOneWidget);
      expect(find.textContaining('You '), findsOneWidget);
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getBool('activity_show_mine'), isTrue);
      // A fresh start keeps it.
      await _done(tester);
      await tester.pumpWidget(_shell(_MineApi()));
      await _settle(tester);
      expect(tester.widget<FilterChip>(chip).selected, isTrue);
      expect(find.text('My notes'), findsOneWidget);
      await _done(tester);
    });

    testWidgets(
        'a phone: no chip in the Home section; the full page has it, '
        'toggling persists and the section follows', (tester) async {
      _size(tester, _phone);
      await tester.pumpWidget(_shell(_MineApi()));
      await _settle(tester);
      // The Home section has no chip and shows others' changes only.
      expect(find.byKey(const ValueKey('home-panel-activity')), findsOneWidget);
      expect(chip, findsNothing);
      expect(find.widgetWithText(FilterChip, 'Show mine'), findsNothing);
      expect(find.text('Budget'), findsOneWidget);
      expect(find.text('My notes'), findsNothing);
      // The full page: the chip in its bar.
      final showAll = find.byKey(const ValueKey('section-show-all-activity'));
      await tester.ensureVisible(showAll);
      await tester.tap(showAll);
      await _settle(tester);
      expect(chip, findsOneWidget);
      expect(find.descendant(of: find.byType(AppBar), matching: chip),
          findsOneWidget);
      expect(tester.widget<FilterChip>(chip).selected, isFalse);
      await tester.tap(chip);
      await _settle(tester);
      expect(tester.widget<FilterChip>(chip).selected, isTrue);
      expect(find.text('My notes'), findsOneWidget);
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getBool('activity_show_mine'), isTrue);
      // Back on the Home: the section includes own changes, still no chip.
      await tester.binding.handlePopRoute();
      await _settle(tester);
      expect(chip, findsNothing);
      expect(find.text('My notes'), findsOneWidget);
      expect(find.textContaining('You '), findsOneWidget);
      await _done(tester);
    });
  });
}

class _IdentityApi extends FakeApi {
  final ProfileIdentity who;
  _IdentityApi(this.who)
      : super(favoriteList: [
          _r('did:ad:plans', 'Plans'),
          _r('did:ad:notes', 'Notes'),
        ]);

  @override
  Future<ProfileIdentity?> ownIdentity() async => who;
}

/// Two drives, to see the visits reorder them.
class _VisitApi extends FakeApi {
  _VisitApi()
      : super(driveList: const [
          (subject: 'did:ad:a', name: 'Alpha', emoji: null, picture: null),
          (subject: 'did:ad:b', name: 'Beta', emoji: null, picture: null),
        ]);
}

/// Activity by others, and the person's own with "Show mine".
class _MineApi extends FakeApi {
  static ActivityEntry _a(String subject, String name, String actor) =>
      ActivityEntry(
          subject: subject,
          drive: 'did:ad:drive',
          kind: 'changed',
          at: DateTime.now().millisecondsSinceEpoch,
          actor: actor,
          name: name,
          className: 'document-v2');

  _MineApi()
      : super(
          driveList: const [],
          activityList: [
            _a('did:ad:budget', 'Budget', 'Polle'),
            for (var i = 0; i < 5; i++) _a('did:ad:o$i', 'Other $i', 'Polle'),
          ],
        );

  @override
  Future<List<ActivityEntry>> activityWithMine(int limit) async =>
      [_a('did:ad:mine', 'My notes', 'You'), ...await activity(limit)];
}
