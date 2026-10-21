import 'dart:async';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:atomic_chat/src/sidebar_metrics.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// The home is the current drive: its name and a switcher on top, its
/// children as a tree in the web sidebar's order, and the panels (Messages,
/// Favorites, AI chats) closed at the bottom.

DriveChild _child(String subject, String title,
        {String className = 'document-v2',
        bool expandable = true,
        String? emoji}) =>
    (
      subject: subject,
      title: title,
      className: className,
      expandable: expandable,
      emoji: emoji,
      picture: null,
    );

const _alpha = (subject: 'did:ad:a', name: 'Alpha', emoji: null, picture: null);
const _beta = (subject: 'did:ad:b', name: 'Beta', emoji: '🦊', picture: null);
const _gamma = (subject: 'did:ad:c', name: 'Gamma', emoji: null, picture: null);

RecentResource _res(String subject, String title) => (
      subject: subject,
      title: title,
      className: 'document-v2',
      openedAt: 1,
      emoji: null,
      picture: null,
    );

FakeApi _api({Map<String, List<DriveChild>>? children}) => FakeApi(
      driveList: const [_alpha, _beta, _gamma],
      childrenOf: children ??
          {
            // Not alphabetical: the drive's own order.
            'did:ad:a': [
              _child('did:ad:z', 'Zebra notes'),
              _child('did:ad:m', 'Mango plan'),
              _child('did:ad:f', 'Apple folder', className: 'folder'),
            ],
            'did:ad:b': [
              _child('did:ad:b1', 'Beta only'),
            ],
            'did:ad:f': [
              _child('did:ad:f1', 'Inside the folder'),
            ],
          },
      favoriteList: [_res('did:ad:fav', 'Starred doc')],
      conversationList: [_res('did:ad:dm', 'Alice, Bob')],
      chatList: [
        (subject: 'did:ad:chat', name: 'A chat', lastActivity: 0, emoji: null)
      ],
    );

FakeApi _manyFavorites() => FakeApi(
      driveList: const [_alpha],
      favoriteList: [for (var i = 0; i < 30; i++) _res('did:ad:f$i', 'Fav $i')],
      chatList: [
        for (var i = 0; i < 30; i++)
          (subject: 'did:ad:c$i', name: 'Chat $i', lastActivity: 0, emoji: null)
      ],
      childrenOf: {
        'did:ad:a': [
          _child('did:ad:z', 'Zebra notes'),
          _child('did:ad:m', 'Mango plan'),
          _child('did:ad:f', 'Apple folder', className: 'folder'),
        ],
        'did:ad:f': [_child('did:ad:f1', 'Inside the folder')],
      },
    );

double _maxScroll(WidgetTester tester, Finder body) => tester
    .state<ScrollableState>(
        find.descendant(of: body, matching: find.byType(Scrollable)).first)
    .position
    .maxScrollExtent;

/// A test on macOS: the desktop density.
void macTest(String name, Future<void> Function(WidgetTester) body) =>
    testWidgets(name, body,
        variant: TargetPlatformVariant.only(TargetPlatform.macOS));

void _size(WidgetTester tester, Size size, {double bottom = 0}) {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = size;
  tester.view.padding = FakeViewPadding(bottom: bottom);
  addTearDown(tester.view.reset);
}

Future<void> _home(WidgetTester tester, FakeApi api,
    {String drive = 'did:ad:a', Brightness? brightness}) async {
  await tester.pumpWidget(app(ChatsScreen(drive: drive, api: api),
      brightness: brightness ?? Brightness.light));
  await tester.pumpAndSettle();
}

double _top(WidgetTester tester, String subject) =>
    tester.getTopLeft(find.byKey(ValueKey('drive-tree-row-$subject'))).dy;

double _contrast(Color a, Color b) {
  final hi = a.computeLuminance() > b.computeLuminance() ? a : b;
  final lo = identical(hi, a) ? b : a;
  return (hi.computeLuminance() + 0.05) / (lo.computeLuminance() + 0.05);
}

Finder _panel(String name) => find.byKey(ValueKey('home-panel-$name'));

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    // The app's defaults: panels closed, accordion by window size.
    HomeLayout.fresh = HomeLayout.closed;
    HomeLayout.accordionOverride = null;
    ResourceView.serverFactory = () async => throw 'no server in a test';
  });

  group('the current drive heads the home', () {
    testWidgets('its name and avatar replace the wordmark', (tester) async {
      await _home(tester, _api(), drive: 'did:ad:b');
      expect(find.byKey(const Key('current-drive-header')), findsOneWidget);
      expect(
          tester.widget<Text>(find.byKey(const Key('current-drive-name'))).data,
          'Beta');
      // Its emoji is the avatar.
      expect(
          find.descendant(
              of: find.byKey(const Key('current-drive-header')),
              matching: find.text('🦊')),
          findsOneWidget);
      expect(find.byType(AtomicWordmark), findsNothing);
      expect(find.textContaining('atomic.place'), findsNothing);
      expect(find.byKey(const Key('atomic-wordmark')), findsNothing);
      // The selector chevron of the web sidebar.
      expect(find.byIcon(Icons.unfold_more), findsOneWidget);
    });

    testWidgets('an untitled drive says so', (tester) async {
      final api = FakeApi(driveList: const [
        (subject: 'did:ad:a', name: '', emoji: null, picture: null)
      ]);
      await _home(tester, api);
      expect(
          tester.widget<Text>(find.byKey(const Key('current-drive-name'))).data,
          'Untitled drive');
    });
  });

  group('the quick drive switcher', () {
    testWidgets('a bottom sheet on a phone, with every drive and a check',
        (tester) async {
      _size(tester, const Size(393, 851));
      await _home(tester, _api());
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      expect(find.byType(BottomSheet), findsOneWidget);
      expect(find.byKey(const Key('drive-switcher-popover')), findsNothing);
      expect(find.byKey(const Key('drive-switcher')), findsOneWidget);
      expect(find.byKey(const Key('drive-switcher-search')), findsOneWidget);
      for (final d in [_alpha, _beta, _gamma]) {
        expect(find.byKey(ValueKey('drive-switcher-row-${d.subject}')),
            findsOneWidget);
      }
      // The current one is checked, the others are not.
      expect(
          find.descendant(
              of: find.byKey(const ValueKey('drive-switcher-row-did:ad:a')),
              matching: find.byKey(const Key('drive-switcher-current'))),
          findsOneWidget);
      expect(find.byKey(const Key('drive-switcher-current')), findsOneWidget);
      expect(find.byKey(const Key('drive-switcher-manage')), findsOneWidget);
    });

    testWidgets('a popover under the header from tablet width on',
        (tester) async {
      _size(tester, const Size(1000, 800));
      await _home(tester, _api());
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('drive-switcher-popover')), findsOneWidget);
      expect(find.byType(BottomSheet), findsNothing);
      final header =
          tester.getRect(find.byKey(const Key('current-drive-header')));
      final pop =
          tester.getRect(find.byKey(const Key('drive-switcher-popover')));
      expect(pop.top, greaterThanOrEqualTo(header.bottom));
      expect(pop.left, lessThanOrEqualTo(header.left + 1));
      // Tapping outside closes it.
      await tester.tapAt(const Offset(900, 700));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('drive-switcher')), findsNothing);
    });

    testWidgets('searching filters as you type', (tester) async {
      await _home(tester, _api());
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      await tester.enterText(
          find.byKey(const Key('drive-switcher-search')), 'gam');
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('drive-switcher-row-did:ad:c')),
          findsOneWidget);
      expect(find.byKey(const ValueKey('drive-switcher-row-did:ad:a')),
          findsNothing);
      expect(find.byKey(const ValueKey('drive-switcher-row-did:ad:b')),
          findsNothing);
      await tester.enterText(
          find.byKey(const Key('drive-switcher-search')), 'zzz');
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('drive-switcher-empty')), findsOneWidget);
    });

    testWidgets('picking a drive sets it active and the tree follows',
        (tester) async {
      final api = _api();
      await _home(tester, api);
      expect(find.text('Zebra notes'), findsOneWidget);
      expect(find.text('Beta only'), findsNothing);
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      await tester
          .tap(find.byKey(const ValueKey('drive-switcher-switch-did:ad:b')));
      await tester.pumpAndSettle();
      // Closed, set in the store, the header and the tree are the other's.
      expect(find.byKey(const Key('drive-switcher')), findsNothing);
      expect(api.activeSet, ['did:ad:b']);
      expect(
          tester.widget<Text>(find.byKey(const Key('current-drive-name'))).data,
          'Beta');
      expect(find.text('Beta only'), findsOneWidget);
      expect(find.text('Zebra notes'), findsNothing);
      expect(api.childrenAsked, contains('did:ad:b'));
    });

    testWidgets('the current drive has a chip and no Switch button',
        (tester) async {
      await _home(tester, _api());
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      expect(
          find.descendant(
              of: find.byKey(const ValueKey('drive-switcher-row-did:ad:a')),
              matching: find.text('Current')),
          findsOneWidget);
      expect(find.byIcon(Icons.check), findsOneWidget);
      expect(find.byKey(const ValueKey('drive-switcher-switch-did:ad:a')),
          findsNothing);
      expect(find.byKey(const ValueKey('drive-switcher-switch-did:ad:b')),
          findsOneWidget);
      expect(find.text('Switch'), findsNWidgets(2));
    });

    testWidgets("the left part opens the drive's page, the drive stays",
        (tester) async {
      _size(tester, const Size(393, 851));
      final api = _api();
      await _home(tester, api);
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Beta'));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('drive-switcher')), findsNothing);
      expect(api.activeSet, isEmpty);
      final page = tester.widget<ResourceView>(find.byType(ResourceView));
      expect(page.path ?? page.subject, anyOf(isNull, contains('did:ad:b')));
      // The home underneath still has the current drive.
      expect(
          tester
              .widget<Text>(find.byKey(const Key('current-drive-name'),
                  skipOffstage: false))
              .data,
          'Alpha');
    });

    testWidgets('the current drive row opens its page too', (tester) async {
      final api = _api();
      await _home(tester, api);
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      await tester
          .tap(find.byKey(const ValueKey('drive-switcher-open-did:ad:a')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('drive-switcher')), findsNothing);
      expect(api.activeSet, isEmpty);
      expect(find.byType(ResourceView), findsOneWidget);
    });

    for (final width in [393.0, 1000.0]) {
      testWidgets(
          'rows span the full width and the button sits 12 from the '
          'edge at $width', (tester) async {
        _size(tester, Size(width, 851));
        await _home(tester, _api());
        await tester.tap(find.byKey(const Key('current-drive-header')));
        await tester.pumpAndSettle();
        final box = tester.getRect(find.byKey(
            Key(width < 600 ? 'drive-switcher' : 'drive-switcher-popover')));
        for (final d in [_alpha, _beta, _gamma]) {
          final row = tester
              .getRect(find.byKey(ValueKey('drive-switcher-row-${d.subject}')));
          expect(row.width, box.width);
          expect(row.left, box.left);
          expect(row.height, greaterThanOrEqualTo(56));
        }
        final manage =
            tester.getRect(find.byKey(const Key('drive-switcher-manage')));
        expect(manage.width, box.width);
        final button = tester.getRect(
            find.byKey(const ValueKey('drive-switcher-switch-did:ad:b')));
        final row = tester
            .getRect(find.byKey(const ValueKey('drive-switcher-row-did:ad:b')));
        expect(row.right - button.right, 12);
        expect(button.height, inInclusiveRange(32, 36));
        // The left part takes what the button leaves.
        final open = tester.getRect(
            find.byKey(const ValueKey('drive-switcher-open-did:ad:b')));
        expect(open.left, row.left);
        expect(open.right, lessThanOrEqualTo(button.left));
      });
    }

    testWidgets('keyboard and semantics', (tester) async {
      final handle = tester.ensureSemantics();
      await _home(tester, _api());
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      expect(find.bySemanticsLabel('Open Beta'), findsOneWidget);
      expect(find.bySemanticsLabel('Switch to Beta'), findsOneWidget);
      expect(find.bySemanticsLabel('Switch to Alpha'), findsNothing);
      handle.dispose();
    });

    testWidgets('Ctrl+Enter on a focused row switches', (tester) async {
      final api = _api();
      await _home(tester, api);
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      final focus = Focus.of(tester.element(find.descendant(
          of: find.byKey(const ValueKey('drive-switcher-open-did:ad:b')),
          matching: find.text('Beta'))));
      focus.requestFocus();
      await tester.pump();
      await tester.sendKeyDownEvent(LogicalKeyboardKey.controlLeft);
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.sendKeyUpEvent(LogicalKeyboardKey.controlLeft);
      await tester.pumpAndSettle();
      expect(api.activeSet, ['did:ad:b']);
    });

    for (final brightness in [Brightness.light, Brightness.dark]) {
      testWidgets('the button label and the chip are legible in $brightness',
          (tester) async {
        await _home(tester, _api(), brightness: brightness);
        await tester.tap(find.byKey(const Key('current-drive-header')));
        await tester.pumpAndSettle();
        final button = tester.widget<FilledButton>(
            find.byKey(const ValueKey('drive-switcher-switch-did:ad:b')));
        final bg = button.style!.backgroundColor!.resolve({})!;
        final fg = button.style!.foregroundColor!.resolve({})!;
        expect(_contrast(fg, bg), greaterThanOrEqualTo(4.5));
        final chip = tester
            .widget<Container>(find.byKey(const Key('drive-switcher-current')));
        final chipBg = (chip.decoration as BoxDecoration).color!;
        final label = tester.widget<Text>(
            find.byKey(const Key('drive-switcher-current-label')));
        expect(
            _contrast(label.style!.color!, chipBg), greaterThanOrEqualTo(4.5));
      });
    }

    testWidgets('Manage drives… lists every drive on a page of its own',
        (tester) async {
      await _home(tester, _api());
      await tester.tap(find.byKey(const Key('current-drive-header')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('drive-switcher-manage')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('drive-switcher')), findsNothing);
      expect(find.text('Gamma'), findsOneWidget);
      expect(find.text('Drives'), findsWidgets);
    });
  });

  group('the drive tree', () {
    testWidgets("lists the children in the drive's order, not by name",
        (tester) async {
      await _home(tester, _api());
      expect(find.byKey(const Key('drive-tree')), findsOneWidget);
      expect(_top(tester, 'did:ad:z'), lessThan(_top(tester, 'did:ad:m')));
      expect(_top(tester, 'did:ad:m'), lessThan(_top(tester, 'did:ad:f')));
      // "New" is the last row.
      expect(tester.getTopLeft(find.byKey(const Key('drive-new-row'))).dy,
          greaterThan(_top(tester, 'did:ad:f')));
    });

    testWidgets('a folder unfolds and folds, and is remembered per drive',
        (tester) async {
      final api = _api();
      await _home(tester, api);
      expect(find.text('Inside the folder'), findsNothing);
      await tester
          .tap(find.byKey(const ValueKey('drive-tree-toggle-did:ad:f')));
      await tester.pumpAndSettle();
      expect(find.text('Inside the folder'), findsOneWidget);
      // Indented one level under its folder, right below it.
      expect(_top(tester, 'did:ad:f1'), greaterThan(_top(tester, 'did:ad:f')));
      expect(tester.getTopLeft(find.text('Inside the folder')).dx,
          greaterThan(tester.getTopLeft(find.text('Apple folder')).dx));
      // A document has no chevron.
      expect(find.byKey(const ValueKey('drive-tree-toggle-did:ad:z')),
          findsNothing);

      // A fresh start finds it open.
      await tester.pumpWidget(const SizedBox());
      await _home(tester, api);
      expect(find.text('Inside the folder'), findsOneWidget);

      await tester
          .tap(find.byKey(const ValueKey('drive-tree-toggle-did:ad:f')));
      await tester.pumpAndSettle();
      expect(find.text('Inside the folder'), findsNothing);
      await tester.pumpWidget(const SizedBox());
      await _home(tester, api);
      expect(find.text('Inside the folder'), findsNothing);
      // Kept under the drive's own key.
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getStringList(driveTreeOpenKey('did:ad:a')), isEmpty);
      expect(prefs.getStringList(driveTreeOpenKey('did:ad:b')), isNull);
    });

    testWidgets('a row opens its resource', (tester) async {
      await _home(tester, _api());
      await tester.tap(find.text('Mango plan'));
      await tester.pumpAndSettle();
      final page = tester.widget<ResourceView>(find.byType(ResourceView));
      expect(page.subject, 'did:ad:m');
      expect(page.drive, 'did:ad:a');
    });

    testWidgets('long lists build the rows in view only', (tester) async {
      _size(tester, const Size(393, 851));
      final api = _api(children: {
        'did:ad:a': [
          for (var i = 0; i < 1000; i++) _child('did:ad:r$i', 'Row $i'),
        ],
      });
      await _home(tester, api);
      expect(find.text('Row 0'), findsOneWidget);
      expect(find.text('Row 999'), findsNothing);
      expect(find.byType(ResourceRow).evaluate().length, lessThan(40));
    });

    testWidgets('a spinner while loading', (tester) async {
      final gate = Completer<void>();
      final api = _api()..driveChildrenGate = gate.future;
      await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:a', api: api)));
      await tester.pump(const Duration(milliseconds: 50));
      expect(find.byKey(const ValueKey('drive-tree-loading-did:ad:a')),
          findsOneWidget);
      gate.complete();
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('drive-tree-loading-did:ad:a')),
          findsNothing);
      expect(find.text('Zebra notes'), findsOneWidget);
    });

    testWidgets('an empty drive says so and still offers New', (tester) async {
      await _home(tester, _api(children: const {}));
      expect(find.byKey(const Key('drive-tree-empty')), findsOneWidget);
      expect(find.text('Nothing here yet'), findsOneWidget);
      expect(find.byKey(const Key('drive-new-row')), findsOneWidget);
    });

    testWidgets('an error shows with Retry, which reads again', (tester) async {
      final api = _api()..driveChildrenError = 'Could not read';
      await _home(tester, api);
      expect(find.text('Could not read'), findsOneWidget);
      expect(find.byKey(const ValueKey('drive-tree-retry-did:ad:a')),
          findsOneWidget);
      api.driveChildrenError = null;
      await tester.tap(find.byKey(const ValueKey('drive-tree-retry-did:ad:a')));
      await tester.pumpAndSettle();
      expect(find.text('Could not read'), findsNothing);
      expect(find.text('Zebra notes'), findsOneWidget);
    });

    testWidgets('"New" opens the new-document sheet on the current drive',
        (tester) async {
      // The last used drive is another one: the current drive wins.
      SharedPreferences.setMockInitialValues({newResourceDriveKey: 'did:ad:c'});
      final api = _api();
      await _home(tester, api, drive: 'did:ad:b');
      await tester.tap(find.byKey(const Key('drive-new-row')));
      await tester.pumpAndSettle();
      expect(find.text('New document'), findsOneWidget);
      expect(
          tester
              .widget<ChoiceChip>(find.byKey(const ValueKey('drive-did:ad:b')))
              .selected,
          isTrue);
      await tester.enterText(find.byKey(const Key('new-document-name')), 'Hi');
      await tester.tap(find.text('Create'));
      await tester.pumpAndSettle();
      expect(api.createdResources.single.$1, 'did:ad:b');
      expect(api.createdResources.single.$3, 'Hi');
      expect(find.byType(ResourceView), findsOneWidget);
    });
  });

  group('the panels', () {
    testWidgets('are closed by default and keep their state', (tester) async {
      _size(tester, const Size(393, 851));
      await _home(tester, _api());
      for (final name in ['messages', 'favorites', 'chats']) {
        expect(_panel(name), findsOneWidget, reason: name);
      }
      expect(find.text('Starred doc'), findsNothing);
      expect(find.text('A chat'), findsNothing);
      await tester.tap(_panel('favorites'));
      await tester.pumpAndSettle();
      expect(find.text('Starred doc'), findsOneWidget);
      // Remembered across a restart.
      await tester.pumpWidget(const SizedBox());
      HomeLayout.fresh = HomeLayout.closed;
      await _home(tester, _api());
      expect(find.text('Starred doc'), findsOneWidget);
    });

    testWidgets('sit at the bottom, in the web order, above the safe area',
        (tester) async {
      _size(tester, const Size(393, 851), bottom: 34);
      await _home(tester, _api());
      final messages = tester.getRect(_panel('messages'));
      final favorites = tester.getRect(_panel('favorites'));
      final chats = tester.getRect(_panel('chats'));
      expect(messages.top, lessThan(favorites.top));
      expect(favorites.top, lessThan(chats.top));
      expect(chats.bottom, 851 - 34);
      // The tree is above them and takes the room.
      expect(tester.getTopLeft(find.byKey(const Key('drive-new-row'))).dy,
          lessThan(messages.top));
    });

    testWidgets('opening one keeps the headers pinned to the bottom',
        (tester) async {
      _size(tester, const Size(393, 851), bottom: 34);
      await _home(tester, _api());
      final before = tester.getRect(_panel('chats')).bottom;
      await tester.tap(_panel('favorites'));
      await tester.pumpAndSettle();
      expect(tester.getRect(_panel('chats')).bottom, before);
      expect(tester.getRect(_panel('favorites')).bottom,
          lessThan(tester.getRect(_panel('chats')).top));
      // The rows grew upwards, into the tree's room.
      expect(find.text('Starred doc'), findsOneWidget);
      expect(tester.getBottomLeft(find.text('Starred doc')).dy,
          lessThan(tester.getRect(_panel('chats')).top));
      // The panels take at most half the column.
      final panels = tester.getRect(find.byKey(const Key('home-panels')));
      expect(panels.height, lessThanOrEqualTo(851 * 0.5 + 1));
    });

    testWidgets('on a phone one is open at a time', (tester) async {
      _size(tester, const Size(393, 851));
      await _home(tester, _api());
      await tester.tap(_panel('favorites'));
      await tester.pumpAndSettle();
      expect(find.text('Starred doc'), findsOneWidget);
      await tester.tap(_panel('chats'));
      await tester.pumpAndSettle();
      expect(find.text('A chat'), findsOneWidget);
      expect(find.text('Starred doc'), findsNothing);
      // Only the last one opened is kept.
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getStringList(homeCollapsedKey), isNot(contains('chats')));
      expect(prefs.getStringList(homeCollapsedKey), contains('favorites'));
    });

    testWidgets('on a wide window several stay open', (tester) async {
      _size(tester, const Size(1000, 800));
      await _home(tester, _api());
      await tester.tap(_panel('favorites'));
      await tester.pumpAndSettle();
      await tester.tap(_panel('chats'));
      await tester.pumpAndSettle();
      expect(find.text('Starred doc'), findsOneWidget);
      expect(find.text('A chat'), findsOneWidget);
      final panels = tester.getRect(find.byKey(const Key('home-panels')));
      expect(panels.height, lessThanOrEqualTo(800 * 0.5 + 1));
    });

    testWidgets('shrinking the window leaves the most recent one open',
        (tester) async {
      _size(tester, const Size(1000, 800));
      await _home(tester, _api());
      await tester.tap(_panel('favorites'));
      await tester.pumpAndSettle();
      await tester.tap(_panel('chats'));
      await tester.pumpAndSettle();
      expect(find.text('Starred doc'), findsOneWidget);
      expect(find.text('A chat'), findsOneWidget);

      tester.view.physicalSize = const Size(393, 851);
      await tester.pumpAndSettle();
      expect(find.text('A chat'), findsOneWidget);
      expect(find.text('Starred doc'), findsNothing);
    });

    testWidgets('an open panel shows its four rows without scrolling',
        (tester) async {
      _size(tester, const Size(393, 851), bottom: 20);
      await _home(tester, _manyFavorites());
      final treeBefore = tester.getRect(find.byKey(const Key('drive-tree')));
      await tester.tap(_panel('favorites'));
      await tester.pumpAndSettle();
      expect(tester.getRect(_panel('chats')).bottom, 851 - 20);
      final body = find.byKey(const ValueKey('home-panel-body-favorites'));
      final bodyRect = tester.getRect(body);
      for (var i = 0; i < 4; i++) {
        final r = tester.getRect(find.text('Fav $i'));
        expect(r.top, greaterThanOrEqualTo(bodyRect.top));
        expect(r.bottom, lessThanOrEqualTo(bodyRect.bottom));
      }
      expect(find.text('Show all (30)'), findsOneWidget);
      expect(_maxScroll(tester, body), 0);
      // The tree yields.
      expect(tester.getRect(find.byKey(const Key('drive-tree'))).height,
          lessThan(treeBefore.height));
      expect(tester.takeException(), isNull);
    });

    macTest('on a wide window several open panels all show four rows',
        (tester) async {
      _size(tester, const Size(1400, 900));
      HomeLayout.accordionOverride = false;
      await _home(tester, _manyFavorites());
      await tester.tap(_panel('favorites'));
      await tester.pumpAndSettle();
      await tester.tap(_panel('chats'));
      await tester.pumpAndSettle();
      for (final name in ['favorites', 'chats']) {
        final body = find.byKey(ValueKey('home-panel-body-$name'));
        expect(_maxScroll(tester, body), 0, reason: name);
      }
      expect(tester.takeException(), isNull);
    });

    testWidgets('a very short window falls back to scrolling inside',
        (tester) async {
      _size(tester, const Size(393, 500), bottom: 20);
      await _home(tester, _manyFavorites());
      await tester.tap(_panel('favorites'));
      await tester.pumpAndSettle();
      final body = find.byKey(const ValueKey('home-panel-body-favorites'));
      expect(_maxScroll(tester, body), greaterThan(0));
      expect(tester.getRect(_panel('chats')).bottom, 500 - 20);
      expect(tester.takeException(), isNull);
    });
  });

  group('desktop density', () {
    Future<void> desktop(WidgetTester tester, {Brightness? b}) async {
      _size(tester, const Size(1400, 900));
      HomeLayout.accordionOverride = false;
      await _home(tester, _manyFavorites(), brightness: b);
      await tester.tap(_panel('favorites'));
      await tester.pumpAndSettle();
      await tester
          .tap(find.byKey(const ValueKey('drive-tree-toggle-did:ad:f')));
      await tester.pumpAndSettle();
    }

    Finder row(String text) =>
        find.ancestor(of: find.text(text), matching: find.byType(SidebarRow));
    double left(WidgetTester t, Finder f) => t.getTopLeft(f).dx;

    macTest('rows are tight and the text is still legible', (tester) async {
      await desktop(tester);
      for (final t in [
        'Zebra notes',
        'Apple folder',
        'Inside the folder',
        'New',
        'Fav 0'
      ]) {
        expect(tester.getSize(row(t)).height, lessThanOrEqualTo(32), reason: t);
        expect(tester.getSize(row(t)).height, greaterThanOrEqualTo(24));
        final text = tester
            .widget<Text>(find.descendant(of: row(t), matching: find.text(t)));
        expect(text.style!.fontSize, greaterThanOrEqualTo(13), reason: t);
      }
      expect(tester.getSize(_panel('favorites')).height, lessThanOrEqualTo(34));
      expect(
          tester.getSize(find.byKey(const Key('current-drive-header'))).height,
          inInclusiveRange(40, 44));
    });

    macTest('all row kinds sit on one grid', (tester) async {
      await desktop(tester);
      const m = SidebarMetrics.desktop;
      // Rows of one kind are equally high.
      expect(tester.getSize(row('Zebra notes')).height,
          tester.getSize(row('Mango plan')).height);
      expect(tester.getSize(row('Zebra notes')).height,
          tester.getSize(row('Fav 0')).height);
      expect(tester.getSize(row('Zebra notes')).height,
          tester.getSize(row('New')).height);
      // Tint is full-bleed.
      expect(
          tester.getSize(row('Zebra notes')).width,
          1400 > 0
              ? tester.getSize(find.byKey(const Key('drive-tree'))).width
              : 0);
      // Icon centres: level 0 equal, level 1 + indent.
      double iconX(Finder r, {bool add = false}) => tester
          .getCenter(find.descendant(
              of: r,
              matching: add ? find.byIcon(Icons.add) : find.byType(RowLeading)))
          .dx;
      final x0 = iconX(row('Zebra notes'));
      expect(iconX(row('Apple folder')), x0);
      expect(iconX(row('Fav 0')), x0);
      expect(iconX(row('New'), add: true), x0);
      expect(iconX(row('Inside the folder')), x0 + m.indent);
      expect(x0, m.hPad + m.iconSlot / 2);
      // Titles share x at a level.
      final t0 = left(tester, find.text('Zebra notes'));
      expect(left(tester, find.text('Apple folder')), t0);
      expect(left(tester, find.text('New')), t0);
      expect(left(tester, find.text('Fav 0')), t0);
      expect(left(tester, find.text('Show all (30)')), t0);
      expect(left(tester, find.text('Inside the folder')), t0 + m.indent);
      expect(t0, m.titleX(0));
      // Header titles start at the icon column.
      expect(left(tester, find.text('Favorites')), m.hPad);
      // Chevrons end at the same x.
      final tree = tester
          .getRect(find.byKey(const ValueKey('drive-tree-toggle-did:ad:f')));
      final panel =
          tester.getRect(find.byKey(const Key('panel-chevron')).first);
      expect(tree.right, panel.right);
      expect(
          tree.right,
          1400 -
              m.hPad -
              (1400 -
                  tester.getRect(find.byKey(const Key('drive-tree'))).right));
    });

    for (final entry in {
      'light': (Brightness.light, AppColors.light),
      'dark': (Brightness.dark, AppColors.dark),
    }.entries) {
      macTest('${entry.key}: the small text reads at 4.5:1',
          (tester) async {
        final (b, c) = entry.value;
        await desktop(tester, b: b);
        for (final t in [
          'Zebra notes',
          'Inside the folder',
          'New',
          'Fav 0'
        ]) {
          final text = tester.widget<Text>(
              find.descendant(of: row(t), matching: find.text(t)));
          expect(_contrast(text.style!.color!, c.bgBody),
              greaterThanOrEqualTo(4.5),
              reason: t);
        }
        final h = tester.widget<Text>(find.text('Favorites'));
        expect(_contrast(h.style!.color!, c.sectionBand),
            greaterThanOrEqualTo(4.5));
        final more = tester.widget<Text>(find.text('Show all (30)'));
        expect(
            _contrast(more.style!.color!, c.bgBody), greaterThanOrEqualTo(4.5));
      });
    }

    testWidgets('a phone keeps the touch sizes', (tester) async {
      _size(tester, const Size(393, 851));
      await _home(tester, _manyFavorites());
      expect(find.byType(SidebarRow), findsNothing);
      expect(
          tester
              .getSize(find.byKey(const ValueKey('drive-tree-row-did:ad:z')))
              .height,
          greaterThanOrEqualTo(44));
      expect(tester.getSize(_panel('favorites')).height, 48);
    });
  });

  group('colours', () {
    for (final entry in {
      'light': (Brightness.light, AppColors.light),
      'dark': (Brightness.dark, AppColors.dark),
    }.entries) {
      testWidgets('${entry.key}: the header and rows read at 4.5:1',
          (tester) async {
        final (brightness, c) = entry.value;
        await _home(tester, _api(), brightness: brightness);
        final name =
            tester.widget<Text>(find.byKey(const Key('current-drive-name')));
        expect(
            _contrast(name.style!.color!, c.bgBody), greaterThanOrEqualTo(4.5));
        final title = tester.widget<Text>(find.text('Zebra notes'));
        final titleColor = title.style?.color ??
            tester
                .widget<ListTile>(find.ancestor(
                    of: find.text('Zebra notes'),
                    matching: find.byType(ListTile)))
                .titleTextStyle!
                .color!;
        expect(_contrast(titleColor, c.bgBody), greaterThanOrEqualTo(4.5));
        // The quiet parts: the selector chevron and "New".
        final chevron = tester.widget<Icon>(find.byIcon(Icons.unfold_more));
        expect(_contrast(chevron.color!, c.bgBody), greaterThanOrEqualTo(4.5));
        final newText = tester.widget<Text>(find.descendant(
            of: find.byKey(const Key('drive-new-row')),
            matching: find.text('New')));
        expect(_contrast(newText.style!.color!, c.bgBody),
            greaterThanOrEqualTo(4.5));
        // The panel headers keep the bar band.
        expect(c.sectionBand, c.barSurface);
        expect(find.byKey(const Key('drive-tree')), findsOneWidget);
      });
    }
  });
}
