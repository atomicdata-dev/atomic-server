import 'dart:async';
import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// The warm page lives in the shell's tree before it is taken (attached and
/// laid out at the size a resource page gives it), and moves into the page
/// that takes it without being made again.

const _phone = Size(393, 851);
const _landscape = Size(1280, 800);

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
      emoji: null, picture: null,
    );

class _Api extends FakeApi {
  _Api()
      : super(favoriteList: [
          _r('did:ad:plans', 'Plans'),
          _r('did:ad:notes', 'Notes'),
        ]);

  @override
  Future<String> embedCall(String method, String argsJson) async => '[]';
}

/// Stands in for the web view: a widget with state (the platform view's),
/// counting how often it is made and where it is laid out.
class _Probe extends StatefulWidget {
  final _AttachedPage page;
  const _Probe(this.page);
  @override
  State<_Probe> createState() => _ProbeState();
}

class _ProbeState extends State<_Probe> {
  @override
  void initState() {
    super.initState();
    widget.page.made++;
  }

  @override
  void dispose() {
    widget.page.gone++;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => LayoutBuilder(builder: (context, box) {
        widget.page.sizes.add(box.biggest);
        return Text('web view ${widget.page.n}');
      });
}

class _AttachedPage implements WarmPage {
  _AttachedPage(this.n, this.send);
  final int n;
  final void Function(String message) send;
  final _key = GlobalKey();
  final scripts = <String>[];
  final _ready = Completer<void>();
  bool released = false;
  int made = 0;
  int gone = 0;
  final sizes = <Size>[];
  void Function(String)? handler;

  void becomeReady() => _ready.complete();

  /// The page says it shows the resource it was told to open.
  void reveal() => handler!(jsonEncode({'method': 'revealed', 'ms': 5}));

  @override
  bool get isReady => _ready.isCompleted && !released;
  @override
  Future<void> get whenReady => _ready.future;
  @override
  set onMessage(void Function(String)? h) => handler = h;
  @override
  set onLoaded(VoidCallback? h) {}
  @override
  Future<void> runJavaScript(String script) async => scripts.add(script);
  @override
  Future<Object> runJavaScriptReturningResult(String script) async => false;
  @override
  Widget build() => KeyedSubtree(key: _key, child: _Probe(this));
  @override
  void release() => released = true;
}

void main() {
  final pages = <_AttachedPage>[];
  late WarmResourceWebView pool;

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    pages.clear();
    ResourceView.releaseDelay = Duration.zero;
    ResourceView.flushTimeout = const Duration(milliseconds: 1);
  });
  tearDown(() {
    ResourceView.releaseDelay = const Duration(seconds: 3);
    ResourceView.flushTimeout = const Duration(seconds: 2);
  });

  /// The shell with a pool whose pages are ready as soon as they are made.
  Future<_Api> start(WidgetTester tester, {Size size = _phone}) async {
    _size(tester, size);
    final api = _Api();
    await tester.pumpWidget(app(AppShell(
      api: api,
      drive: 'did:ad:drive',
      warmPool: (api) => pool = WarmResourceWebView(
        api: api,
        rewarmDelay: Duration.zero,
        builder: (onMessage) async {
          final p = _AttachedPage(pages.length, onMessage)..becomeReady();
          pages.add(p);
          return p;
        },
      ),
      home: ChatsScreen(drive: 'did:ad:drive', api: api),
    )));
    await tester.pumpAndSettle();
    return api;
  }

  Future<void> done(WidgetTester tester) async {
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 1));
  }

  Finder skeleton() => find.byKey(const Key('resource-skeleton'));

  bool painted(WidgetTester tester, Finder finder) {
    for (final o in tester.widgetList<Opacity>(
        find.ancestor(of: finder, matching: find.byType(Opacity)))) {
      if (o.opacity == 0) return false;
    }
    return true;
  }

  testWidgets('a ready spare is in the tree, laid out, hidden and untouchable',
      (tester) async {
    await start(tester);
    final spare = pages.single;
    expect(spare.made, 1);
    expect(find.text('web view 0'), findsOneWidget);
    expect(painted(tester, find.text('web view 0')), isFalse);
    // The size a resource page gives its web view: the pages' box under the
    // status bar.
    final navigator = tester.getRect(find
        .descendant(of: find.byType(AppShell), matching: find.byType(Navigator))
        .first);
    expect(spare.sizes.last, Size(navigator.width, navigator.height));
    // Taps go through it to the home.
    expect(
        tester
            .widgetList<IgnorePointer>(find.ancestor(
                of: find.text('web view 0'),
                matching: find.byType(IgnorePointer)))
            .any((w) => w.ignoring),
        isTrue);
    await done(tester);
  });

  testWidgets(
      'opening takes the attached page as it is, and covers it until '
      'the page shows the resource', (tester) async {
    await start(tester);
    final spare = pages.single;
    final before = spare.sizes.last;

    await tester.tap(find.text('Plans'));
    await tester.pump();
    // The first frame of the page: the placeholder with the row's title.
    // The web view is still in the slot (attached), and only in it.
    expect(skeleton(), findsOneWidget);
    expect(find.descendant(of: skeleton(), matching: find.text('Plans')),
        findsOneWidget);
    expect(find.text('web view 0'), findsOneWidget);
    // The next frame it is under the placeholder: the same one (not made
    // again), at the same size.
    await tester.pump();
    expect(
        find.descendant(
            of: find.byType(ResourceView), matching: find.text('web view 0')),
        findsOneWidget);
    expect(spare.made, 1);
    expect(spare.gone, 0);
    expect(spare.sizes.last, before);
    expect(spare.scripts.any((s) => s.contains('"did:ad:plans"')), isTrue);

    await tester.pumpAndSettle();
    expect(skeleton(), findsOneWidget, reason: 'not shown yet');
    spare.reveal();
    await tester.pump();
    await tester.pumpAndSettle();
    expect(skeleton(), findsNothing);
    expect(painted(tester, find.text('web view 0')), isTrue);
    expect(spare.made, 1);

    // The next spare is in the slot, and only it.
    expect(pages, hasLength(2));
    expect(find.text('web view 1'), findsOneWidget);
    expect(painted(tester, find.text('web view 1')), isFalse);
    await done(tester);
  });

  testWidgets(
      'a warm page opens the row with `open` (history reset), and back with '
      'nothing to go back to inside leaves to the home', (tester) async {
    await start(tester);
    final spare = pages.single;

    await tester.tap(find.text('Plans'));
    await tester.pumpAndSettle();
    // `open` (replacing the warm-up's entries), never a pushing `show` alone.
    final script =
        spare.scripts.singleWhere((s) => s.contains('e.open||e.show'));
    expect(script, contains('"did:ad:plans"'));
    expect(find.byType(ResourceView), findsOneWidget);

    // The page has no earlier entry (`back()` answers false): back leaves.
    await tester.binding.handlePopRoute();
    await tester.pumpAndSettle();
    expect(find.byType(ResourceView), findsNothing);
    expect(find.text('Plans'), findsWidgets);
    expect(find.byType(ChatsScreen), findsOneWidget);
    await done(tester);
  });

  testWidgets('a page that never says it shows the resource is shown anyway',
      (tester) async {
    await start(tester);
    await tester.tap(find.text('Plans'));
    await tester.pumpAndSettle();
    expect(skeleton(), findsOneWidget);
    await tester.pump(ResourceView.revealWarm);
    await tester.pumpAndSettle();
    expect(skeleton(), findsNothing);
    await done(tester);
  });

  testWidgets('closing releases the taken page; the spare stays attached',
      (tester) async {
    await start(tester);
    await tester.tap(find.text('Plans'));
    await tester.pumpAndSettle();
    final taken = pages.first;
    final next = pages.last;
    expect(next, isNot(same(taken)));

    await tester.binding.handlePopRoute();
    await tester.pumpAndSettle();
    await tester.pump(const Duration(milliseconds: 10));
    expect(find.byType(ResourceView), findsNothing);
    expect(taken.released, isTrue);
    expect(taken.gone, 1);
    expect(next.released, isFalse);
    expect(next.gone, 0);
    expect(find.text('web view 1'), findsOneWidget);

    // Opening again takes the attached one.
    await tester.ensureVisible(find.text('Notes'));
    await tester.tap(find.text('Notes'));
    await tester.pump();
    expect(next.made, 1);
    expect(next.handler, isNotNull);
    await tester.pumpAndSettle();
    await done(tester);
  });

  testWidgets('memory pressure drops the attached spare', (tester) async {
    await start(tester);
    final spare = pages.single;
    tester.binding.handleMemoryPressure();
    await tester.pump();
    expect(spare.released, isTrue);
    expect(spare.gone, 1);
    expect(find.text('web view 0'), findsNothing);
    await done(tester);
  });

  testWidgets('rotating keeps the spare and the open page, resized',
      (tester) async {
    await start(tester);
    final spare = pages.single;
    // The spare moves with the layout: from under the phone's pages to under
    // the detail pane, not made again.
    _size(tester, _landscape);
    await tester.pumpAndSettle();
    expect(pool.attached, same(spare));
    expect(spare.made, 1);
    expect(spare.gone, 0);
    final detail = tester.getRect(find
        .descendant(of: find.byType(AppShell), matching: find.byType(Navigator))
        .first);
    expect(spare.sizes.last, detail.size);

    // Opened in the detail pane, then back to a phone.
    await tester.tap(find.text('Plans'));
    await tester.pumpAndSettle();
    expect(spare.handler, isNotNull);
    expect(tester.getSize(find.text('web view 0')).width,
        lessThanOrEqualTo(detail.width));
    _size(tester, _phone);
    await tester.pumpAndSettle();
    expect(spare.made, 1);
    expect(spare.gone, 0);
    expect(spare.sizes.last.width, _phone.width);
    expect(find.text('web view 0'), findsOneWidget);
    // And the next spare came along too.
    expect(pages, hasLength(2));
    expect(pages.last.made, 1);
    expect(pages.last.gone, 0);
    await done(tester);
  });
}
