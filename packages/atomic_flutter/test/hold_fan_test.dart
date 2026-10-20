import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late int taps;
  late List<String> picked;

  Widget app(
          {List<HoldFanItem<String>>? items,
          Alignment at = Alignment.bottomCenter}) =>
      MaterialApp(
        theme: ThemeData(extensions: const [AppColors.light]),
        home: Scaffold(
          body: Align(
            alignment: at,
            child: Padding(
              padding: const EdgeInsets.all(8),
              child: HoldFan<String>(
                tooltip: 'New',
                onTap: () => taps++,
                onSelected: picked.add,
                items: items ??
                    const [
                      HoldFanItem('AI chat', 'chat'),
                      HoldFanItem('AI voice', 'voice'),
                      HoldFanItem('Document', 'doc', emoji: '📄'),
                      HoldFanItem('Other', 'other'),
                    ],
                child: const Icon(Icons.add),
              ),
            ),
          ),
        ),
      );

  setUp(() {
    taps = 0;
    picked = [];
  });

  Future<TestGesture> hold(WidgetTester tester) async {
    final gesture =
        await tester.startGesture(tester.getCenter(find.byIcon(Icons.add)));
    await tester.pump(const Duration(milliseconds: 400));
    await tester.pump(const Duration(milliseconds: 200));
    return gesture;
  }

  testWidgets('a tap does the default action and opens no list',
      (tester) async {
    await tester.pumpWidget(app());
    await tester.tap(find.byIcon(Icons.add));
    await tester.pumpAndSettle();
    expect(taps, 1);
    expect(find.text('AI chat'), findsNothing);
    expect(picked, isEmpty);
  });

  testWidgets('holding opens the list above the button, inside the screen',
      (tester) async {
    await tester.pumpWidget(app());
    final gesture = await hold(tester);
    expect(find.text('AI chat'), findsOneWidget);
    expect(find.text('📄 Document'), findsOneWidget);
    final button = tester.getCenter(find.byIcon(Icons.add));
    final screen = tester.view.physicalSize / tester.view.devicePixelRatio;
    var lastY = double.infinity;
    for (final label in ['AI chat', 'AI voice', '📄 Document', 'Other']) {
      final r = tester.getRect(find.text(label));
      expect(r.center.dy, lessThan(button.dy));
      // The first (default) one is nearest the thumb, each next one higher.
      expect(r.center.dy, lessThan(lastY));
      lastY = r.center.dy;
      expect(r.left, greaterThanOrEqualTo(0));
      expect(r.right, lessThanOrEqualTo(screen.width));
    }
    await gesture.up();
    await tester.pumpAndSettle();
    expect(taps, 0);
    // Let go where it was held: the list stays as a menu, until a tap
    // elsewhere closes it.
    expect(find.text('AI chat'), findsOneWidget);
    await tester.tapAt(const Offset(2, 2));
    await tester.pumpAndSettle();
    expect(find.text('AI chat'), findsNothing);
    expect(picked, isEmpty);
    expect(taps, 0);
  });

  testWidgets('after a plain long press a tap on a pill picks it',
      (tester) async {
    await tester.pumpWidget(app());
    final gesture = await hold(tester);
    await gesture.up();
    await tester.pumpAndSettle();
    await tester.tap(find.text('AI voice'));
    await tester.pumpAndSettle();
    expect(picked, ['voice']);
    expect(taps, 0);
    expect(find.text('AI voice'), findsNothing);
  });

  testWidgets('a menu near the top stays out of the status bar',
      (tester) async {
    tester.view.padding = const FakeViewPadding(top: 120);
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(400, 800);
    addTearDown(tester.view.reset);
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: Scaffold(
        appBar: AppBar(title: const Text('Home')),
        body: Align(
          alignment: Alignment.topLeft,
          child: Padding(
            padding: const EdgeInsets.only(top: 100),
            child: HoldFan<String>(
              width: double.infinity,
              size: 40,
              layout: HoldFanLayout.list,
              defaultIndex: null,
              onSelected: picked.add,
              items: const [
                HoldFanItem('One', '1'),
                HoldFanItem('Two', '2'),
                HoldFanItem('Three', '3'),
              ],
              child: const Text('Heading'),
            ),
          ),
        ),
      ),
    ));
    final g = await tester.startGesture(tester.getCenter(find.text('Heading')));
    await tester.pump(const Duration(milliseconds: 400));
    await tester.pump(const Duration(milliseconds: 200));
    for (var i = 0; i < 3; i++) {
      final r = tester.getRect(find.byKey(ValueKey('hold-fan-item-$i')));
      expect(r.top, greaterThanOrEqualTo(120), reason: 'pill $i');
    }
    await g.up();
    await tester.pumpAndSettle();
  });

  testWidgets('a wide target opens its list over the finger', (tester) async {
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: Scaffold(
        body: Align(
          alignment: Alignment.center,
          child: HoldFan<String>(
            width: double.infinity,
            size: 40,
            layout: HoldFanLayout.list,
            defaultIndex: null,
            onSelected: picked.add,
            items: const [HoldFanItem('Hide', 'h')],
            child: const Text('Heading'),
          ),
        ),
      ),
    ));
    final at = tester.getTopLeft(find.text('Heading')) + const Offset(20, 10);
    final g = await tester.startGesture(at);
    await tester.pump(const Duration(milliseconds: 400));
    await tester.pump(const Duration(milliseconds: 200));
    final pill = tester.getRect(find.byKey(const ValueKey('hold-fan-item-0')));
    expect(pill.left, lessThan(at.dx));
    expect(pill.right, greaterThan(at.dx));
    await g.up();
    await tester.pumpAndSettle();
  });

  testWidgets('dragging onto an item and letting go picks it', (tester) async {
    await tester.pumpWidget(app());
    final gesture = await hold(tester);
    await gesture.moveTo(tester.getCenter(find.text('AI chat')));
    await tester.pump();
    await gesture.moveTo(tester.getCenter(find.text('📄 Document')));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    expect(picked, ['doc']);
    expect(taps, 0);
    expect(find.text('📄 Document'), findsNothing);
  });

  testWidgets('letting go elsewhere picks nothing', (tester) async {
    await tester.pumpWidget(app());
    final gesture = await hold(tester);
    await gesture.moveTo(tester.getCenter(find.text('AI chat')));
    await tester.pump();
    // Off the list, to the far side of the screen.
    await gesture.moveTo(const Offset(2, 2));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    expect(picked, isEmpty);
    expect(taps, 0);
    expect(find.text('AI chat'), findsNothing);
  });

  testWidgets('a cancelled touch closes the list without a choice',
      (tester) async {
    await tester.pumpWidget(app());
    final gesture = await hold(tester);
    await gesture.moveTo(tester.getCenter(find.text('AI voice')));
    await tester.pump();
    await gesture.cancel();
    await tester.pumpAndSettle();
    expect(picked, isEmpty);
    expect(find.text('AI voice'), findsNothing);
  });

  testWidgets('near a screen edge the list stays on screen', (tester) async {
    await tester.pumpWidget(app(
      at: Alignment.bottomRight,
      items: const [
        HoldFanItem('All drives', 'all'),
        HoldFanItem('A drive with a rather long name', 'a'),
        HoldFanItem('Work', 'w'),
      ],
    ));
    final gesture = await hold(tester);
    final screen = tester.view.physicalSize / tester.view.devicePixelRatio;
    for (final label in [
      'All drives',
      'A drive with a rather long name',
      'Work'
    ]) {
      final r = tester.getRect(find.text(label));
      expect(r.right, lessThanOrEqualTo(screen.width));
      expect(r.left, greaterThanOrEqualTo(0));
    }
    await gesture.moveTo(tester.getCenter(find.text('Work')));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    expect(picked, ['w']);
  });

  for (final size in [const Size(360, 800), Size(1080 / 3, 2400 / 3)]) {
    testWidgets('no pill label is clipped at ${size.width} px wide',
        (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = size;
      addTearDown(tester.view.reset);
      await tester.pumpWidget(MaterialApp(
        // Material 3 text styles carry letter spacing, which a plain
        // measurement of the label would miss.
        theme:
            ThemeData(useMaterial3: true, extensions: const [AppColors.light]),
        home: Scaffold(
          body: Align(
            alignment: Alignment.bottomCenter,
            child: HoldFan<String>(
              tooltip: 'New',
              onSelected: picked.add,
              items: const [
                HoldFanItem('AI chat', 'chat'),
                HoldFanItem('AI voice', 'voice'),
                HoldFanItem('Document', 'doc'),
                HoldFanItem('Other', 'other'),
              ],
              child: const Icon(Icons.add),
            ),
          ),
        ),
      ));
      final gesture = await hold(tester);
      for (final label in ['AI chat', 'AI voice', 'Document', 'Other']) {
        final text = find.text(label);
        expect(text, findsOneWidget);
        final r = tester.getRect(text);
        expect(r.left, greaterThanOrEqualTo(0));
        expect(r.right, lessThanOrEqualTo(size.width));
        expect(r.top, greaterThanOrEqualTo(0));
        expect(r.bottom, lessThanOrEqualTo(size.height));
        // The label has its natural width inside its pill: nothing is
        // shrunk and nothing is cut off.
        final fitted =
            find.ancestor(of: text, matching: find.byType(FittedBox));
        final box = tester.renderObject<RenderBox>(text);
        expect(
            box.size.width,
            lessThanOrEqualTo(
                tester.renderObject<RenderBox>(fitted).size.width));
        final paragraph = tester.renderObject<RenderParagraph>(text);
        expect(paragraph.didExceedMaxLines, isFalse);
        expect(paragraph.debugNeedsLayout, isFalse);
      }
      await gesture.up();
      await tester.pumpAndSettle();
    });
  }

  testWidgets('the long-press semantic action lists the choices as a menu',
      (tester) async {
    final semantics = tester.ensureSemantics();
    await tester.pumpWidget(app());
    final node = tester.getSemantics(find.byType(HoldFan<String>));
    expect(node.label, 'New');
    expect(
        node.getSemanticsData().hasAction(SemanticsAction.longPress), isTrue);
    expect(
      node.getSemanticsData().customSemanticsActionIds,
      isNotEmpty,
    );
    tester.semantics.longPress(find.semantics.byLabel('New'));
    await tester.pumpAndSettle();
    expect(find.byType(ListTile), findsNWidgets(4));
    await tester.tap(find.widgetWithText(ListTile, 'AI voice'));
    await tester.pumpAndSettle();
    expect(picked, ['voice']);
    expect(taps, 0);
    semantics.dispose();
  });

  test('the layouts are a list and a side list: no fan', () {
    expect(HoldFanLayout.values.map((l) => l.name), ['list', 'side']);
  });

  test('holdFanListLayout stacks the pills vertically, first nearest', () {
    final rects = holdFanListLayout(
      anchor: const Offset(100, 700),
      sizes: const [Size(80, 44), Size(120, 44), Size(100, 44)],
      bounds: const Rect.fromLTWH(0, 0, 400, 800),
    );
    expect(rects, hasLength(3));
    // All as wide as the widest, one column, going up from the button.
    expect(rects.map((r) => r.width).toSet(), {120});
    expect(rects.map((r) => r.left).toSet().length, 1);
    expect(rects[0].bottom, lessThan(700));
    expect(rects[1].bottom, lessThan(rects[0].top));
    expect(rects[2].bottom, lessThan(rects[1].top));
  });

  test('holdFanListLayout goes below when there is no room above', () {
    final rects = holdFanListLayout(
      anchor: const Offset(100, 60),
      sizes: const [Size(80, 44), Size(80, 44), Size(80, 44)],
      bounds: const Rect.fromLTWH(0, 0, 400, 800),
    );
    expect(rects[0].top, greaterThan(60));
    expect(rects[1].top, greaterThan(rects[0].bottom));
    expect(rects[2].top, greaterThan(rects[1].bottom));
  });

  test('holdFanSideLayout stacks the pills right of the button, going down',
      () {
    final rects = holdFanSideLayout(
      anchor: const Offset(40, 200),
      sizes: const [Size(80, 44), Size(120, 44), Size(100, 44)],
      bounds: const Rect.fromLTWH(0, 0, 1280, 800),
    );
    expect(rects.map((r) => r.width).toSet(), {120});
    // Right of the button (its right edge is 24 from the centre).
    expect(rects.first.left, greaterThan(64));
    expect(rects.first.center.dy, 200);
    expect(rects[1].top, greaterThan(rects[0].bottom));
    expect(rects[2].top, greaterThan(rects[1].bottom));
  });

  test('holdFanSideLayout moves up when it would pass the bottom', () {
    final rects = holdFanSideLayout(
      anchor: const Offset(40, 380),
      sizes: const [Size(80, 44), Size(80, 44), Size(80, 44)],
      bounds: const Rect.fromLTWH(0, 0, 900, 400),
    );
    expect(rects.last.bottom, lessThanOrEqualTo(400));
    expect(rects.first.top, greaterThanOrEqualTo(0));
  });

  testWidgets('a list opens at the short hold and draws no line',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: Scaffold(
        body: Align(
          alignment: Alignment.bottomCenter,
          child: HoldFan<String>(
            tooltip: 'Pick',
            layout: HoldFanLayout.list,
            onSelected: picked.add,
            items: const [HoldFanItem('One', '1'), HoldFanItem('Two', '2')],
            child: const Icon(Icons.search),
          ),
        ),
      ),
    ));
    final g =
        await tester.startGesture(tester.getCenter(find.byIcon(Icons.search)));
    await tester.pump(const Duration(milliseconds: 250));
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('One'), findsOneWidget);
    final one = tester.getRect(find.byKey(const ValueKey('hold-fan-item-0')));
    final two = tester.getRect(find.byKey(const ValueKey('hold-fan-item-1')));
    expect(two.bottom, lessThan(one.top));
    expect((one.center.dx - two.center.dx).abs(), lessThan(1));
    // The finger moves; still no connector drawn.
    await g.moveTo(const Offset(5, 5));
    await tester.pump();
    final overlay = find.descendant(
        of: find.byType(Overlay).last, matching: find.byType(CustomPaint));
    for (final w in tester.widgetList<CustomPaint>(overlay)) {
      expect(w.painter?.runtimeType.toString(), isNot('_LinePainter'));
    }
    await g.up();
    await tester.pumpAndSettle();
  });
  group('tapOpensMenu', () {
    const entries = [
      HoldFanItem('AI chat', 'chat', icon: Icons.chat_bubble_outline),
      HoldFanItem('AI voice', 'voice', icon: Icons.mic_none),
      HoldFanItem('Document', 'doc', icon: Icons.description_outlined),
      HoldFanItem('Other…', 'other', icon: Icons.add_box_outlined),
    ];

    Widget menuApp({
      HoldFanLayout layout = HoldFanLayout.list,
      Alignment at = Alignment.bottomCenter,
    }) =>
        MaterialApp(
          theme: ThemeData(extensions: const [AppColors.light]),
          home: Scaffold(
            body: Align(
              alignment: at,
              child: HoldFan<String>(
                tooltip: 'New',
                tapOpensMenu: true,
                layout: layout,
                holdDuration: const Duration(milliseconds: 250),
                onTap: () => taps++,
                onSelected: picked.add,
                items: entries,
                child: const Icon(Icons.add),
              ),
            ),
          ),
        );

    List<Rect> rows(WidgetTester tester) => [
          for (var i = 0; i < 4; i++)
            tester.getRect(find.byKey(ValueKey('hold-fan-item-$i'))),
        ];

    void expectOnScreen(WidgetTester tester, Size size) {
      final card = tester.getRect(find.byKey(const ValueKey('hold-fan-card')));
      expect(card.left, greaterThanOrEqualTo(0));
      expect(card.top, greaterThanOrEqualTo(0));
      expect(card.right, lessThanOrEqualTo(size.width));
      expect(card.bottom, lessThanOrEqualTo(size.height));
      for (final r in rows(tester)) {
        expect(r.height, greaterThanOrEqualTo(48));
        expect(
            card.contains(r.topLeft) && card.contains(r.bottomRight), isTrue);
      }
    }

    testWidgets('a tap opens the list at once, in reading order, above',
        (tester) async {
      await tester.pumpWidget(menuApp());
      final button = tester.getCenter(find.byIcon(Icons.add));
      await tester.tap(find.byIcon(Icons.add));
      // The same frame: no wait for an animation to start.
      await tester.pump();
      for (final label in ['AI chat', 'AI voice', 'Document', 'Other…']) {
        expect(find.text(label), findsOneWidget);
      }
      expect(taps, 0);
      final r = rows(tester);
      // AI chat first, at the top; one column, above the button.
      for (var i = 1; i < r.length; i++) {
        expect(r[i].top, greaterThanOrEqualTo(r[i - 1].bottom - 0.01));
      }
      expect(r.last.bottom, lessThan(button.dy));
      expect(find.byIcon(Icons.mic_none), findsOneWidget);
      final card =
          tester.widget<Material>(find.byKey(const ValueKey('hold-fan-card')));
      expect(card.color, AppColors.light.barSurface);
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 120));
      // Fully in within 120 ms: rows are their full size.
      expect(rows(tester).first.height, greaterThanOrEqualTo(48));
    });

    testWidgets('tapping a row picks it and closes the list', (tester) async {
      await tester.pumpWidget(menuApp());
      await tester.tap(find.byIcon(Icons.add));
      await tester.pump();
      await tester.tap(find.text('Document'));
      await tester.pumpAndSettle();
      expect(picked, ['doc']);
      expect(find.text('Document'), findsNothing);
    });

    testWidgets(
        'a tap outside and dismissOpenMenu (back) close it without a choice',
        (tester) async {
      await tester.pumpWidget(menuApp());
      await tester.tap(find.byIcon(Icons.add));
      await tester.pump();
      await tester.tapAt(const Offset(3, 3));
      await tester.pumpAndSettle();
      expect(find.text('AI chat'), findsNothing);
      await tester.tap(find.byIcon(Icons.add));
      await tester.pump();
      expect(find.text('AI chat'), findsOneWidget);
      expect(HoldFan.dismissOpenMenu(), isTrue);
      await tester.pumpAndSettle();
      expect(find.text('AI chat'), findsNothing);
      expect(picked, isEmpty);
    });

    testWidgets(
        'holding opens the same list and dragging picks the item '
        'under the finger', (tester) async {
      await tester.pumpWidget(menuApp());
      final g =
          await tester.startGesture(tester.getCenter(find.byIcon(Icons.add)));
      await tester.pump(const Duration(milliseconds: 150));
      expect(find.text('AI chat'), findsNothing);
      await tester.pump(const Duration(milliseconds: 150));
      expect(find.text('AI chat'), findsOneWidget);
      await g.moveTo(tester.getCenter(find.text('AI chat')));
      await tester.pump();
      await g.moveTo(tester.getCenter(find.text('AI voice')));
      await tester.pump();
      await g.up();
      await tester.pumpAndSettle();
      expect(picked, ['voice']);
      expect(taps, 0);
      expect(find.text('AI voice'), findsNothing);
    });

    testWidgets('holding and letting go elsewhere dismisses', (tester) async {
      await tester.pumpWidget(menuApp());
      final g =
          await tester.startGesture(tester.getCenter(find.byIcon(Icons.add)));
      await tester.pump(const Duration(milliseconds: 400));
      await g.moveTo(tester.getCenter(find.text('Document')));
      await tester.pump();
      await g.moveTo(const Offset(3, 3));
      await tester.pump();
      await g.up();
      await tester.pumpAndSettle();
      expect(picked, isEmpty);
      expect(find.text('Document'), findsNothing);
    });

    testWidgets('a tap before the hold time is a tap, not a hold',
        (tester) async {
      await tester.pumpWidget(menuApp());
      final g =
          await tester.startGesture(tester.getCenter(find.byIcon(Icons.add)));
      await tester.pump(const Duration(milliseconds: 100));
      await g.up();
      await tester.pump();
      expect(find.text('AI chat'), findsOneWidget);
      // Opened by the tap: it stays until closed.
      await tester.pump(const Duration(milliseconds: 600));
      expect(find.text('AI chat'), findsOneWidget);
    });

    for (final size in [const Size(360, 800), const Size(1280, 800)]) {
      testWidgets('the list stays on screen at ${size.width.toInt()}x800',
          (tester) async {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = size;
        addTearDown(tester.view.reset);
        for (final at in [Alignment.bottomRight, Alignment.bottomLeft]) {
          await tester.pumpWidget(menuApp(at: at));
          await tester.tap(find.byIcon(Icons.add));
          await tester.pump();
          await tester.pump(const Duration(milliseconds: 120));
          expectOnScreen(tester, size);
          await tester.tapAt(const Offset(3, 3));
          await tester.pumpAndSettle();
        }
      });
    }

    testWidgets('the side list opens right of a rail button, going down',
        (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(1280, 800);
      addTearDown(tester.view.reset);
      await tester.pumpWidget(
          menuApp(layout: HoldFanLayout.side, at: Alignment.centerLeft));
      final button = tester.getRect(find.byIcon(Icons.add));
      await tester.tap(find.byIcon(Icons.add));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 120));
      final r = rows(tester);
      expect(r.first.left, greaterThan(button.right));
      for (var i = 1; i < r.length; i++) {
        expect(r[i].top, greaterThanOrEqualTo(r[i - 1].bottom - 0.01));
      }
      expectOnScreen(tester, const Size(1280, 800));
      // Hold-drag works the same on the side.
      await tester.tapAt(const Offset(1270, 3));
      await tester.pumpAndSettle();
      final g =
          await tester.startGesture(tester.getCenter(find.byIcon(Icons.add)));
      await tester.pump(const Duration(milliseconds: 400));
      await g.moveTo(tester.getCenter(find.text('Other…')));
      await tester.pump();
      await g.up();
      await tester.pumpAndSettle();
      expect(picked, ['other']);
    });
  });
}
