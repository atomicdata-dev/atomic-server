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

  testWidgets('a tap does the default action and opens no fan', (tester) async {
    await tester.pumpWidget(app());
    await tester.tap(find.byIcon(Icons.add));
    await tester.pumpAndSettle();
    expect(taps, 1);
    expect(find.text('AI chat'), findsNothing);
    expect(picked, isEmpty);
  });

  testWidgets('holding opens the fan above the button, inside the screen',
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
    expect(find.text('AI chat'), findsNothing);
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
    // Off the fan, to the far side of the screen.
    await gesture.moveTo(const Offset(2, 2));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();
    expect(picked, isEmpty);
    expect(taps, 0);
    expect(find.text('AI chat'), findsNothing);
  });

  testWidgets('a cancelled touch closes the fan without a choice',
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

  testWidgets('near a screen edge the fan stays on screen', (tester) async {
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

  test('the layout keeps pills apart and inside the bounds', () {
    final rects = holdFanLayout(
      anchor: const Offset(40, 780),
      sizes: List.filled(6, const Size(140, 44)),
      bounds: const Rect.fromLTWH(8, 8, 384, 784),
    );
    for (var i = 0; i < rects.length; i++) {
      expect(rects[i].left, greaterThanOrEqualTo(8));
      expect(rects[i].right, lessThanOrEqualTo(392));
      for (var j = i + 1; j < rects.length; j++) {
        expect(rects[i].overlaps(rects[j]), isFalse);
      }
    }
    expect(holdFanHit(rects, rects[2].center), 2);
    expect(holdFanHit(rects, const Offset(40, 780)), isNull);
  });
}
