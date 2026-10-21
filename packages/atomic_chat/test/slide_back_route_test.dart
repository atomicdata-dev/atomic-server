import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> _open(WidgetTester tester) async {
  await tester.pumpWidget(MaterialApp(
    home: Builder(
      builder: (context) => Scaffold(
        body: Center(
          child: TextButton(
            onPressed: () => Navigator.of(context).push(SlideBackRoute<void>(
              builder: (_) => const Scaffold(body: Center(child: Text('chat'))),
            )),
            child: const Text('overview'),
          ),
        ),
      ),
    ),
  ));
  await tester.tap(find.text('overview'));
  await tester.pumpAndSettle();
}

void main() {
  _surfaceTests();
  testWidgets('dragging the page to the right far enough goes back',
      (tester) async {
    await _open(tester);
    expect(find.text('chat'), findsOneWidget);

    await tester.drag(find.text('chat'), const Offset(500, 0));
    await tester.pumpAndSettle();

    expect(find.text('chat'), findsNothing);
    expect(find.text('overview'), findsOneWidget);
  });

  testWidgets('a short drag springs back and stays', (tester) async {
    await _open(tester);
    await tester.drag(find.text('chat'), const Offset(60, 0));
    await tester.pumpAndSettle();
    expect(find.text('chat'), findsOneWidget);
  });

  testWidgets('the overview is there on the left while the page moves',
      (tester) async {
    await _open(tester);
    final gesture =
        await tester.startGesture(tester.getCenter(find.text('chat')));
    await gesture.moveBy(const Offset(200, 0));
    await tester.pump();
    expect(find.text('overview', skipOffstage: false), findsOneWidget);
    expect(tester.getTopLeft(find.text('chat')).dx, greaterThan(300));
    await gesture.up();
    await tester.pumpAndSettle();
  });

  testWidgets('back runs the same slide', (tester) async {
    await _open(tester);
    final navigator = tester.state<NavigatorState>(find.byType(Navigator));
    navigator.pop();
    await tester.pump(const Duration(milliseconds: 100));
    // Mid-slide: still on screen, moving out.
    expect(find.text('chat'), findsOneWidget);
    await tester.pumpAndSettle();
    expect(find.text('chat'), findsNothing);
  });
}

void _surfaceTests() {
  testWidgets('the page has an opaque surface under it, in the slide too',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData.dark(),
      home: Builder(
        builder: (context) => TextButton(
          onPressed: () => Navigator.of(context).push(SlideBackRoute<void>(
            // A page that paints nothing of its own, as a web view that has
            // not painted yet.
            builder: (_) => const SizedBox.expand(key: Key('empty')),
          )),
          child: const Text('overview'),
        ),
      ),
    ));
    await tester.tap(find.text('overview'));
    await tester.pump();
    for (var i = 0; i < 3; i++) {
      await tester.pump(const Duration(milliseconds: 40));
      final box = tester.widget<ColoredBox>(find
          .ancestor(
              of: find.byKey(const Key('empty')),
              matching: find.byType(ColoredBox))
          .first);
      expect(box.color.a, 1.0, reason: 'opaque at step $i');
      expect(box.color, isNot(const Color(0xFF000000)));
    }
    await tester.pumpAndSettle();
    final navigator = tester.state<NavigatorState>(find.byType(Navigator));
    navigator.pop();
    await tester.pump(const Duration(milliseconds: 40));
    final box = tester.widget<ColoredBox>(find
        .ancestor(
            of: find.byKey(const Key('empty')),
            matching: find.byType(ColoredBox))
        .first);
    expect(box.color.a, 1.0);
    await tester.pumpAndSettle();
  });
}
