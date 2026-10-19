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

  testWidgets('streamed text fades in piece by piece', (tester) async {
    var clock = DateTime(2026, 10, 19, 12);
    var chunks = <(String, DateTime)>[('Hel', clock)];
    late StateSetter set;
    await tester.pumpWidget(MaterialApp(
      home: StatefulBuilder(builder: (context, setState) {
        set = setState;
        return Scaffold(
          body: FadingText(
            chunks: chunks,
            style: const TextStyle(color: Colors.white),
            now: () => clock,
          ),
        );
      }),
    ));
    double alpha() {
      final text = tester.widget<Text>(find.byType(Text));
      final span = (text.textSpan! as TextSpan).children!.last as TextSpan;
      return span.style!.color!.a;
    }

    clock = clock.add(const Duration(milliseconds: 50));
    await tester.pump(const Duration(milliseconds: 16));
    expect(alpha(), lessThan(0.5));

    // A new piece starts from nothing while the old one carries on.
    set(() => chunks = [...chunks, ('lo', clock)]);
    await tester.pump();
    expect(alpha(), lessThan(0.1));

    clock = clock.add(const Duration(milliseconds: 500));
    await tester.pump(const Duration(milliseconds: 16));
    expect(alpha(), 1.0);
  });
}
