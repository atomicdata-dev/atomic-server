import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _app(int items, ScrollController c) => MaterialApp(
      scrollBehavior: const AppScrollBehavior(),
      home: Scaffold(
        body: ListView.builder(
          controller: c,
          itemCount: items,
          itemBuilder: (_, i) => SizedBox(height: 100, child: Text('$i')),
        ),
      ),
    );

void main() {
  test('fling and drag feel are stock iOS; only overscroll differs', () {
    const a = AppScrollPhysics();
    const ios = BouncingScrollPhysics();
    expect(a.decelerationRate, ScrollDecelerationRate.normal);
    expect(a.minFlingVelocity, ios.minFlingVelocity);
    expect(a.maxFlingVelocity, ios.maxFlingVelocity);
    expect(a.dragStartDistanceMotionThreshold,
        ios.dragStartDistanceMotionThreshold);
    for (final v in [100.0, 800.0, 3000.0, 9000.0]) {
      expect(a.carriedMomentum(v), ios.carriedMomentum(v));
    }
    final m = FixedScrollMetrics(
        minScrollExtent: 0,
        maxScrollExtent: 5000,
        pixels: 1000,
        viewportDimension: 800,
        axisDirection: AxisDirection.down,
        devicePixelRatio: 3);
    for (final v in [1500.0, -900.0]) {
      final x = a.createBallisticSimulation(m, v)!;
      final y = ios.createBallisticSimulation(m, v)!;
      for (final t in [0.1, 0.5, 1.0, 2.0]) {
        expect(x.x(t), closeTo(y.x(t), 1e-6));
      }
    }
  });

  test('friction is monotonic and milder than iOS', () {
    const a = AppScrollPhysics();
    const ios = BouncingScrollPhysics();
    var prev = double.infinity;
    for (var f = 0.0; f < 1.0; f += 0.1) {
      final v = a.frictionFactor(f);
      expect(v, lessThanOrEqualTo(prev));
      expect(v, lessThan(ios.frictionFactor(f)));
      prev = v;
    }
  });

  testWidgets('drag past the end overscrolls gently and settles back',
      (tester) async {
    final c = ScrollController();
    await tester.pumpWidget(_app(20, c));
    final view = c.position.viewportDimension;
    c.jumpTo(c.position.maxScrollExtent);
    await tester.pump();
    final max = c.position.maxScrollExtent;
    final g = await tester.startGesture(const Offset(200, 300));
    for (var i = 0; i < 30; i++) {
      await g.moveBy(const Offset(0, -10));
    }
    await tester.pump();
    final over = c.position.pixels - max;
    expect(over, greaterThanOrEqualTo(16));
    expect(over, lessThanOrEqualTo(0.3 * view));
    await g.up();
    var peak = over;
    for (var i = 0; i < 100; i++) {
      await tester.pump(const Duration(milliseconds: 16));
      expect(c.position.pixels, greaterThanOrEqualTo(max - 0.01));
      peak = peak > c.position.pixels - max ? peak : c.position.pixels - max;
    }
    await tester.pumpAndSettle();
    expect(c.position.pixels, max);
  });

  testWidgets('short content still bounces', (tester) async {
    final c = ScrollController();
    await tester.pumpWidget(_app(2, c));
    final g = await tester.startGesture(const Offset(200, 300));
    for (var i = 0; i < 30; i++) {
      await g.moveBy(const Offset(0, 10));
    }
    await tester.pump();
    expect(c.position.pixels, lessThan(-16));
    await g.up();
    await tester.pumpAndSettle();
    expect(c.position.pixels, 0);
  });

  testWidgets('haptic once per drag at the end, not for flings',
      (tester) async {
    var ticks = 0;
    tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'HapticFeedback.vibrate') ticks++;
      return null;
    });
    final c = ScrollController();
    await tester.pumpWidget(_app(20, c));
    c.jumpTo(c.position.maxScrollExtent);
    await tester.pump();
    final g = await tester.startGesture(const Offset(200, 300));
    for (var i = 0; i < 20; i++) {
      await g.moveBy(const Offset(0, -10));
    }
    await tester.pump();
    expect(ticks, 1);
    await g.up();
    await tester.pumpAndSettle();

    // A fling that runs into the end: no tick.
    ticks = 0;
    c.jumpTo(c.position.maxScrollExtent - 300);
    await tester.pump();
    await tester.fling(find.byType(ListView), const Offset(0, -400), 3000);
    await tester.pumpAndSettle();
    expect(ticks, 0);
    tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null);
  });
}
