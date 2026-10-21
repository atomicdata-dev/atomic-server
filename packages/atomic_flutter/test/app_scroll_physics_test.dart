import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/foundation.dart' show debugDefaultTargetPlatformOverride;
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
  test('physics is clamping based and keeps the always-scrollable parent', () {
    const a = AppScrollPhysics();
    expect(a, isA<ClampingScrollPhysics>());
    expect(a, isNot(isA<BouncingScrollPhysics>()));
    expect(a.parent, isA<RangeMaintainingScrollPhysics>());
    expect(a.applyTo(null), isA<AppScrollPhysics>());
    final m = FixedScrollMetrics(
        minScrollExtent: 0,
        maxScrollExtent: 5000,
        pixels: 0,
        viewportDimension: 800,
        axisDirection: AxisDirection.down,
        devicePixelRatio: 3);
    // Dragging past the edge is refused entirely.
    expect(a.applyBoundaryConditions(m, -20), -20);
    expect(a.shouldAcceptUserOffset(m), isTrue);
  });

  for (final platform in [
    TargetPlatform.iOS,
    TargetPlatform.macOS,
    TargetPlatform.android,
    TargetPlatform.linux,
    TargetPlatform.windows,
  ]) {
    testWidgets('the stretch indicator is used on $platform', (tester) async {
      debugDefaultTargetPlatformOverride = platform;
      try {
        await tester.pumpWidget(_app(20, ScrollController()));
        expect(find.byType(StretchingOverscrollIndicator), findsOneWidget);
        expect(find.byType(GlowingOverscrollIndicator), findsNothing);
      } finally {
        debugDefaultTargetPlatformOverride = null;
      }
    });
  }

  testWidgets('drag past the top stretches the content, it does not move',
      (tester) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    try {
      final c = ScrollController();
      await tester.pumpWidget(_app(20, c));
      final top = tester.getTopLeft(find.text('0')).dy;
      final g = await tester.startGesture(const Offset(200, 300));
      for (var i = 0; i < 30; i++) {
        await g.moveBy(const Offset(0, 10));
        expect(c.position.pixels, 0);
      }
      await tester.pump();
      // The first item is still at the top edge...
      expect(c.position.pixels, 0);
      expect(tester.getTopLeft(find.text('0')).dy, closeTo(top, 0.01));
      // ...and the stretch is a scale transform inside the indicator.
      final stretch = find.descendant(
          of: find.byType(StretchingOverscrollIndicator),
          matching: find.byType(Transform));
      final scales = tester
          .widgetList<Transform>(stretch)
          .map((t) => t.transform.getMaxScaleOnAxis());
      expect(scales.any((s) => s > 1), isTrue);
      await g.up();
      await tester.pumpAndSettle();
      expect(c.position.pixels, 0);
      expect(
          tester
              .widgetList<Transform>(stretch)
              .every((t) => t.transform.getMaxScaleOnAxis() == 1),
          isTrue);
    } finally {
      debugDefaultTargetPlatformOverride = null;
    }
  });

  testWidgets('drag past the end never exceeds the extent', (tester) async {
    final c = ScrollController();
    await tester.pumpWidget(_app(20, c));
    c.jumpTo(c.position.maxScrollExtent);
    await tester.pump();
    final max = c.position.maxScrollExtent;
    final g = await tester.startGesture(const Offset(200, 300));
    for (var i = 0; i < 30; i++) {
      await g.moveBy(const Offset(0, -10));
      expect(c.position.pixels, max);
    }
    await g.up();
    await tester.pumpAndSettle();
    expect(c.position.pixels, max);
  });

  testWidgets('short content can still be pulled (stretches)', (tester) async {
    final c = ScrollController();
    await tester.pumpWidget(_app(2, c));
    final g = await tester.startGesture(const Offset(200, 300));
    for (var i = 0; i < 30; i++) {
      await g.moveBy(const Offset(0, 10));
    }
    await tester.pump();
    expect(c.position.pixels, 0);
    final scales = tester
        .widgetList<Transform>(find.descendant(
            of: find.byType(StretchingOverscrollIndicator),
            matching: find.byType(Transform)))
        .map((t) => t.transform.getMaxScaleOnAxis());
    expect(scales.any((s) => s > 1), isTrue);
    await g.up();
    await tester.pumpAndSettle();
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
