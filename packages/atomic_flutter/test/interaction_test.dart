import 'dart:io';

import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

/// The cursor the mouse shows after hovering [target].
Future<MouseCursor> cursorOver(WidgetTester tester, Finder target) async {
  final mouse =
      await tester.createGesture(kind: PointerDeviceKind.mouse, pointer: 1);
  await mouse.addPointer(location: const Offset(1, 1));
  await tester.pump();
  await mouse.moveTo(tester.getCenter(target));
  await tester.pump();
  final cursor = tester.binding.mouseTracker.debugDeviceActiveCursor(1)!;
  await mouse.removePointer();
  await tester.pump();
  return cursor;
}

void main() {
  ThemeData theme() => withCalmInteraction(
        ThemeData(extensions: const [AppColors.light]),
        ink: AppColors.light.textPrimary,
      );

  test('the theme has no ink splash and a flat pressed tint', () {
    final t = theme();
    expect(t.splashFactory, same(NoSplash.splashFactory));
    expect(t.splashColor, Colors.transparent);
    expect(t.highlightColor.a, greaterThan(0));
    for (final s in [
      t.filledButtonTheme.style!,
      t.outlinedButtonTheme.style!,
      t.textButtonTheme.style!,
      t.elevatedButtonTheme.style!,
      t.iconButtonTheme.style!,
      t.segmentedButtonTheme.style!,
      t.menuButtonTheme.style!,
    ]) {
      expect(s.splashFactory, same(NoSplash.splashFactory));
      expect(s.mouseCursor!.resolve({}), SystemMouseCursors.click);
      expect(s.mouseCursor!.resolve({WidgetState.disabled}),
          SystemMouseCursors.basic);
      expect(s.overlayColor!.resolve({}), Colors.transparent);
      expect(s.overlayColor!.resolve({WidgetState.pressed})!.a, greaterThan(0));
      expect(s.overlayColor!.resolve({WidgetState.hovered})!.a, greaterThan(0));
    }
  });

  testWidgets('buttons point on hover, disabled ones do not', (tester) async {
    await tester.pumpWidget(MaterialApp(
      theme: theme(),
      home: Scaffold(
        body: Column(children: [
          FilledButton(
              key: const Key('on'), onPressed: () {}, child: const Text('a')),
          const FilledButton(
              key: Key('off'), onPressed: null, child: Text('b')),
        ]),
      ),
    ));
    expect(await cursorOver(tester, find.byKey(const Key('on'))),
        SystemMouseCursors.click);
    expect(await cursorOver(tester, find.byKey(const Key('off'))),
        SystemMouseCursors.basic);
  });

  testWidgets('ClickCursor points only when enabled', (tester) async {
    await tester.pumpWidget(const MaterialApp(
      home: Column(children: [
        ClickCursor(
            enabled: true,
            child: SizedBox(key: Key('on'), width: 80, height: 40)),
        ClickCursor(
            enabled: false,
            child: SizedBox(key: Key('off'), width: 80, height: 40)),
      ]),
    ));
    expect(await cursorOver(tester, find.byKey(const Key('on'))),
        SystemMouseCursors.click);
    expect(await cursorOver(tester, find.byKey(const Key('off'))),
        SystemMouseCursors.basic);
  });

  testWidgets('a HoldFan button points', (tester) async {
    await tester.pumpWidget(MaterialApp(
      theme: theme(),
      home: Scaffold(
        body: Center(
          child: HoldFan<String>(
            tooltip: 'New',
            onTap: () {},
            onSelected: (_) {},
            items: const [HoldFanItem('A', 'a')],
            child: const Icon(Icons.add),
          ),
        ),
      ),
    ));
    expect(await cursorOver(tester, find.byIcon(Icons.add)),
        SystemMouseCursors.click);
  });

  testWidgets('a HoldFan button sinks while pressed', (tester) async {
    await tester.pumpWidget(MaterialApp(
      theme: theme(),
      home: Scaffold(
        body: Center(
          child: HoldFan<String>(
            tooltip: 'New',
            onTap: () {},
            onSelected: (_) {},
            items: const [],
            child: const Icon(Icons.add),
          ),
        ),
      ),
    ));
    final scale = find.descendant(
        of: find.byType(HoldFan<String>), matching: find.byType(AnimatedScale));
    expect(tester.widget<AnimatedScale>(scale).scale, 1);
    final g =
        await tester.startGesture(tester.getCenter(find.byIcon(Icons.add)));
    await tester.pump();
    expect(tester.widget<AnimatedScale>(scale).scale, 0.94);
    await g.up();
    await tester.pump();
    expect(tester.widget<AnimatedScale>(scale).scale, 1);
  });

  test('no source asks for an ink splash or ripple', () {
    // The `lib` folders of the app and its packages.
    final bad = RegExp(r'InkSplash|InkRipple|splashFactory:\s*Ink');
    for (final dir in ['lib', '../atomic_chat/lib', '../../flutter/lib']) {
      final d = Directory(dir);
      if (!d.existsSync()) continue;
      for (final f in d.listSync(recursive: true).whereType<File>()) {
        if (!f.path.endsWith('.dart')) continue;
        expect(bad.hasMatch(f.readAsStringSync()), isFalse, reason: f.path);
      }
    }
  });
}
