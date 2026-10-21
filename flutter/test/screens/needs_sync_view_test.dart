import 'dart:math' as math;

import 'package:atomic_app/atomic/sync_failure.dart';
import 'package:atomic_app/screens/needs_sync_view.dart';
import 'package:atomic_app/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const _raw = 'https://node1.atomicserver.eu: PanicException(\n'
    'Could not automatically determine the process-level CryptoProvider\n'
    'https://staging.atomicdata.dev: ClientConnection closed\n'
    'None of the 4 devices that announced your drive answered (a9dd56e296f0: '
    'Iroh connect timed out after 20s.)';

double _lum(Color c) {
  double f(double v) =>
      v <= 0.03928 ? v / 12.92 : math.pow((v + 0.055) / 1.055, 2.4).toDouble();
  return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
}

double _contrast(Color a, Color b) {
  final l1 = _lum(a), l2 = _lum(b);
  return (math.max(l1, l2) + 0.05) / (math.min(l1, l2) + 0.05);
}

Future<void> _pump(
  WidgetTester tester, {
  bool searching = true,
  SyncFailure? failure,
  Size size = const Size(393, 852),
  bool dark = false,
  bool reduced = false,
  VoidCallback? onRetry,
  VoidCallback? onBack,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(MaterialApp(
    theme: ThemeData(
      brightness: dark ? Brightness.dark : Brightness.light,
      extensions: [dark ? AppColors.dark : AppColors.light],
    ),
    builder: (context, child) => MediaQuery(
      data: MediaQuery.of(context).copyWith(disableAnimations: reduced),
      child: child!,
    ),
    home: NeedsSyncView(
      searching: searching,
      failure: failure,
      status: 'Checking devices on your network…',
      onRetry: onRetry ?? () {},
      onPair: () {},
      onPaste: () {},
      onBack: onBack ?? () {},
    ),
  ));
  await tester.pump(const Duration(milliseconds: 300));
}

void main() {
  for (final w in [393.0, 1000.0]) {
    for (final dark in [false, true]) {
      testWidgets(
          'searching: big hero, small buttons, no scroll '
          '(${w.toInt()} dp, ${dark ? 'dark' : 'light'})', (tester) async {
        await _pump(tester, size: Size(w, 852), dark: dark);
        final hero =
            tester.getSize(find.byKey(const ValueKey('needsSync-hero')));
        expect(hero.width, greaterThanOrEqualTo(96));
        expect(hero.height, greaterThanOrEqualTo(96));
        expect(find.text('Looking for your devices'), findsOneWidget);
        expect(find.text('Checking devices on your network…'), findsOneWidget);
        for (final k in ['pair', 'paste']) {
          final s = tester.getSize(find.byKey(ValueKey('needsSync-$k')));
          expect(s.height, lessThanOrEqualTo(44));
          expect(s.width, lessThan(w - 48));
          expect(s.width, lessThan(360));
        }
        expect(find.text('Back'), findsNothing);
        expect(find.byTooltip('Back'), findsOneWidget);
        final scroll = tester.state<ScrollableState>(find.byType(Scrollable));
        expect(scroll.position.maxScrollExtent, 0);

        final c = dark ? AppColors.dark : AppColors.light;
        final title =
            tester.widget<Text>(find.byKey(const ValueKey('needsSync-title')));
        expect(_contrast(title.style!.color!, c.pageBg),
            greaterThanOrEqualTo(4.5));
        final status =
            tester.widget<Text>(find.byKey(const ValueKey('needsSync-status')));
        expect(_contrast(status.style!.color!, c.pageBg),
            greaterThanOrEqualTo(4.5));
        await tester.pumpWidget(const SizedBox());
      });
    }
  }

  testWidgets('reduced motion: static ring plus a small bar, nothing repeats',
      (tester) async {
    await _pump(tester, reduced: true);
    expect(find.byKey(const ValueKey('needsSync-bar')), findsOneWidget);
    expect(
        find.byType(CustomPaint).evaluate().where((e) =>
            e.widget is CustomPaint &&
            (e.widget as CustomPaint).painter.runtimeType.toString() ==
                '_PulsePainter'),
        isEmpty);
    expect(tester.getSize(find.byKey(const ValueKey('needsSync-hero'))).width,
        112);
  });

  testWidgets('failure: friendly summary, raw text only behind Details',
      (tester) async {
    var retried = 0;
    await _pump(tester,
        searching: false,
        failure: SyncFailure.parse(_raw),
        onRetry: () => retried++);
    expect(find.text('Couldn’t reach your devices'), findsOneWidget);
    expect(find.textContaining('No other device answered'), findsOneWidget);
    expect(find.textContaining('PanicException'), findsNothing);
    expect(find.textContaining('https://'), findsNothing);
    expect(find.byKey(const ValueKey('needsSync-details-panel')), findsNothing);

    await tester.tap(find.byKey(const ValueKey('needsSync-retry')));
    expect(retried, 1);
    expect(tester.getSize(find.byKey(const ValueKey('needsSync-retry'))).height,
        lessThanOrEqualTo(44));

    await tester.tap(find.byKey(const ValueKey('needsSync-details')));
    await tester.pumpAndSettle();
    expect(
        find.byKey(const ValueKey('needsSync-details-panel')), findsOneWidget);
    expect(find.textContaining('PanicException', findRichText: true),
        findsOneWidget);
    expect(
        find.byWidgetPredicate((w) =>
            w is SelectableText && (w.data ?? '').contains('PanicException')),
        findsOneWidget);

    String? copied;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        copied = (call.arguments as Map)['text'] as String;
      }
      return null;
    });
    await tester.ensureVisible(find.byKey(const ValueKey('needsSync-copy')));
    await tester.tap(find.byKey(const ValueKey('needsSync-copy')));
    expect(copied, contains('Iroh connect'));
  });

  test('SyncFailure.parse keeps URLs and panics out of the summary', () {
    final f = SyncFailure.parse(_raw);
    expect(f.summary, isNot(contains('://')));
    expect(f.summary, isNot(contains('Panic')));
    expect(f.details, hasLength(4));
    final g = SyncFailure.parse('https://x.eu: PanicException(boom');
    expect(g.summary, isNot(contains('Panic')));
    expect(g.summary, isNot(contains('https')));
  });

  testWidgets('back arrow calls onBack', (tester) async {
    var backs = 0;
    await _pump(tester, onBack: () => backs++);
    await tester.tap(find.byKey(const ValueKey('needsSync-back')));
    expect(backs, 1);
  });
}
