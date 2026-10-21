import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

BackgroundState _busy([Map<String, int> kinds = const {'drives': 1}]) =>
    BackgroundState(
        total: kinds.values.fold(0, (a, b) => a + b), byKind: kinds);

Widget _app(BackgroundActivity activity,
        {VoidCallback? onTap, bool reduced = false}) =>
    MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: MediaQuery(
        data: MediaQueryData(disableAnimations: reduced),
        child: Scaffold(
          appBar: AppBar(actions: [
            BackgroundActivityIndicator(activity: activity, onTap: onTap),
          ]),
        ),
      ),
    );

final _spinner = find.descendant(
    of: find.byKey(const Key('background-activity')),
    matching: find.byType(RotationTransition));

double _opacity(WidgetTester tester) => tester
    .widget<AnimatedOpacity>(find.byKey(const Key('background-activity')))
    .opacity;

void main() {
  late BackgroundActivity activity;
  late BackgroundState host;

  setUp(() {
    host = BackgroundState.idle;
    activity = BackgroundActivity()..hostPoller = () => host;
  });

  testWidgets('hidden while idle', (tester) async {
    await tester.pumpWidget(_app(activity));
    await tester.pump(const Duration(seconds: 2));
    expect(_opacity(tester), 0);
    expect(find.byIcon(Icons.sync), findsNothing);
  });

  testWidgets('shows after 400 ms of activity and rotates', (tester) async {
    await tester.pumpWidget(_app(activity));
    host = _busy();
    await tester.pump(const Duration(seconds: 1)); // the poll sees it
    await tester.pump(const Duration(milliseconds: 300));
    expect(_opacity(tester), 0);
    await tester.pump(const Duration(milliseconds: 200));
    await tester.pump(const Duration(milliseconds: 200));
    expect(_opacity(tester), 1);
    expect(_spinner, findsOneWidget);
    final before = tester
        .widget<RotationTransition>(_spinner)
        .turns
        .value;
    await tester.pump(const Duration(milliseconds: 300));
    final after = tester
        .widget<RotationTransition>(_spinner)
        .turns
        .value;
    expect(after, isNot(before));

    // Idle again: stays for at least 800 ms from when it showed, then goes.
    host = BackgroundState.idle;
    await tester.pump(const Duration(seconds: 1));
    await tester.pump(const Duration(seconds: 1));
    expect(_opacity(tester), 0);
    expect(_spinner, findsNothing);
  });

  testWidgets('a 100 ms blip never shows', (tester) async {
    await tester.pumpWidget(_app(activity));
    final token = activity.begin('pictures');
    await tester.pump(const Duration(milliseconds: 100));
    token.end();
    await tester.pump(const Duration(seconds: 2));
    expect(_opacity(tester), 0);
    expect(_spinner, findsNothing);
  });

  testWidgets('stays at least 800 ms once shown', (tester) async {
    await tester.pumpWidget(_app(activity));
    final token = activity.begin('pictures');
    await tester.pump(const Duration(milliseconds: 450));
    expect(_opacity(tester), 1);
    token.end();
    await tester.pump(const Duration(milliseconds: 500));
    expect(_opacity(tester), 1);
    await tester.pump(const Duration(milliseconds: 400));
    await tester.pump(const Duration(milliseconds: 200));
    expect(_opacity(tester), 0);
  });

  testWidgets('an error with nothing running shows a static amber icon',
      (tester) async {
    host = const BackgroundState(lastError: 'Sync timed out');
    await tester.pumpWidget(_app(activity));
    await tester.pump(const Duration(milliseconds: 300));
    expect(_opacity(tester), 1);
    expect(find.byIcon(Icons.sync_problem), findsOneWidget);
    expect(_spinner, findsNothing);
    expect(find.bySemanticsLabel('Sync problem'), findsOneWidget);
  });

  testWidgets('tap opens the Sync page; the label says what runs',
      (tester) async {
    var taps = 0;
    await tester.pumpWidget(_app(activity, onTap: () => taps++));
    host = _busy({'drives': 2, 'pictures': 1});
    await tester.pump(const Duration(seconds: 1));
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pump(const Duration(milliseconds: 50));
    expect(find.bySemanticsLabel('Syncing…'), findsOneWidget);
    await tester.tap(find.byKey(const Key('background-activity-spinner')));
    expect(taps, 1);
    expect(activity.value.caption, 'Syncing drives · Loading pictures');
    expect(activity.value.summary,
        'Syncing drives · Loading pictures · 3 tasks');
  });

  testWidgets('reduced motion: a still dot, no rotation', (tester) async {
    await tester.pumpWidget(_app(activity, reduced: true));
    host = _busy();
    await tester.pump(const Duration(seconds: 1));
    await tester.pump(const Duration(milliseconds: 500));
    expect(find.byKey(const Key('background-activity-dot')), findsOneWidget);
    expect(_spinner, findsNothing);
  });

  test('polls fast, slows down when idle, stops when stopped', () async {
    var reads = 0;
    final a = BackgroundActivity(
        fast: const Duration(milliseconds: 10),
        slow: const Duration(milliseconds: 60),
        idleLimit: 3)
      ..hostPoller = () {
        reads++;
        return BackgroundState.idle;
      };
    a.start();
    await Future<void>.delayed(const Duration(milliseconds: 100));
    final fastReads = reads;
    expect(fastReads, greaterThan(2));
    a.stop();
    expect(a.polling, isFalse);
    final stopped = reads;
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(reads, stopped);
  });

  test('summary: idle, error', () {
    expect(BackgroundState.idle.summary, 'Idle');
    expect(const BackgroundState(lastError: 'Offline').summary, 'Offline');
  });
}
