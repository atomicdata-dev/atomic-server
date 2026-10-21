import 'package:atomic_app/screens/store_recovery_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

const _broken = StoreRecoveryNotice(
  keptPath: '/data/app_flutter/atomic.redb.corrupt-1',
  reason: 'The store file is damaged: redb panicked opening atomic.redb',
  repaired: false,
);

void main() {
  testWidgets('an unrepairable store: say so, start fresh, share the file',
      (tester) async {
    var continued = false;
    String? shared;
    await tester.pumpWidget(MaterialApp(
      home: StoreRecoveryScreen(
        notice: _broken,
        onContinue: () => continued = true,
        onShare: (path) async => shared = path,
      ),
    ));

    expect(find.text('Your local data could not be opened'), findsOneWidget);
    expect(find.textContaining('Your identity is kept'), findsOneWidget);
    expect(find.textContaining('which is kept'), findsOneWidget);

    await tester.tap(find.byKey(const Key('store-recovery-share')));
    await tester.pump();
    expect(shared, _broken.keptPath);

    await tester.tap(find.text('Details'));
    await tester.pumpAndSettle();
    expect(find.textContaining('redb panicked'), findsOneWidget);
    expect(
        find.byWidgetPredicate((w) =>
            w is SelectableText && (w.data ?? '').contains('redb panicked')),
        findsOneWidget);

    await tester.tap(find.text('Start fresh'));
    expect(continued, isTrue);
  });

  testWidgets('a repaired store: say the last changes may be missing',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: StoreRecoveryScreen(
        notice: const StoreRecoveryNotice(
            keptPath: '/x.corrupt-2', reason: 'short', repaired: true),
        onContinue: () {},
        onShare: (_) async {},
      ),
    ));
    expect(find.text('Your local data was repaired'), findsOneWidget);
    expect(find.textContaining('may be missing'), findsOneWidget);
    expect(find.text('Continue'), findsOneWidget);
    expect(find.text('Start fresh'), findsNothing);
  });

  testWidgets('a failed share is reported, not thrown', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: StoreRecoveryScreen(
        notice: _broken,
        onContinue: () {},
        onShare: (_) async => throw Exception('no share target'),
      ),
    ));
    await tester.tap(find.byKey(const Key('store-recovery-share')));
    await tester.pumpAndSettle();
    expect(find.textContaining('Could not share the file'), findsOneWidget);
  });

  testWidgets('a store that does not open at all offers to try again',
      (tester) async {
    var attempts = 0;
    await tester.pumpWidget(MaterialApp(
      home: StoreOpenFailedScreen(
        error: 'Permission denied',
        onRetry: () async {
          attempts++;
          return 'No space left on device';
        },
      ),
    ));
    expect(find.text('The app could not open its local data'), findsOneWidget);
    expect(find.text('Permission denied'), findsOneWidget);
    await tester.tap(find.byKey(const Key('store-open-retry')));
    await tester.pumpAndSettle();
    expect(attempts, 1);
    expect(find.text('No space left on device'), findsOneWidget);
  });
}
