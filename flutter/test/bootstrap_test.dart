import 'package:atomic_app/bootstrap.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late List<Widget> shown;
  late int started;

  setUp(() {
    shown = [];
    started = 0;
  });

  Future<void> boot(
    WidgetTester tester, {
    Future<void> Function()? initRust,
    Future<String?> Function(String)? openDb,
  }) async {
    await bootstrap(
      initRust: initRust ?? () async {},
      ready: () async {},
      documentsPath: () async => '/docs',
      openDb: openDb ?? (_) async => null,
      startApp: () => started++,
      show: (app) {
        shown.add(app);
      },
    );
  }

  testWidgets('a failing native init shows the fallback, not a black window',
      (tester) async {
    await boot(tester,
        initRust: () async => throw StateError('api version mismatch'));
    expect(started, 0);
    expect(shown, hasLength(1));

    await tester.pumpWidget(shown.single);
    expect(find.text('The app could not start'), findsOneWidget);
    expect(find.textContaining('api version mismatch'), findsOneWidget);
    expect(find.text('Try again'), findsOneWidget);
    expect(find.text('Copy details'), findsOneWidget);
  });

  testWidgets('Try again starts the app once the init works', (tester) async {
    var fail = true;
    var inits = 0;
    await boot(tester, initRust: () async {
      inits++;
      if (fail) throw StateError('boom');
    });
    await tester.pumpWidget(shown.single);

    // Still failing: the same screen, the new error.
    await tester.tap(find.byKey(const Key('startup-retry')));
    await tester.pumpAndSettle();
    expect(started, 0);
    expect(find.textContaining('boom'), findsOneWidget);

    fail = false;
    await tester.tap(find.byKey(const Key('startup-retry')));
    await tester.pumpAndSettle();
    expect(started, 1);
    expect(inits, 3);
  });

  testWidgets('the library is not initialised twice after it loaded',
      (tester) async {
    var inits = 0;
    var opens = 0;
    await boot(tester,
        initRust: () async => inits++,
        openDb: (_) async {
          if (opens++ == 0) throw StateError('no documents');
          return null;
        });
    await tester.pumpWidget(shown.single);
    await tester.tap(find.byKey(const Key('startup-retry')));
    await tester.pumpAndSettle();
    expect(started, 1);
    expect(inits, 1);
  });

  testWidgets('Copy details puts the error on the clipboard', (tester) async {
    String? copied;
    tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        copied = (call.arguments as Map)['text'] as String;
      }
      return null;
    });
    addTearDown(() => tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null));

    await boot(tester, initRust: () async => throw StateError('mismatch'));
    await tester.pumpWidget(shown.single);
    await tester.tap(find.byKey(const Key('startup-copy')));
    await tester.pumpAndSettle();
    expect(copied, contains('mismatch'));
    expect(find.text('Copied'), findsOneWidget);
  });

  testWidgets('a store that will not open keeps its own screen',
      (tester) async {
    await boot(tester, openDb: (_) async => 'disk full');
    expect(started, 0);
    await tester.pumpWidget(shown.single);
    expect(find.text('The app could not open its local data'), findsOneWidget);
  });

  testWidgets('everything fine starts the app', (tester) async {
    await boot(tester);
    expect(started, 1);
    expect(shown, isEmpty);
  });
}
