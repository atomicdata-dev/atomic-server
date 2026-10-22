import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  String? copied;

  setUp(() {
    copied = null;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        copied = (call.arguments as Map)['text'] as String;
      }
      return null;
    });
  });
  tearDown(() => messenger.setMockMethodCallHandler(
      SystemChannels.platform, null));

  Widget app(Widget child) =>
      MaterialApp(home: Scaffold(body: Center(child: child)));

  testWidgets('is selectable text, not plain Text', (tester) async {
    await tester.pumpWidget(app(const ErrorText('boom: it broke')));
    expect(find.byType(SelectableText), findsOneWidget);
    expect(find.widgetWithText(SelectableText, 'boom: it broke'),
        findsOneWidget);
    expect(find.byType(Text), findsNothing);
  });

  testWidgets('Copy puts the exact full text on the clipboard',
      (tester) async {
    final long = List.generate(20, (i) => 'line $i of the stack').join('\n');
    await tester.pumpWidget(app(ErrorText(long)));
    // Long text starts collapsed, copy still takes everything.
    expect(find.text('Show more'), findsOneWidget);
    await tester.tap(find.byTooltip('Copy'));
    await tester.pump();
    expect(copied, long);
    expect(find.text('Copied'), findsOneWidget);
    await tester.pump(const Duration(seconds: 2));
    expect(find.text('Copied'), findsNothing);
    expect(find.byTooltip('Copy'), findsOneWidget);

    await tester.tap(find.text('Show more'));
    await tester.pump();
    expect(find.text('Show less'), findsOneWidget);
  });
}
