import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _app(Widget bar) => MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: Builder(
        builder: (context) => Scaffold(
          appBar: bar is PreferredSizeWidget ? bar : null,
          body: ElevatedButton(
            onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(
                builder: (_) => Scaffold(
                    appBar: const AppTopBar(title: 'Second'),
                    body: const SizedBox()))),
            child: const Text('go'),
          ),
        ),
      ),
    );

void main() {
  testWidgets('shows the title, trailing actions and a fixed height',
      (tester) async {
    await tester.pumpWidget(_app(AppTopBar(
      title: 'Chats',
      actions: [IconButton(onPressed: () {}, icon: const Icon(Icons.edit))],
    )));
    expect(find.text('Chats'), findsOneWidget);
    expect(find.byIcon(Icons.edit), findsOneWidget);
    expect(tester.getSize(find.byType(AppBar)).height, AppTopBar.height);
  });

  testWidgets('the home bar can show the wordmark', (tester) async {
    await tester
        .pumpWidget(_app(const AppTopBar(titleWidget: AtomicWordmark())));
    expect(find.byType(SvgPicture), findsOneWidget);
    expect(tester.getSize(find.byKey(const Key('atomic-wordmark'))).height, 22);
    expect(tester.takeException(), isNull);
    expect(find.byKey(const Key('atomic-wordmark')), findsOneWidget);
  });

  testWidgets('a pushed screen gets a back button and the same height',
      (tester) async {
    await tester.pumpWidget(_app(const AppTopBar(title: 'First')));
    expect(find.byType(BackButton), findsNothing);
    await tester.tap(find.text('go'));
    await tester.pumpAndSettle();
    expect(find.byType(BackButton), findsOneWidget);
    expect(tester.getSize(find.byType(AppBar)).height, AppTopBar.height);
    await tester.tap(find.byType(BackButton));
    await tester.pumpAndSettle();
    expect(find.text('First'), findsOneWidget);
  });
}
