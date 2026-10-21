import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// "Show icons in the sidebar" (Appearance): off, Home's rows are text only.
void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    AppSidebarIcons.show.value = true;
  });
  tearDown(() => AppSidebarIcons.show.value = true);

  final api = FakeApi(driveList: [
    (subject: 'did:ad:current', name: 'Zebra', emoji: '🦓', picture: null),
    (subject: 'did:ad:used', name: 'Mango', emoji: null, picture: null),
  ], childrenOf: {
    'did:ad:current': [
      (
        subject: 'did:ad:doc',
        title: 'Plan',
        className: 'document-v2',
        classUrl: '',
        expandable: true,
        emoji: '🦊',
        picture: null
      ),
    ],
  });

  testWidgets('a row has its leading by default', (tester) async {
    await tester
        .pumpWidget(app(ChatsScreen(drive: 'did:ad:current', api: api)));
    await tester.pumpAndSettle();
    expect(find.byType(RowLeading), findsWidgets);
    expect(tester.getTopLeft(find.text('Plan').first).dx, greaterThan(16));
  });

  testWidgets('off: no RowLeading on Home and the text starts at 16 dp',
      (tester) async {
    AppSidebarIcons.show.value = false;
    await tester
        .pumpWidget(app(ChatsScreen(drive: 'did:ad:current', api: api)));
    await tester.pumpAndSettle();
    expect(find.text('Plan'), findsOneWidget);
    expect(find.byType(RowLeading), findsNothing);
    expect(tester.getTopLeft(find.text('Plan').first).dx, 16);
    expect(tester.getSize(find.widgetWithText(ListTile, 'Plan')).height,
        greaterThanOrEqualTo(44));

    // Switched on again: the leading comes back at once.
    AppSidebarIcons.show.value = true;
    await tester.pumpAndSettle();
    expect(find.byType(RowLeading), findsWidgets);
  });

  testWidgets('a row outside Home keeps its leading (search, sheets)',
      (tester) async {
    AppSidebarIcons.show.value = false;
    await tester.pumpWidget(app(const Material(
        child: Column(children: [
      ResourceRow(title: 'Result', icon: Icons.description_outlined),
    ]))));
    expect(find.byType(RowLeading), findsOneWidget);
  });

  testWidgets(
      'an AI chat row shows its emoji, the chat icon without one, '
      'and nothing with icons off', (tester) async {
    final chats = FakeApi(chatList: [
      (subject: 'c1', name: 'Bakery site', lastActivity: 2, emoji: '🥐'),
      (subject: 'c2', name: 'Plain chat', lastActivity: 1, emoji: null),
    ]);
    await tester
        .pumpWidget(app(ChatsScreen(drive: 'did:ad:current', api: chats)));
    await tester.pumpAndSettle();
    Finder leadingOf(String title) => find.descendant(
        of: find.widgetWithText(ListTile, title),
        matching: find.byType(RowLeading));
    expect(find.text('Bakery site'), findsOneWidget);
    expect(
        find.descendant(
            of: leadingOf('Bakery site'), matching: find.text('🥐')),
        findsOneWidget);
    expect(leadingOf('Plain chat'), findsOneWidget);
    expect(
        find.descendant(
            of: leadingOf('Plain chat'), matching: find.byType(Icon)),
        findsOneWidget);

    AppSidebarIcons.show.value = false;
    await tester.pumpAndSettle();
    expect(find.text('🥐'), findsNothing);
    expect(leadingOf('Bakery site'), findsNothing);
  });
}
