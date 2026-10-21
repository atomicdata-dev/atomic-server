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
  ]);

  testWidgets('a row has its leading by default', (tester) async {
    await tester
        .pumpWidget(app(ChatsScreen(drive: 'did:ad:current', api: api)));
    await tester.pumpAndSettle();
    expect(find.byType(RowLeading), findsWidgets);
    expect(tester.getTopLeft(find.text('Zebra').first).dx, greaterThan(16));
  });

  testWidgets('off: no RowLeading on Home and the text starts at 16 dp',
      (tester) async {
    AppSidebarIcons.show.value = false;
    await tester
        .pumpWidget(app(ChatsScreen(drive: 'did:ad:current', api: api)));
    await tester.pumpAndSettle();
    expect(find.text('Zebra'), findsOneWidget);
    expect(find.byType(RowLeading), findsNothing);
    expect(tester.getTopLeft(find.text('Zebra').first).dx, 16);
    expect(tester.getSize(find.widgetWithText(ListTile, 'Zebra')).height,
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
}
