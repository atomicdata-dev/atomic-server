import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// The host orders the drives (the current one, then the most recently used,
/// then the rest by name: `order_drives_by_use`), so every list of drives
/// agrees. Home keeps that order and does not sort them again.
void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('The drive switcher lists the drives in the order the host gives',
      (tester) async {
    final api = FakeApi(driveList: [
      (subject: 'did:ad:current', name: 'Zebra', emoji: null, picture: null),
      (subject: 'did:ad:used', name: 'Mango', emoji: null, picture: null),
      (subject: 'did:ad:never-a', name: 'Apple', emoji: null, picture: null),
    ]);
    await tester
        .pumpWidget(app(ChatsScreen(drive: 'did:ad:current', api: api)));
    await tester.pumpAndSettle();

    // The current drive is the header; the switcher lists them as given.
    expect(find.byKey(const Key('current-drive-name')), findsOneWidget);
    expect(find.text('Zebra'), findsOneWidget);
    await tester.tap(find.byKey(const Key('current-drive-header')));
    await tester.pumpAndSettle();
    double y(String s) => tester
        .getTopLeft(find.byKey(ValueKey('drive-switcher-row-did:ad:$s')))
        .dy;
    expect(y('current'), lessThan(y('used')));
    expect(y('used'), lessThan(y('never-a')));
  });
}
