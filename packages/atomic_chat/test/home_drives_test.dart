import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// The host orders the drives (the current one, then the most recently used,
/// then the rest by name: `order_drives_by_use`), so every list of drives
/// agrees. Home keeps that order and does not sort them again.
void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('Home lists the drives in the order the host gives',
      (tester) async {
    final api = FakeApi(driveList: [
      (subject: 'did:ad:current', name: 'Zebra', emoji: null),
      (subject: 'did:ad:used', name: 'Mango', emoji: null),
      (subject: 'did:ad:never-a', name: 'Apple', emoji: null),
    ]);
    await tester
        .pumpWidget(app(ChatsScreen(drive: 'did:ad:current', api: api)));
    await tester.pumpAndSettle();

    double y(String t) => tester.getTopLeft(find.text(t).first).dy;
    expect(find.text('Zebra'), findsOneWidget);
    expect(y('Zebra'), lessThan(y('Mango')));
    expect(y('Mango'), lessThan(y('Apple')));
  });
}
