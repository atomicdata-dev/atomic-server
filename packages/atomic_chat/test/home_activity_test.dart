import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// Activity on Home is what other members did; the person's own work is
/// Recents. The host leaves the own changes out of the activity it returns;
/// the Home shows what it returns, in the person's drives only, and names
/// every member (never "Someone").

final _fiveMinAgo =
    DateTime.now().millisecondsSinceEpoch - 5 * 60 * 1000 - 5000;

ActivityEntry _by(String? actor, String name,
        {String kind = 'changed', String drive = 'did:ad:drive'}) =>
    ActivityEntry(
      subject: 'did:ad:$name',
      drive: drive,
      kind: kind,
      at: _fiveMinAgo,
      actor: actor,
      name: name,
      className: 'Document',
    );

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('own edits are Recents, other members\' are Activity',
      (tester) async {
    final api = FakeApi(
      recent: [
        (
          subject: 'did:ad:mine',
          title: 'My own edit',
          className: 'Document',
          openedAt: _fiveMinAgo,
          emoji: null
        ),
      ],
      activityList: [
        _by('Bob', 'Bobs plan'),
        _by('a3f9…', 'Unnamed members note', kind: 'created'),
        _by(null, 'Old host row'),
        _by('Carol', 'Not my drive', drive: 'did:ad:someone-elses'),
      ],
    );
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();

    double y(Finder f) => tester.getTopLeft(f).dy;
    final activity = y(find.text('Activity'));
    // The own edit is under Recents, above Activity.
    expect(y(find.text('My own edit')), lessThan(activity));
    expect(find.text('My own edit'), findsOneWidget);

    expect(find.text('Bob edited · 5 min ago'), findsOneWidget);
    expect(y(find.text('Bobs plan')), greaterThan(activity));
    expect(find.text('a3f9… created · 5 min ago'), findsOneWidget);
    expect(find.text('Unknown member edited · 5 min ago'), findsOneWidget);
    expect(find.textContaining('Someone'), findsNothing);
    // Only the person's drives.
    expect(find.text('Not my drive'), findsNothing);
    expect(find.text('No activity from others yet'), findsNothing);
  });

  testWidgets('no activity from others is one quiet line', (tester) async {
    final api = FakeApi(recent: [
      (
        subject: 'did:ad:mine',
        title: 'My own edit',
        className: 'Document',
        openedAt: _fiveMinAgo,
        emoji: null
      ),
    ]);
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();
    expect(find.text('Activity'), findsOneWidget);
    expect(find.text('No activity from others yet'), findsOneWidget);
    expect(find.text('My own edit'), findsOneWidget);
  });
}
