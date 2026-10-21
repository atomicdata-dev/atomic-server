import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// Activity on Home is what other members did; the person's own work is
/// not in it (Search lists it). The host leaves the own changes out of the activity it returns;
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

  testWidgets('the activity lists other members\' changes, not the own',
      (tester) async {
    final api = FakeApi(
      favoriteList: [
        (
          subject: 'did:ad:mine',
          title: 'My own edit',
          className: 'Document',
          classUrl: '',
          openedAt: _fiveMinAgo,
          emoji: null, picture: null
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
    // The own edit is not an activity row (here it is a favorite, below).
    expect(y(find.text('My own edit')), greaterThan(activity));
    expect(find.text('My own edit'), findsOneWidget);

    expect(find.text('Bob · 5m ago'), findsOneWidget);
    expect(y(find.text('Bobs plan')), greaterThan(activity));
    expect(find.text('a3f9… created · 5m ago'), findsOneWidget);
    expect(find.text('Unknown member · 5m ago'), findsOneWidget);
    expect(find.textContaining('Someone'), findsNothing);
    // Only the person's drives.
    expect(find.text('Not my drive'), findsNothing);
    expect(find.text('No activity from others yet'), findsNothing);
  });

  testWidgets('no activity from others is one quiet line', (tester) async {
    final api = FakeApi(favoriteList: [
      (
        subject: 'did:ad:mine',
        title: 'My own edit',
        className: 'Document',
        classUrl: '',
        openedAt: _fiveMinAgo,
        emoji: null, picture: null
      ),
    ]);
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();
    expect(find.text('Activity'), findsOneWidget);
    expect(find.text('No activity from others yet'), findsOneWidget);
    expect(find.text('My own edit'), findsOneWidget);
  });
}
