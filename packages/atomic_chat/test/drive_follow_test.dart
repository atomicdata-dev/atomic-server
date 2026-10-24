import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

const _home =
    (subject: 'did:ad:home', name: 'Home', emoji: null, picture: null);
const _work =
    (subject: 'did:ad:work', name: 'Work', emoji: null, picture: null);
const _club = (subject: 'did:ad:club', name: 'Club', emoji: '⚽', picture: null);

/// A store that answers `getResource` with [resources] (subject → JSON-AD).
class _Api extends FakeApi {
  final Map<String, Map<String, Object?>> resources;
  _Api(this.resources) : super(driveList: const [_home, _work, _club]);

  @override
  Future<String> embedCall(String method, String argsJson) async {
    if (method != 'getResource') return 'null';
    final subject = (jsonDecode(argsJson) as List).first as String;
    return jsonEncode(resources[subject]);
  }
}

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:home',
      warmPool: (_) => null,
      profile: (_) => const Scaffold(body: Text('profile page')),
      home: ChatsScreen(drive: 'did:ad:home', api: api),
    ));

String _header(WidgetTester tester) =>
    tester.widget<Text>(find.byKey(const Key('current-drive-name'))).data!;

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    resetDriveVisits();
    ResourceView.serverFactory = () async => throw 'no server in a test';
  });

  group('the drive of a resource', () {
    test('is its drive property, a drive its own, else unknown', () async {
      final api = _Api({
        'did:ad:doc': {
          'https://atomicdata.dev/properties/drive': 'did:ad:work'
        },
        'did:ad:work': {
          'https://atomicdata.dev/properties/isA': [
            'https://atomicdata.dev/classes/Drive'
          ]
        },
        'did:ad:loose': {'https://atomicdata.dev/properties/name': 'x'},
      });
      expect(await driveOfResource(api, 'did:ad:doc'), 'did:ad:work');
      expect(await driveOfResource(api, 'did:ad:work'), 'did:ad:work');
      expect(await driveOfResource(api, 'did:ad:loose'), isNull);
      expect(await driveOfResource(api, 'did:ad:missing'), isNull);
    });
  });

  testWidgets('the home follows when another page makes a drive current',
      (tester) async {
    final api = _Api({});
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    expect(_header(tester), 'Home');

    final shell =
        tester.widget<ShellScope>(find.byType(ShellScope).first).controller;
    shell.drive.value = 'did:ad:work';
    await tester.pumpAndSettle();

    expect(api.activeSet, ['did:ad:work']);
    expect(_header(tester), 'Work');
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 6));
  });

  testWidgets('holding the drive lists the others; letting go on one switches',
      (tester) async {
    final api = _Api({});
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:home', api: api)));
    await tester.pumpAndSettle();

    final switcher = find.byKey(const Key('current-drive-switch'));
    expect(tester.widget(switcher), isA<HoldFan>());

    final gesture = await tester.startGesture(tester.getCenter(switcher));
    await tester.pump(const Duration(milliseconds: 600));
    await tester.pump(const Duration(milliseconds: 200));
    // The current drive is not offered.
    expect(find.text('Work'), findsOneWidget);
    expect(find.textContaining('Club'), findsWidgets);
    expect(find.text('Home'), findsOneWidget, reason: 'only the header');

    await gesture.moveTo(tester.getCenter(find.text('Work')));
    await tester.pump();
    await gesture.up();
    await tester.pumpAndSettle();

    expect(api.activeSet, ['did:ad:work']);
    expect(_header(tester), 'Work');
    expect(find.byKey(const Key('drive-switcher')), findsNothing);
  });

  testWidgets('a tap on the selector still opens the switcher', (tester) async {
    final api = _Api({});
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:home', api: api)));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('current-drive-switch')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('drive-switcher')), findsOneWidget);
    expect(api.activeSet, isEmpty);
  });
}
