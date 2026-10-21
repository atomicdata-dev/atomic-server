import 'dart:convert';
import 'dart:typed_data';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// A 1x1 PNG.
final Uint8List _png = base64Decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==');

final _now = DateTime.now().millisecondsSinceEpoch;

ActivityEntry _entry(String name,
        {String actor = 'Polle Pas 1',
        String drive = 'did:ad:drive',
        String driveName = 'Ontola',
        Duration ago = const Duration(hours: 16, minutes: 5),
        ResourcePicture? actorPicture =
            const ResourcePicture(file: 'did:ad:polle', person: true)}) =>
    ActivityEntry(
      subject: 'did:ad:$name',
      drive: drive,
      kind: 'changed',
      at: _now - ago.inMilliseconds,
      actor: actor,
      name: name,
      className: 'Document',
      actorPicture: actorPicture,
      driveName: driveName,
      drivePicture: const ResourcePicture(file: 'did:ad:drivepic'),
    );

class _Api extends FakeApi {
  _Api({super.activityList, super.driveList});

  @override
  Future<Uint8List?> fileBytes(String file) async => _png;

  @override
  Future<List<ActivityEntry>> activityPage(
          {ActivityEntry? before,
          int limit = AssistantApi.activityPageSize,
          bool includeOwn = false}) async =>
      before == null ? activityList : const [];
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  test('the short relative time reads like the web', () {
    final now = DateTime(2026, 10, 21, 12);
    String f(Duration d) =>
        shortTimeAgo(now.subtract(d).millisecondsSinceEpoch, now: now);
    expect(f(const Duration(seconds: 20)), 'just now');
    expect(f(const Duration(minutes: 5)), '5m ago');
    expect(f(const Duration(hours: 16)), '16h ago');
    expect(f(const Duration(days: 1, hours: 3)), '1d ago');
    expect(f(const Duration(days: 6)), '6d ago');
    expect(f(const Duration(days: 7)), '1w ago');
    expect(f(const Duration(days: 20)), '2w ago');
    expect(f(const Duration(days: 55)), '7w ago');
    expect(f(const Duration(days: 60)), '2026-08-22');
  });

  final entries = [
    _entry('Butter Cheese'),
    _entry('Tekenign',
        actor: 'joep.io',
        driveName: 'Other drive',
        drive: 'did:ad:d2',
        ago: const Duration(days: 5),
        actorPicture: null),
    for (var i = 0; i < 8; i++)
      _entry('Filler $i', ago: Duration(hours: 17 + i)),
  ];
  final drives = [
    (subject: 'did:ad:drive', name: 'Ontola', emoji: null, picture: null),
    (subject: 'did:ad:d2', name: 'Other drive', emoji: null, picture: null),
  ];

  void expectRow(WidgetTester tester, String title,
      {required String who, required String drive, required bool picture}) {
    final row = find
        .ancestor(of: find.text(title), matching: find.byType(ResourceRow))
        .first;
    expect(find.descendant(of: row, matching: find.text(who)), findsOneWidget);
    expect(
        find.descendant(of: row, matching: find.text(drive)), findsOneWidget);
    final avatar = find.descendant(
        of: find.descendant(
            of: row, matching: find.byKey(const Key('activity-actor-avatar'))),
        matching: find.byKey(const Key('row-picture')));
    expect(avatar, picture ? findsOneWidget : findsNothing);
  }

  testWidgets('Home section: type icon, who with avatar, when and the drive',
      (tester) async {
    tester.view.physicalSize = const Size(400, 3000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    final api = _Api(activityList: entries, driveList: drives);
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pumpAndSettle();

    expectRow(tester, 'Butter Cheese',
        who: 'Polle Pas 1 · 16h ago', drive: 'Ontola', picture: true);
    // No picture known: the initial on a colour, not an image.
    expectRow(tester, 'Tekenign',
        who: 'joep.io · 5d ago', drive: 'Other drive', picture: false);
    final row = find
        .ancestor(of: find.text('Tekenign'), matching: find.byType(ResourceRow))
        .first;
    expect(find.descendant(of: row, matching: find.text('J')), findsWidgets);
    // The drive's own picture is in the caption.
    expect(
        find.descendant(
            of: find.byKey(const Key('activity-drive')).first,
            matching: find.byKey(const Key('row-picture'))),
        findsOneWidget);
    // The type icon of a document.
    expect(find.descendant(of: row, matching: find.byType(RowLeading)),
        findsWidgets);
  });

  testWidgets('the full page, and its drive chips limit the feed to a drive',
      (tester) async {
    tester.view.physicalSize = const Size(400, 3000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    final api = _Api(activityList: entries, driveList: drives);
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const ValueKey('section-show-all-activity')));
    await tester.pump();
    await tester.tap(find.byKey(const ValueKey('section-show-all-activity')));
    await tester.pumpAndSettle();
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pumpAndSettle();

    expectRow(tester, 'Butter Cheese',
        who: 'Polle Pas 1 · 16h ago', drive: 'Ontola', picture: true);
    expect(find.text('Tekenign'), findsOneWidget);

    await tester.ensureVisible(find.byKey(const Key('activity-drive-d2')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('activity-drive-d2')));
    await tester.pumpAndSettle();
    Finder inList(String t) => find.descendant(
        of: find.byKey(const Key('activity-all-list')), matching: find.text(t));
    expect(inList('Butter Cheese'), findsNothing);
    expect(inList('Tekenign'), findsOneWidget);
    // Limited to one drive, the rows no longer name it.
    expect(
        find.descendant(
            of: find.byKey(const Key('activity-all-list')),
            matching: find.byKey(const Key('activity-drive'))),
        findsNothing);

    await tester.ensureVisible(find.byKey(const Key('activity-drive-all')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('activity-drive-all')));
    await tester.pumpAndSettle();
    expect(inList('Butter Cheese'), findsOneWidget);
  });

  testWidgets('on a tablet the who and when sit at the right, with the avatar',
      (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    final api = _Api(activityList: entries, driveList: drives);
    await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
    await tester.pumpAndSettle();
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pumpAndSettle();

    expect(find.text('Polle Pas 1 · 16h ago'), findsWidgets);
    expect(find.text('Ontola'), findsWidgets);
    expect(find.byKey(const Key('activity-actor-avatar')), findsWidgets);
    expect(
        find.descendant(
            of: find.byKey(const Key('activity-actor-avatar')).first,
            matching: find.byKey(const Key('row-picture'))),
        findsOneWidget);
  });
}
