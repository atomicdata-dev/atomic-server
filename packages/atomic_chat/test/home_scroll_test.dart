import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

RecentResource _r(String subject, String title) => (
      subject: subject,
      title: title,
      className: 'document-v2',
      classUrl: '',
      openedAt: 1,
      emoji: null, picture: null,
    );

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:home',
      home: ChatsScreen(drive: 'did:ad:home', api: api),
    ));

Finder _heading(String name) => find.byKey(ValueKey('home-panel-$name'));

void main() {
  late FakeApi api;

  setUp(() {
    ResourceView.serverFactory = () async => throw 'no server in a test';
    api = FakeApi(
      driveList: [
        for (var i = 0; i < 7; i++)
          (subject: 'did:ad:d$i', name: 'Drive $i', emoji: null, picture: null),
      ],
      favoriteList: [for (var i = 0; i < 7; i++) _r('did:ad:f$i', 'Fav $i')],
    );
  });

  Future<void> phone(WidgetTester tester, {double h = 480}) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = Size(400, h);
    addTearDown(tester.view.reset);
  }

  group('a heading is one tap target', () {
    testWidgets('the far right, the title and a hold', (tester) async {
      SharedPreferences.setMockInitialValues({});
      await phone(tester, h: 800);
      await tester.pumpWidget(_shell(api));
      await tester.pumpAndSettle();
      final heading = _heading('favorites');
      expect(tester.getSize(heading).width, 400);
      var r = tester.getRect(heading);
      expect(find.text('Fav 0'), findsOneWidget);
      // Empty space right of the title, left of the chevron.
      await tester.tapAt(Offset(r.right - 80, r.center.dy));
      await tester.pumpAndSettle();
      expect(find.text('Fav 0'), findsNothing);
      await tester.tap(find.text('Favorites'));
      await tester.pumpAndSettle();
      expect(find.text('Fav 0'), findsOneWidget);
      // Semantics.
      final h = tester.ensureSemantics();
      r = tester.getRect(heading);
      final node =
          tester.getSemantics(find.bySemanticsLabel('Favorites, expanded'));
      final data = node.getSemanticsData();
      expect(data.flagsCollection.isButton, isTrue);
      expect(data.flagsCollection.isExpanded.toString(), contains('isTrue'));
      await tester.tapAt(Offset(r.right - 80, r.center.dy));
      await tester.pumpAndSettle();
      expect(find.bySemanticsLabel('Favorites, collapsed'), findsOneWidget);
      h.dispose();
      r = tester.getRect(heading);
      // A hold opens the dialog.
      await tester.longPressAt(Offset(r.right - 80, r.center.dy));
      await tester.pumpAndSettle();
      expect(find.text('Home sections'), findsOneWidget);
    });
  });
}
