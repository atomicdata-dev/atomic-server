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

Widget _host(Widget child) => MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: Scaffold(body: Column(children: [child])),
    );

class _PicApi extends FakeApi {
  final Map<String, Uint8List> files;
  final List<String> asked2 = [];
  _PicApi({this.files = const {}, super.conversationList, super.driveList,
      super.favoriteList, super.lastMessages, super.notificationList});

  @override
  Future<Uint8List?> fileBytes(String file) async {
    asked2.add(file);
    return files[file];
  }
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    RowPictures.clear();
    RowPictures.loader = null;
  });

  testWidgets('bytes show an image, an emoji shows text, nothing the icon',
      (tester) async {
    await tester.pumpWidget(_host(RowLeading(
        image: ImageSource(bytes: _png), fallbackIcon: Icons.folder_outlined)));
    expect(find.byKey(const Key('row-picture')), findsOneWidget);

    await tester.pumpWidget(_host(const RowLeading(
        image: ImageSource.emoji('🦊'), fallbackIcon: Icons.folder_outlined)));
    expect(find.text('🦊'), findsOneWidget);
    expect(find.byKey(const Key('row-picture')), findsNothing);
    expect(find.byIcon(Icons.folder_outlined), findsNothing);

    await tester.pumpWidget(_host(
        const RowLeading(image: null, fallbackIcon: Icons.folder_outlined)));
    expect(find.byIcon(Icons.folder_outlined), findsOneWidget);
    expect(tester.getSize(find.byType(RowLeading)), const Size(32, 32));
  });

  testWidgets('a File is read lazily, once, and kept', (tester) async {
    var reads = 0;
    RowPictures.loader = (file) async {
      reads++;
      return _png;
    };
    Widget row() => _host(const RowLeading(
        image: ImageSource.file('did:ad:f1'),
        fallbackLabel: 'Bob',
        showInitial: true,
        shape: RowShape.circle,
        fallbackIcon: Icons.person));
    await tester.pumpWidget(row());
    // Until it is read the initial shows.
    expect(find.text('B'), findsOneWidget);
    expect(find.byKey(const Key('row-picture')), findsNothing);
    expect(reads, 0, reason: 'nothing is read before the row has stayed');
    await tester.pump(const Duration(milliseconds: 200));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 10));
    await tester.pump(const Duration(milliseconds: 10));
    expect(reads, 1);
    expect(find.byKey(const Key('row-picture')), findsOneWidget);
    // Built again (scrolled back): from the cache.
    await tester.pumpWidget(_host(const SizedBox()));
    await tester.pumpWidget(row());
    expect(find.byKey(const Key('row-picture')), findsOneWidget);
    expect(reads, 1);
  });

  testWidgets('a row scrolled past quickly reads nothing', (tester) async {
    var reads = 0;
    RowPictures.loader = (file) async {
      reads++;
      return _png;
    };
    await tester.pumpWidget(_host(const RowLeading(
        image: ImageSource.file('did:ad:f2'), fallbackIcon: Icons.folder)));
    await tester.pump(const Duration(milliseconds: 30));
    await tester.pumpWidget(_host(const SizedBox()));
    await tester.pump(const Duration(milliseconds: 300));
    expect(reads, 0);
  });

  testWidgets('a picture that is not an image keeps the fallback',
      (tester) async {
    await tester.pumpWidget(_host(RowLeading(
        image: ImageSource(bytes: Uint8List.fromList([1, 2, 3])),
        fallbackLabel: 'Zed',
        showInitial: true,
        fallbackIcon: Icons.person)));
    await tester.pump();
    await tester.pump();
    expect(find.text('Z'), findsOneWidget);
  });

  test('the host rows become pictures', () {
    final rows = AssistantJson.parseConversations(jsonEncode([
      {
        'subject': 'dm',
        'title': 'Bob',
        'class_name': 'conversation',
        'peer': {'subject': 'a', 'name': 'Bob', 'icon_file': 'f', 'image_url': 'https://x.test/b.png'},
      },
      {'subject': 'g', 'title': 'Bob, Carol', 'class_name': 'conversation', 'group': true},
      {'subject': 'me', 'title': 'Only you', 'class_name': 'conversation'},
    ]));
    expect(rows[0].resource.picture,
        const ResourcePicture(file: 'f', url: 'https://x.test/b.png', name: 'Bob', person: true));
    expect(rows[1].resource.picture?.group, true);
    expect(rows[2].resource.picture, isNull);
    final favs = AssistantJson.parseRecentResources(jsonEncode([
      {'subject': 'd', 'title': 'D', 'class_name': 'drive', 'icon_file': 'f2'},
      {'subject': 'e', 'title': 'E', 'class_name': 'drive', 'emoji': '🦊'},
    ]));
    expect(favs[0].picture?.file, 'f2');
    expect(favs[1].picture, isNull);
    final notes = AssistantJson.parseNotifications(jsonEncode([
      {'subject': 'n', 'actor_picture': {'name': 'Dora', 'icon_file': 'f3'}},
      {'subject': 'm'},
    ]));
    expect(notes[0].actor?.name, 'Dora');
    expect(notes[0].actor?.person, true);
    expect(notes[1].actor, isNull);
    final drives = AssistantJson.parseDrives(jsonEncode([
      {'subject': 'x', 'name': 'X', 'icon_file': 'f4'},
    ]));
    expect(drives[0].picture?.file, 'f4');
  });

  test('the initial colour is stable per name', () {
    expect(initialColor('Bob'), initialColor(' bob '));
    expect(initialColor('Bob'), isNot(initialColor('Alice')));
  });

  group('the home', () {
    final convo = (
      subject: 'did:ad:dm1',
      title: 'Bob',
      className: 'conversation',
      classUrl: 'https://atomicdata.dev/classes/Conversation',
      openedAt: 1000,
      emoji: null,
      picture: const ResourcePicture(file: 'did:ad:bobpic', name: 'Bob', person: true),
    );
    final noPic = (
      subject: 'did:ad:dm2',
      title: 'Carol',
      className: 'conversation',
      classUrl: 'https://atomicdata.dev/classes/Conversation',
      openedAt: 900,
      emoji: null,
      picture: const ResourcePicture(name: 'Carol', person: true),
    );
    final group = (
      subject: 'did:ad:g1',
      title: 'Bob, Carol',
      className: 'conversation',
      classUrl: 'https://atomicdata.dev/classes/Conversation',
      openedAt: 800,
      emoji: null,
      picture: const ResourcePicture(group: true),
    );
    final fav = (
      subject: 'did:ad:doc',
      title: 'Plain doc',
      className: 'document-v2',
      classUrl: '',
      openedAt: 0,
      emoji: null,
      picture: null,
    );
    final favEmoji = (
      subject: 'did:ad:doc2',
      title: 'Fox doc',
      className: 'document-v2',
      classUrl: '',
      openedAt: 0,
      emoji: '🦊',
      picture: null,
    );
    final favPic = (
      subject: 'did:ad:doc3',
      title: 'Pic doc',
      className: 'document-v2',
      classUrl: '',
      openedAt: 0,
      emoji: null,
      picture: const ResourcePicture(file: 'did:ad:docpic'),
    );

    testWidgets('DMs show the other member, favorites their own, the drive header its picture',
        (tester) async {
      tester.view.physicalSize = const Size(400, 3000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      final api = _PicApi(
        files: {'did:ad:bobpic': _png, 'did:ad:docpic': _png, 'did:ad:drvpic': _png},
        conversationList: [convo, noPic, group],
        lastMessages: const {},
        favoriteList: [fav, favEmoji, favPic],
        driveList: [
          (
            subject: 'did:ad:drive',
            name: 'Home',
            emoji: null,
            picture: const ResourcePicture(file: 'did:ad:drvpic')
          ),
          (subject: 'did:ad:d2', name: 'Plain drive', emoji: null, picture: null),
        ],
        notificationList: [
          (
            subject: 'n1',
            title: 'Dora wrote',
            body: 'hi',
            about: 'did:ad:x',
            kind: 'chat',
            occurredAt: DateTime.now().millisecondsSinceEpoch,
            read: false,
            actor: const ResourcePicture(name: 'Dora', person: true),
          ),
        ],
      );
      await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api)));
      await tester.pumpAndSettle();
      await tester.pump(const Duration(milliseconds: 300));
      await tester.pumpAndSettle();

      ResourceRow rowOf(String title) => tester.widget<ResourceRow>(
          find.ancestor(of: find.text(title), matching: find.byType(ResourceRow)).first);
      Finder inRow(String title, Finder what) => find.descendant(
          of: find.ancestor(of: find.text(title), matching: find.byType(ResourceRow)).first,
          matching: what);

      // Bob's picture was read through the bridge; Carol has none: initial.
      expect(api.asked2, containsAll(['did:ad:bobpic', 'did:ad:docpic', 'did:ad:drvpic']));
      expect(inRow('Bob', find.byKey(const Key('row-picture'))), findsOneWidget);
      expect(inRow('Carol', find.byKey(const Key('row-picture'))), findsNothing);
      expect(inRow('Carol', find.text('C')), findsOneWidget);
      expect(rowOf('Bob').shape, RowShape.circle);
      // A group: its own icon, no initial.
      expect(inRow('Bob, Carol', find.byIcon(Icons.groups_outlined)), findsOneWidget);
      // Resources.
      expect(inRow('Plain doc', find.byIcon(Icons.description_outlined)), findsOneWidget);
      expect(inRow('Fox doc', find.text('🦊')), findsOneWidget);
      expect(inRow('Pic doc', find.byKey(const Key('row-picture'))), findsOneWidget);
      expect(rowOf('Pic doc').shape, RowShape.square);
      // The current drive's picture is in the header.
      expect(
          find.descendant(
              of: find.byKey(const Key('current-drive-header')),
              matching: find.byKey(const Key('row-picture'))),
          findsOneWidget);
      // The notification shows the actor's initial.
      expect(inRow('Dora wrote', find.text('D')), findsOneWidget);

      // Every kind of row: the same leading slot and the same text x.
      final xs = <double>{};
      for (final t in ['Bob', 'Carol', 'Bob, Carol', 'Plain doc', 'Fox doc', 'Pic doc', 'Dora wrote']) {
        final lead = tester.getRect(inRow(t, find.byType(RowLeading)));
        expect(lead.size, const Size(32, 32), reason: t);
        expect(lead.left, 16, reason: t);
        xs.add(tester.getRect(find.text(t).first).left);
      }
      expect(xs.length, 1, reason: 'text starts at one x: $xs');
    });
  });
}
