import 'dart:convert';
import 'dart:typed_data';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

/// A 1x1 PNG.
final _png = base64Decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');

class _Picker extends AttachmentPicker {
  _Picker({this.images = const [], this.files = const []});
  final List<PickedFile> images;
  final List<PickedFile> files;
  @override
  bool get canTakePhoto => true;
  @override
  Future<List<PickedFile>> pickImages() async => images;
  @override
  Future<PickedFile?> takePhoto() async => images.firstOrNull;
  @override
  Future<List<PickedFile>> pickFiles() async => files;
}

class _Api extends UnimplementedApi {
  _Api({this.acceptsImages = false});
  final bool acceptsImages;
  final added = <(String, List<Map<String, dynamic>>)>[];
  final sent = <List<Map<String, dynamic>>>[];

  @override
  Future<HostedAi?> hostedAi() async => HostedAi(
        status: {'enabled': true, 'consent': true, 'model': 'm'},
        acceptsImages: acceptsImages,
        completions: (messages, model, tools) {
          sent.add([for (final m in messages) Map.of(m)]);
          return Stream.value({
            'choices': [
              {
                'delta': {'content': 'Got it.'}
              }
            ]
          });
        },
        enable: () async => {},
      );
  @override
  Future<List<DriveInfo>> drives() async =>
      const [(subject: 'did:ad:home', name: 'Home', emoji: null, picture: null)];
  @override
  Future<List<RecentResource>> recentResources(String drive) async => const [
        (
          subject: 'did:ad:notes',
          title: 'Meeting notes',
          className: 'document',
          classUrl: '',
          openedAt: 2,
          emoji: '📝', picture: null
        ),
      ];
  @override
  Future<List<SearchHit>> search(String query, {String? drive}) async => [
        (
          subject: 'did:ad:budget',
          title: 'Budget 2026',
          className: 'table',
          classUrl: '',
          drive: 'did:ad:home',
          score: 1,
          emoji: null, picture: null
        ),
      ];
  @override
  Future<String> resourceText(String subject, {int maxChars = 4000}) async =>
      'Contents of $subject';
  @override
  Future<String> newChat(String name) async => 'did:ad:chat';
  @override
  Future<void> addEntry(String chat, String role, List<ChatPart> parts) async =>
      added.add((role, [for (final p in parts) p.toJson()]));
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: [AppColors.light]),
      home: home,
    );

Future<void> _openSheet(WidgetTester tester) async {
  await tester.tap(find.byKey(const Key('chat-attach')));
  await tester.pumpAndSettle();
}

bool _enabled(WidgetTester tester, String key) =>
    tester.widget<ListTile>(find.byKey(Key(key))).enabled;

void main() {
  testWidgets(
      'a text file is attached as a chip, sent as its text and saved as a '
      'file part; the included AI cannot take photos', (tester) async {
    final api = _Api();
    final picker = _Picker(files: [
      PickedFile(
        name: 'todo.md',
        mediaType: 'text/markdown',
        bytes: Uint8List.fromList(utf8.encode('- buy milk')),
      ),
    ]);
    await tester.pumpWidget(
        _app(ChatScreen(api: api, attachmentPicker: picker, tools: const [])));
    await tester.pumpAndSettle();

    await _openSheet(tester);
    expect(_enabled(tester, 'attach-photos'), isFalse);
    expect(find.text('The included AI reads text only'), findsNWidgets(2));
    expect(_enabled(tester, 'attach-file'), isTrue);
    await tester.tap(find.byKey(const Key('attach-file')));
    await tester.pumpAndSettle();
    expect(find.text('todo.md'), findsOneWidget);

    // Sent with no text of its own.
    await tester.tap(find.byTooltip('Send'));
    await tester.pumpAndSettle();
    final user = api.sent.single.last;
    expect(user['role'], 'user');
    expect(user['content'], contains('- buy milk'));
    expect(api.added.first.$1, 'user');
    final part = api.added.first.$2.single;
    expect(part['type'], 'file');
    expect(part['filename'], 'todo.md');
    expect(part['url'], startsWith('data:text/markdown;base64,'));
    // In the bubble, and no longer above the field.
    expect(find.text('todo.md'), findsOneWidget);
    expect(find.text('Got it.'), findsOneWidget);
  });

  testWidgets('a file that is not text is refused, with why', (tester) async {
    final api = _Api();
    final picker = _Picker(files: [
      PickedFile(
          name: 'scan.pdf', mediaType: 'application/pdf', bytes: Uint8List(10)),
    ]);
    await tester.pumpWidget(
        _app(ChatScreen(api: api, attachmentPicker: picker, tools: const [])));
    await tester.pumpAndSettle();
    await _openSheet(tester);
    await tester.tap(find.byKey(const Key('attach-file')));
    await tester.pumpAndSettle();
    expect(find.textContaining("Can't read scan.pdf"), findsOneWidget);
    expect(find.byType(AttachmentChip), findsNothing);
  });

  testWidgets(
      'an AI that sees images gets a photo as an image part; the photo shows '
      'as a thumbnail, removable before sending', (tester) async {
    final api = _Api(acceptsImages: true);
    final picker = _Picker(images: [
      PickedFile(name: 'cat.png', mediaType: 'image/png', bytes: _png),
    ]);
    await tester.pumpWidget(
        _app(ChatScreen(api: api, attachmentPicker: picker, tools: const [])));
    await tester.pumpAndSettle();

    await _openSheet(tester);
    expect(_enabled(tester, 'attach-photos'), isTrue);
    expect(_enabled(tester, 'attach-camera'), isTrue);
    await tester.runAsync(() async {
      await tester.tap(find.byKey(const Key('attach-photos')));
      await Future<void>.delayed(const Duration(milliseconds: 200));
    });
    await tester.pumpAndSettle();
    expect(find.byType(AttachmentThumb), findsOneWidget);

    // Removed, and attached again from the camera.
    await tester.tap(find.bySemanticsLabel('Remove cat.png'));
    await tester.pumpAndSettle();
    expect(find.byType(AttachmentThumb), findsNothing);
    await _openSheet(tester);
    await tester.runAsync(() async {
      await tester.tap(find.byKey(const Key('attach-camera')));
      await Future<void>.delayed(const Duration(milliseconds: 200));
    });
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'What is this?');
    await tester.pump();
    await tester.tap(find.byTooltip('Send'));
    await tester.pumpAndSettle();
    final content = api.sent.single.last['content'] as List;
    expect(content[0], {'type': 'text', 'text': 'What is this?'});
    expect(content[1]['type'], 'image_url');
    expect((content[1]['image_url'] as Map)['url'],
        startsWith('data:image/png;base64,'));
    expect(api.added.first.$2.map((p) => p['type']), ['text', 'file']);
    // The sent bubble shows the photo.
    expect(find.byType(AttachmentThumb), findsOneWidget);
  });

  testWidgets(
      'from my drive: search, pick, and the resource goes along as context',
      (tester) async {
    final api = _Api();
    await tester.pumpWidget(_app(
        ChatScreen(api: api, attachmentPicker: _Picker(), tools: const [])));
    await tester.pumpAndSettle();
    await _openSheet(tester);
    await tester.tap(find.byKey(const Key('attach-drive')));
    await tester.pumpAndSettle();
    // Recent ones first.
    expect(find.text('Meeting notes'), findsWidgets);
    await tester.enterText(
        find.byKey(const Key('drive-picker-search')), 'budget');
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Budget 2026'));
    await tester.pumpAndSettle();
    expect(find.widgetWithText(Chip, 'Budget 2026'), findsOneWidget);

    await tester.enterText(find.byType(TextField), 'Summarize');
    await tester.pump();
    await tester.tap(find.byTooltip('Send'));
    await tester.pumpAndSettle();
    final context = api.sent.single[1];
    expect(context['role'], 'system');
    expect(context['content'], contains('Contents of did:ad:budget'));
    // The sent message shows what went along.
    expect(find.widgetWithText(AttachmentChip, 'Budget 2026'), findsOneWidget);
  });

  testWidgets('without a picker only drive resources can be attached',
      (tester) async {
    await tester.pumpWidget(_app(ChatScreen(api: _Api(), tools: const [])));
    await tester.pumpAndSettle();
    await _openSheet(tester);
    expect(_enabled(tester, 'attach-photos'), isFalse);
    expect(_enabled(tester, 'attach-camera'), isFalse);
    expect(_enabled(tester, 'attach-file'), isFalse);
    expect(_enabled(tester, 'attach-drive'), isTrue);
  });
}
