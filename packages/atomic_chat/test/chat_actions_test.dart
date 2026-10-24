import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

Map<String, dynamic> _text(String t) => {
      'choices': [
        {
          'delta': {'content': t}
        }
      ]
    };

bool _isTitle(List<Map<String, dynamic>> messages) =>
    (messages.first['content'] as String).contains('titles');

ChatEntry _entry(String id, String role, String text) =>
    ChatEntry(id: id, role: role, createdAt: 1000, parts: [TextPart(text)]);

class _Api extends UnimplementedApi {
  _Api(this.ai, [List<ChatEntry> stored = const []]) : stored = List.of(stored);
  final HostedAi ai;
  final List<ChatEntry> stored;
  final renamed = <(String, String)>[];

  @override
  Future<HostedAi?> hostedAi() async => ai;
  @override
  Future<List<ChatMessage>> messages(String chat) async => const [];
  @override
  Future<List<ChatEntry>> chatEntries(String chat) async => stored;
  @override
  Future<String> newChat(String name) async => 'did:ad:chat';
  @override
  Future<void> addMessage(String chat, String role, String text) async {}
  @override
  Future<void> addEntry(String chat, String role, List<ChatPart> parts) async {}
  @override
  Future<void> renameResource(String subject, String name) async =>
      renamed.add((subject, name));
}

/// An AI whose answers are [answer]'s results in turn; a title request gets
/// [title] (it throws when that is null).
HostedAi _ai(
  List<List<Map<String, dynamic>>> asked, {
  required Stream<Map<String, dynamic>> Function(int n) answer,
  String? title,
  Map<String, dynamic> status = const {},
  Uri? portal,
}) {
  var n = 0;
  return HostedAi(
    status: {'enabled': true, 'consent': true, 'model': 'm', ...status},
    portal: portal,
    completions: (messages, model, tools) {
      if (_isTitle(messages)) {
        return title == null
            ? Stream.error(StateError('no title'))
            : Stream.value(_text(title));
      }
      asked.add(messages);
      return answer(n++);
    },
    enable: () async => {},
  );
}

Future<void> _open(WidgetTester tester, _Api api,
    {String? subject, String title = ''}) async {
  await tester.pumpWidget(MaterialApp(
    theme: ThemeData(extensions: [AppColors.light]),
    home: ChatScreen(
        api: api, subject: subject, title: title, toolBridge: _NoBridge()),
  ));
  await tester.pumpAndSettle();
}

class _NoBridge implements WebToolBridge {
  @override
  Future<List<ToolDef>> listTools() async => const [];
  @override
  Future<String> systemPrompt() async => 'WEB PROMPT';
  @override
  Future<String> run(String name, Map<String, dynamic> args) async => '{}';
}

Future<void> _ask(WidgetTester tester, String text) async {
  await tester.enterText(find.byType(TextField), text);
  await tester.pump();
  await tester.tap(find.byTooltip('Send'));
  await tester.pumpAndSettle();
}

Future<void> _longPress(WidgetTester tester, String id) async {
  await tester.longPress(find.byKey(Key('message-$id')));
  await tester.pumpAndSettle();
}

void main() {
  final chat = [
    _entry('q', 'user', 'What is Atomic?'),
    _entry('a', 'assistant', 'First answer')
  ];

  group('message actions', () {
    testWidgets('Regenerate drops the last reply and asks the question again',
        (tester) async {
      final asked = <List<Map<String, dynamic>>>[];
      final api = _Api(
          _ai(asked, answer: (n) => Stream.value(_text('Second answer'))),
          chat);
      await _open(tester, api, subject: 'did:ad:chat');
      expect(find.text('First answer'), findsOneWidget);

      await _longPress(tester, 'a');
      await tester.tap(find.text('Regenerate response'));
      await tester.pumpAndSettle();

      expect(find.text('First answer'), findsNothing);
      expect(find.text('Second answer'), findsOneWidget);
      expect(find.text('What is Atomic?'), findsOneWidget);
      final sent = [
        for (final m in asked.single)
          if (m['role'] != 'system') m['content'],
      ];
      expect(sent, ['What is Atomic?']);
    });

    testWidgets('only the last reply can be regenerated', (tester) async {
      final api = _Api(_ai([], answer: (n) => Stream.value(_text('x'))), chat);
      await _open(tester, api, subject: 'did:ad:chat');
      await _longPress(tester, 'q');
      expect(find.text('Regenerate response'), findsNothing);
      expect(find.text('Copy message'), findsOneWidget);
    });

    testWidgets('Hide takes a message off the screen', (tester) async {
      final api = _Api(_ai([], answer: (n) => Stream.value(_text('x'))), chat);
      await _open(tester, api, subject: 'did:ad:chat');
      await _longPress(tester, 'a');
      await tester.tap(find.text('Hide message'));
      await tester.pumpAndSettle();
      expect(find.text('First answer'), findsNothing);
      expect(find.text('What is Atomic?'), findsOneWidget);
    });

    testWidgets('Copy puts the message text on the clipboard', (tester) async {
      final copied = <String>[];
      tester.binding.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
        if (call.method == 'Clipboard.setData') {
          copied.add((call.arguments as Map)['text'] as String);
        }
        return null;
      });
      addTearDown(() => tester.binding.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, null));
      final api = _Api(_ai([], answer: (n) => Stream.value(_text('x'))), chat);
      await _open(tester, api, subject: 'did:ad:chat');
      await _longPress(tester, 'a');
      await tester.tap(find.text('Copy message'));
      await tester.pumpAndSettle();
      expect(copied, ['First answer']);
    });
  });

  group('errors', () {
    testWidgets('a failure is readable and Try again asks again',
        (tester) async {
      final asked = <List<Map<String, dynamic>>>[];
      final api = _Api(_ai(asked,
          answer: (n) => n == 0
              ? Stream.error(StateError('Included AI is unavailable (500)'))
              : Stream.value(_text('Now it works'))));
      await _open(tester, api);
      await _ask(tester, 'Hello');

      expect(
          find.textContaining('No answer from Included AI: Included AI is '
              'unavailable (500)'),
          findsOneWidget);
      expect(find.textContaining('Bad state'), findsNothing);
      expect(find.byKey(const Key('chat-buy-credits')), findsNothing);

      await tester.tap(find.byKey(const Key('chat-retry')));
      await tester.pumpAndSettle();
      expect(find.text('Now it works'), findsOneWidget);
      expect(find.byKey(const Key('chat-error')), findsNothing);
      // The question was not added a second time.
      expect(
          find.descendant(
              of: find.byType(ListView), matching: find.text('Hello')),
          findsOneWidget);
      expect(asked.length, 2);
    });

    testWidgets('out of credits explains and links to buy more',
        (tester) async {
      final api = _Api(_ai([],
          answer: (n) => Stream.error(StateError('Not enough AI credits')),
          status: {'purchases_enabled': true, 'remaining_micros': 5},
          portal: Uri.parse('https://atomic.place')));
      await _open(tester, api);
      await _ask(tester, 'Hello');
      expect(find.textContaining('your credits have run out'), findsOneWidget);
      expect(find.byKey(const Key('chat-buy-credits')), findsOneWidget);
      expect(find.byKey(const Key('chat-retry')), findsOneWidget);
    });

    testWidgets('no credits left is said before sending, with the link',
        (tester) async {
      final api = _Api(_ai([],
          answer: (n) => Stream.value(_text('x')),
          status: {'purchases_enabled': true, 'remaining_micros': 0},
          portal: Uri.parse('https://atomic.place')));
      await _open(tester, api);
      expect(find.byKey(const Key('chat-no-credits')), findsOneWidget);
      expect(find.byKey(const Key('chat-buy-credits')), findsOneWidget);
    });

    test('credits url is the portal dashboard when purchases are on', () {
      HostedAi make(bool on, Uri? portal) => HostedAi(
            status: {'enabled': true, 'purchases_enabled': on},
            portal: portal,
            completions: (m, model, t) => const Stream.empty(),
            enable: () async => {},
          );
      expect(make(true, Uri.parse('https://atomic.place')).creditsUrl,
          Uri.parse('https://atomic.place/dashboard'));
      expect(make(false, Uri.parse('https://atomic.place')).creditsUrl, isNull);
      expect(make(true, null).creditsUrl, isNull);
    });
  });

  group('chat title', () {
    testWidgets('the first answer names the chat with the AI', (tester) async {
      final api = _Api(_ai([],
          answer: (n) => Stream.value(_text('Sure')),
          title: '"Bakery plans"\n'));
      await _open(tester, api);
      await _ask(tester, 'Help me with my bakery');
      expect(api.renamed, [('did:ad:chat', 'Bakery plans')]);
      expect(find.text('Bakery plans'), findsOneWidget);
    });

    testWidgets('without a generated title the first words stay',
        (tester) async {
      final api = _Api(_ai([], answer: (n) => Stream.value(_text('Sure'))));
      await _open(tester, api);
      await _ask(tester, 'Help me with my bakery');
      expect(api.renamed, isEmpty);
      expect(find.text('Untitled chat'), findsOneWidget);
    });

    testWidgets('the title can be renamed from the chat screen',
        (tester) async {
      final api = _Api(_ai([], answer: (n) => Stream.value(_text('x'))), chat);
      await _open(tester, api, subject: 'did:ad:chat');
      await tester.tap(find.byKey(const Key('chat-title')));
      await tester.pumpAndSettle();
      await tester.enterText(
          find.byKey(const Key('rename-field')), 'Atomic Q&A');
      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();
      expect(api.renamed, [('did:ad:chat', 'Atomic Q&A')]);
      expect(find.text('Atomic Q&A'), findsOneWidget);
    });
  });

  group('reasoning', () {
    testWidgets('a reply with reasoning shows it folded away', (tester) async {
      final reply =
          ChatEntry(id: 'r', role: 'assistant', createdAt: 1000, parts: const [
        RawPart({'type': 'reasoning', 'text': 'Let me think it over'}),
        TextPart('The answer'),
      ]);
      final api = _Api(_ai([], answer: (n) => Stream.value(_text('x'))),
          [_entry('q', 'user', 'Hm?'), reply]);
      await _open(tester, api, subject: 'did:ad:chat');
      expect(find.text('The answer'), findsOneWidget);
      expect(find.text('Thinking'), findsOneWidget);
      expect(find.text('Let me think it over'), findsNothing);

      await tester.tap(find.byKey(const Key('reasoning-row')));
      await tester.pumpAndSettle();
      expect(find.text('Let me think it over'), findsOneWidget);
    });
  });
}
