import 'dart:async';
import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

/// A completion chunk with text.
Map<String, dynamic> _text(String t) => {
      'choices': [
        {
          'delta': {'content': t}
        }
      ]
    };

/// A completion chunk with a piece of a tool call.
Map<String, dynamic> _call(int index,
        {String? id, String? name, String args = ''}) =>
    {
      'choices': [
        {
          'delta': {
            'tool_calls': [
              {
                'index': index,
                if (id != null) 'id': id,
                'type': 'function',
                'function': {if (name != null) 'name': name, 'arguments': args},
              }
            ]
          }
        }
      ]
    };

/// A fake account AI: each request gets the next of [steps]; what it was
/// sent is in [requests].
class _Fake {
  final List<Stream<Map<String, dynamic>> Function()> steps;
  final requests = <List<Map<String, dynamic>>>[];
  final toolLists = <List<Map<String, dynamic>>?>[];
  _Fake(this.steps);

  HostedAi ai() => HostedAi(
        status: {'enabled': true, 'consent': true, 'model': 'm'},
        completions: (messages, model, tools) {
          // A copy: the run adds to its list after the request.
          requests.add([
            for (final m in messages)
              jsonDecode(jsonEncode(m)) as Map<String, dynamic>,
          ]);
          toolLists.add(tools);
          return steps[requests.length - 1]();
        },
        enable: () async => {},
      );
}

class _Api extends UnimplementedApi {
  _Api(this.ai, {this.history = const []});
  final HostedAi ai;
  final List<ChatEntry> history;
  final added = <(String, List<Map<String, dynamic>>)>[];
  final searched = <String>[];

  @override
  Future<HostedAi?> hostedAi() async => ai;
  @override
  Future<List<ChatEntry>> chatEntries(String chat) async => history;
  @override
  Future<String> newChat(String name) async => 'did:ad:chat';
  @override
  Future<void> addEntry(String chat, String role, List<ChatPart> parts) async =>
      added.add((role, [for (final p in parts) p.toJson()]));
  @override
  Future<List<SearchHit>> search(String query, {String? drive}) async {
    searched.add(query);
    return [
      (
        subject: 'did:ad:lisbon',
        title: 'Lisbon trip',
        className: 'document',
        classUrl: '',
        drive: 'did:ad:d',
        score: 1,
        emoji: null, picture: null
      ),
    ];
  }

  @override
  Future<String> resourceText(String subject, {int maxChars = 4000}) async =>
      'Text of $subject';
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(extensions: [AppColors.light]),
      home: home,
    );

Future<void> _type(WidgetTester tester, String text) async {
  await tester.enterText(find.byType(TextField), text);
  await tester.pump();
  await tester.tap(find.byTooltip('Send'));
  await tester.pump();
}

List<AiEvent> _events = [];

void main() {
  group('HostedAi.run', () {
    test(
        'streams text, runs a tool split over chunks, and goes on with its '
        'result', () async {
      final fake = _Fake([
        () => Stream.fromIterable([
              _text('Let me look. '),
              _call(0, id: 'c1', name: 'semantic_search', args: '{"query":'),
              _call(0, args: '"Lisbon","description":"Searching for Lisbon"}'),
            ]),
        () => Stream.fromIterable([_text('Found '), _text('it.')]),
      ]);
      final api = _Api(fake.ai());
      _events = await fake.ai().run(
        [
          ChatEntry.text((id: 'u', role: 'user', text: 'Lisbon?', createdAt: 0))
        ],
        tools: assistantTools(api),
      ).toList();
      final kinds = _events.map((e) => e.runtimeType).toList();
      expect(kinds, [
        AiTextDelta,
        AiToolStarted,
        AiToolFinished,
        AiTextDelta,
        AiTextDelta,
      ]);
      final started = (_events[1] as AiToolStarted).part;
      expect(started.toolName, 'semantic_search');
      expect(started.input,
          {'query': 'Lisbon', 'description': 'Searching for Lisbon'});
      final finished = (_events[2] as AiToolFinished).part;
      expect(finished.state, ToolState.outputAvailable);
      expect(finished.output, [
        {
          'subject': 'did:ad:lisbon',
          'title': 'Lisbon trip',
          'chunk': 'Text of did:ad:lisbon'
        }
      ]);
      expect(api.searched, ['Lisbon']);
      // The second request has the call and its result.
      final second = fake.requests[1];
      final call = second[second.length - 2];
      expect(call['role'], 'assistant');
      expect(call['content'], 'Let me look. ');
      expect(call['tool_calls'][0]['function']['name'], 'semantic_search');
      expect(second.last['role'], 'tool');
      expect(second.last['tool_call_id'], 'c1');
      expect(jsonDecode(second.last['content'] as String), finished.output);
      // Tools are offered, by the web app's names.
      expect([for (final t in fake.toolLists.first!) t['function']['name']],
          ['semantic_search', 'get_atomic_resource']);
    });

    test('an unknown tool and a failing tool are failures the model hears of',
        () async {
      final fake = _Fake([
        () => Stream.fromIterable([
              _call(0, id: 'a', name: 'delete_everything', args: '{}'),
              _call(1, id: 'b', name: 'get_atomic_resource', args: '{}'),
            ]),
        () => Stream.fromIterable([_text('Sorry.')]),
      ]);
      final api = _Api(fake.ai());
      final events = await fake.ai().run(
          [ChatEntry.text((id: 'u', role: 'user', text: 'x', createdAt: 0))],
          tools: assistantTools(api)).toList();
      final failed = [
        for (final e in events)
          if (e is AiToolFinished) e.part,
      ];
      expect(failed.map((p) => p.state),
          [ToolState.outputError, ToolState.outputError]);
      expect(failed[0].errorText, 'Unknown tool delete_everything');
      expect(failed[1].errorText, 'No subjects given');
      expect(fake.requests[1].where((m) => m['role'] == 'tool').length, 2);
    });

    test('stops after the most rounds of tool calls', () async {
      final fake = _Fake([
        for (var i = 0; i < 20; i++)
          () => Stream.fromIterable([
                _call(0,
                    id: 'c$i', name: 'semantic_search', args: '{"query":"q"}'),
              ]),
      ]);
      final events = await fake.ai().run(
          [ChatEntry.text((id: 'u', role: 'user', text: 'x', createdAt: 0))],
          tools: assistantTools(_Api(fake.ai()))).toList();
      expect(fake.requests.length, HostedAi.maxSteps);
      expect(events.whereType<AiToolFinished>().length, HostedAi.maxSteps);
    });

    test('an error mid-stream ends the run with it', () async {
      final fake = _Fake([
        () async* {
          yield _text('Half');
          throw StateError('AI is busy. Try again shortly.');
        },
      ]);
      final seen = <AiEvent>[];
      await expectLater(
        fake.ai().run([
          ChatEntry.text((id: 'u', role: 'user', text: 'x', createdAt: 0))
        ]).forEach(seen.add),
        throwsA(isA<StateError>()),
      );
      expect(seen.single, isA<AiTextDelta>());
    });

    test(
        'history: tool parts go back as calls and results, an unfinished '
        'call as a note, a text file as text, an image as a note', () async {
      final fake = _Fake([
        () => Stream.fromIterable([_text('ok')])
      ]);
      await fake.ai().run([
        ChatEntry(id: 'u', role: 'user', createdAt: 0, parts: [
          const TextPart('Read this'),
          FilePart.bytes(utf8.encode('hello file'),
              mediaType: 'text/plain', filename: 'a.txt'),
          FilePart.bytes(utf8.encode('png'),
              mediaType: 'image/png', filename: 'p.png'),
        ]),
        const ChatEntry(id: 'a', role: 'assistant', createdAt: 1, parts: [
          ToolPart(
              toolCallId: 't1',
              toolName: 'semantic_search',
              state: ToolState.outputAvailable,
              input: {'query': 'q'},
              output: []),
          ToolPart(toolCallId: 't2', toolName: 'query'),
          TextPart('Nothing found.'),
        ]),
        ChatEntry.text((id: 'u2', role: 'user', text: 'Hm', createdAt: 2)),
      ]).toList();
      final sent = fake.requests.single;
      final user = sent[1]['content'] as List;
      expect(user[0], {'type': 'text', 'text': 'Read this'});
      expect(user[1]['text'], contains('hello file'));
      expect(user[2]['text'], contains('cannot see'));
      expect(sent[2]['tool_calls'][0]['id'], 't1');
      expect(sent[3], {'role': 'tool', 'tool_call_id': 't1', 'content': '[]'});
      expect(sent[4]['content'], contains('no recorded result'));
      expect(sent[4]['content'], contains('Nothing found.'));
      expect(sent.last, {'role': 'user', 'content': 'Hm'});
    });
  });

  group('parts', () {
    test('entries are read with all their parts, in the web format', () {
      final entries = AssistantJson.parseChatEntries(jsonEncode([
        {
          'id': 'p#1',
          'role': 'user',
          'c': 5,
          'ctx': jsonEncode([
            {'type': 'atomic-resource', 'subject': 'did:ad:doc'}
          ]),
          'parts': [
            {'type': 'text', 'text': 'Hi'},
            {
              'type': 'file',
              'url': 'data:text/plain;base64,${base64Encode(utf8.encode('x'))}',
              'mediaType': 'text/plain',
              'filename': 'x.txt'
            },
          ],
        },
        {
          'id': 'p#2',
          'role': 'assistant',
          'c': 6,
          'parts': [
            {'type': 'step-start'},
            {
              'type': 'tool-semantic_search',
              'toolCallId': 'c1',
              'state': 'output-error',
              'input': {'query': 'q'},
              'errorText': 'boom'
            },
            {'type': 'reasoning', 'text': 'hmm'},
            {'type': 'text', 'text': 'Done'},
          ],
        },
        {'id': 'p#3', 'role': 'system', 'parts': []},
      ]));
      expect(entries, hasLength(2));
      expect(entries[0].context.single.subject, 'did:ad:doc');
      final file = entries[0].parts[1] as FilePart;
      expect(file.text, 'x');
      final tool = entries[1].parts[1] as ToolPart;
      expect(tool.state, ToolState.outputError);
      expect(tool.toJson(), {
        'type': 'tool-semantic_search',
        'toolCallId': 'c1',
        'state': 'output-error',
        'input': {'query': 'q'},
        'errorText': 'boom',
      });
      // Parts not shown are kept as they were.
      expect(
          entries[1].parts[2].toJson(), {'type': 'reasoning', 'text': 'hmm'});
      expect(entries[1].text, 'Done');
    });

    test('labels for known tools and the fallback', () {
      expect(
          toolLabel(const ToolPart(
              toolCallId: '1',
              toolName: 'semantic_search',
              input: {'query': 'tea'})),
          'Searching your drives for “tea”');
      expect(
          toolLabel(
              const ToolPart(
                  toolCallId: '1',
                  toolName: 'get_atomic_resource',
                  state: ToolState.outputAvailable,
                  input: {
                    'subjects': ['did:ad:a']
                  }),
              titles: {'did:ad:a': 'Groceries'}),
          'Read Groceries');
      expect(
          toolLabel(const ToolPart(
              toolCallId: '1',
              toolName: 'run_plugin',
              state: ToolState.outputAvailable)),
          'Used tool run plugin');
    });
  });

  group('ChatScreen', () {
    testWidgets(
        'a tool call shows as a step that spins, then checks, and opens to '
        'its arguments and result; the answer is saved with its parts',
        (tester) async {
      final second = StreamController<Map<String, dynamic>>();
      final fake = _Fake([
        () => Stream.fromIterable([
              _call(0,
                  id: 'c1',
                  name: 'semantic_search',
                  args:
                      '{"query":"Lisbon","description":"Looking for Lisbon"}'),
            ]),
        () => second.stream,
      ]);
      final api = _Api(fake.ai());
      await tester.pumpWidget(_app(ChatScreen(api: api)));
      await tester.pumpAndSettle();
      await _type(tester, 'Where was Lisbon?');
      await tester.pump(const Duration(milliseconds: 50));

      expect(find.text('Looking for Lisbon'), findsOneWidget);
      expect(find.byIcon(Icons.check_rounded), findsOneWidget);
      second.add(_text('In **Portugal**, see [Lisbon trip](did:ad:lisbon).'));
      await tester.pump(const Duration(milliseconds: 50));
      expect(find.text('In Portugal, see Lisbon trip.'), findsOneWidget);

      await tester.tap(find.byKey(const Key('tool-step-c1')));
      await tester.pump();
      expect(find.byKey(const Key('tool-result-c1')), findsOneWidget);
      expect(find.text('1 result: Lisbon trip'), findsOneWidget);
      expect(find.textContaining('"query": "Lisbon"'), findsOneWidget);

      await second.close();
      await tester.pumpAndSettle();
      expect(api.added.map((a) => a.$1), ['user', 'assistant']);
      final saved = api.added.last.$2;
      expect(saved.map((p) => p['type']), ['tool-semantic_search', 'text']);
      expect(saved.first['state'], 'output-available');
    });

    testWidgets('a running step spins; Stop marks it stopped and keeps it',
        (tester) async {
      final gate = Completer<List<SearchHit>>();
      final fake = _Fake([
        () => Stream.fromIterable([
              _call(0,
                  id: 'c1', name: 'semantic_search', args: '{"query":"x"}'),
            ]),
      ]);
      final api = _SlowSearch(fake.ai(), gate.future);
      await tester.pumpWidget(_app(ChatScreen(api: api)));
      await tester.pumpAndSettle();
      await _type(tester, 'Search');
      await tester.pump(const Duration(milliseconds: 50));
      expect(find.text('Searching your drives for “x”…'), findsOneWidget);

      await tester.tap(find.byKey(const Key('chat-stop')));
      await tester.pumpAndSettle();
      expect(find.byIcon(Icons.close_rounded), findsOneWidget);
      expect(api.added.last.$2.single['errorText'], 'Stopped');
      gate.complete(const []);
    });

    testWidgets('history shows tool steps as the web stored them',
        (tester) async {
      final api = _Api(
        _Fake([]).ai(),
        history: const [
          ChatEntry(
              id: 'p#1',
              role: 'user',
              createdAt: 1,
              parts: [TextPart('Make a table')]),
          ChatEntry(id: 'p#2', role: 'assistant', createdAt: 2, parts: [
            ToolPart(
                toolCallId: 'w1',
                toolName: 'create_table',
                state: ToolState.outputAvailable,
                input: {'name': 'Books'},
                output: 'Created'),
            ToolPart(
                toolCallId: 'w2',
                toolName: 'mystery_tool',
                state: ToolState.outputError,
                errorText: 'nope'),
            TextPart('# Done\n\n- Books'),
          ]),
        ],
      );
      await tester.pumpWidget(
          _app(ChatScreen(api: api, subject: 'did:ad:chat', title: 'Old')));
      await tester.pumpAndSettle();
      expect(find.text('Created table Books'), findsOneWidget);
      expect(find.text('Used tool mystery tool'), findsOneWidget);
      expect(find.byIcon(Icons.close_rounded), findsOneWidget);
      expect(find.text('Done'), findsOneWidget);
      await tester.tap(find.byKey(const Key('tool-step-w2')));
      await tester.pump();
      expect(find.text('nope'), findsOneWidget);
    });
  });
}

class _SlowSearch extends _Api {
  _SlowSearch(super.ai, this.gate);
  final Future<List<SearchHit>> gate;
  @override
  Future<List<SearchHit>> search(String query, {String? drive}) => gate;
}
