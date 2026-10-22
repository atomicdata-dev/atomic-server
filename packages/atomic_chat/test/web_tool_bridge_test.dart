import 'dart:async';
import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

Map<String, dynamic> _text(String t) => {
      'choices': [
        {
          'delta': {'content': t}
        }
      ]
    };

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

class _Fake {
  final List<Stream<Map<String, dynamic>> Function()> steps;
  final requests = <List<Map<String, dynamic>>>[];
  final toolLists = <List<Map<String, dynamic>>?>[];
  _Fake(this.steps);

  HostedAi ai() => HostedAi(
        status: {'enabled': true, 'consent': true, 'model': 'm'},
        completions: (messages, model, tools) {
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

class _Bridge implements WebToolBridge {
  _Bridge({
    this.tools = const [
      ToolDef(
        name: 'create_resource',
        description: 'Creates a resource.',
        parameters: {
          'type': 'object',
          'properties': {
            'jsonAD': {'type': 'string'}
          },
        },
      ),
      ToolDef(
        name: 'semantic_search',
        description: 'The web search.',
        parameters: {'type': 'object', 'properties': {}},
      ),
    ],
    this.onRun,
  });

  final List<ToolDef> tools;
  final String prompt = 'WEB PROMPT';
  Object? listError;
  Object? promptError;
  final Future<String> Function(String name, Map<String, dynamic> args)? onRun;
  final ran = <(String, Map<String, dynamic>)>[];

  @override
  Future<List<ToolDef>> listTools() async {
    if (listError != null) throw listError!;
    return tools;
  }

  @override
  Future<String> systemPrompt() async {
    if (promptError != null) throw promptError!;
    return prompt;
  }

  @override
  Future<String> run(String name, Map<String, dynamic> args) async {
    ran.add((name, args));
    return onRun != null ? onRun!(name, args) : '{"ok":true}';
  }
}

AiTool _local(String name, List<String> log) => AiTool(
      name: name,
      description: 'local $name',
      parameters: const {'type': 'object', 'properties': {}},
      execute: (input) async {
        log.add(name);
        return {'local': name};
      },
    );

final _history = [
  ChatEntry.text((id: 'u', role: 'user', text: 'Make a note', createdAt: 0)),
];

Future<List<AiEvent>> _run(_Fake fake,
        {WebToolBridge? bridge, List<AiTool> tools = const []}) =>
    fake.ai().run(_history, tools: tools, bridge: bridge).toList();

void main() {
  group('HostedAi.run with a web tool bridge', () {
    test('offers the web tools, sends {name, args} and feeds the text back',
        () async {
      final bridge = _Bridge(onRun: (n, a) async => '{"created":"did:ad:x"}');
      final fake = _Fake([
        () => Stream.fromIterable([
              _call(0,
                  id: 'c1',
                  name: 'create_resource',
                  args: '{"jsonAD":"{\\"name\\":\\"N\\"}"}'),
            ]),
        () => Stream.fromIterable([_text('Done.')]),
      ]);
      final events = await _run(fake, bridge: bridge);
      // The web app's definitions, as the account's AI takes them.
      expect(fake.toolLists.first, [
        {
          'type': 'function',
          'function': {
            'name': 'create_resource',
            'description': 'Creates a resource.',
            'parameters': bridge.tools.first.parameters,
          },
        },
        {
          'type': 'function',
          'function': {
            'name': 'semantic_search',
            'description': 'The web search.',
            'parameters': bridge.tools.last.parameters,
          },
        },
      ]);
      expect(bridge.ran.map((r) => r.$1), ['create_resource']);
      expect(bridge.ran.single.$2, {'jsonAD': '{"name":"N"}'});
      final finished = events.whereType<AiToolFinished>().single.part;
      expect(finished.state, ToolState.outputAvailable);
      expect(finished.output, '{"created":"did:ad:x"}');
      // The text goes to the model as it is, not encoded again.
      expect(fake.requests[1].last, {
        'role': 'tool',
        'tool_call_id': 'c1',
        'content': '{"created":"did:ad:x"}'
      });
    });

    test('the web prompt is the system message; the short one is the fallback',
        () async {
      final fake = _Fake([
        () => Stream.fromIterable([_text('a')]),
        () => Stream.fromIterable([_text('b')]),
      ]);
      await _run(fake, bridge: _Bridge());
      expect(
          fake.requests[0].first, {'role': 'system', 'content': 'WEB PROMPT'});

      final noPrompt = _Bridge()..promptError = StateError('no');
      await _run(fake, bridge: noPrompt);
      final system = fake.requests[1].first['content'] as String;
      expect(system, startsWith('You are the assistant in atomic.place'));
      // The web tools are still offered.
      expect(fake.toolLists[1], hasLength(2));
    });

    test('falls back to the built-in tools and prompt when the page fails',
        () async {
      final log = <String>[];
      final bridge = _Bridge()..listError = TimeoutException('page');
      final fake = _Fake([
        () => Stream.fromIterable([_call(0, id: 'c', name: 'a', args: '{}')]),
        () => Stream.fromIterable([_text('ok')]),
      ]);
      await _run(fake, bridge: bridge, tools: [_local('a', log)]);
      expect(log, ['a']);
      expect(bridge.ran, isEmpty);
      expect(fake.requests[0].first['content'],
          startsWith('You are the assistant in atomic.place'));
      expect([for (final t in fake.toolLists.first!) t['function']['name']],
          ['a']);
    });

    test('an empty tool list also falls back', () async {
      final log = <String>[];
      final fake = _Fake([
        () => Stream.fromIterable([_text('ok')]),
      ]);
      await _run(fake,
          bridge: _Bridge(tools: const []), tools: [_local('a', log)]);
      expect([for (final t in fake.toolLists.first!) t['function']['name']],
          ['a']);
    });

    test('built-in tools the web app lacks are kept; same names are the web\'s',
        () async {
      final log = <String>[];
      final fake = _Fake([
        () => Stream.fromIterable([_text('ok')]),
      ]);
      await _run(fake,
          bridge: _Bridge(),
          tools: [_local('semantic_search', log), _local('extra', log)]);
      expect([for (final t in fake.toolLists.first!) t['function']['name']],
          ['create_resource', 'semantic_search', 'extra']);
      expect(fake.toolLists.first![1]['function']['description'],
          'The web search.');
    });

    test(
        '{"error"} results, thrown errors and timeouts are failures the '
        'model hears of; the loop goes on', () async {
      final previous = HostedAi.toolTimeout;
      HostedAi.toolTimeout = const Duration(milliseconds: 50);
      addTearDown(() => HostedAi.toolTimeout = previous);
      final bridge = _Bridge(onRun: (name, args) async {
        switch (args['n']) {
          case 1:
            return '{"error":"No such parent"}';
          case 2:
            throw StateError('page gone');
          default:
            return Completer<String>().future;
        }
      });
      final fake = _Fake([
        () => Stream.fromIterable([
              _call(0, id: 'a', name: 'create_resource', args: '{"n":1}'),
              _call(1, id: 'b', name: 'create_resource', args: '{"n":2}'),
              _call(2, id: 'c', name: 'create_resource', args: '{"n":3}'),
            ]),
        () => Stream.fromIterable([_text('Sorry.')]),
      ]);
      final events = await _run(fake, bridge: bridge);
      final parts = [
        for (final e in events.whereType<AiToolFinished>()) e.part
      ];
      expect(parts.map((p) => p.state), everyElement(ToolState.outputError));
      expect(parts[0].errorText, 'No such parent');
      expect(parts[1].errorText, 'page gone');
      expect(parts[2].errorText, contains('stopped'));
      final tools = fake.requests[1].where((m) => m['role'] == 'tool').toList();
      expect(tools.map((m) => m['content']), [
        'Error: No such parent',
        'Error: page gone',
        contains('Error: The tool took longer'),
      ]);
      expect((events.last as AiTextDelta).text, 'Sorry.');
    });

    test('arguments that are not JSON are reported, the page is not called',
        () async {
      final bridge = _Bridge();
      final fake = _Fake([
        () => Stream.fromIterable([
              _call(0, id: 'a', name: 'create_resource', args: '{"jsonAD": '),
            ]),
        () => Stream.fromIterable([_text('Again.')]),
      ]);
      final events = await _run(fake, bridge: bridge);
      expect(bridge.ran, isEmpty);
      final part = events.whereType<AiToolFinished>().single.part;
      expect(part.errorText, contains('not valid JSON'));
    });
  });

  group('AiCallChannel', () {
    test('runs aiCall in the page and resolves on the aiResult message',
        () async {
      final scripts = <String>[];
      final channel = AiCallChannel(runScript: (js) async => scripts.add(js));
      final answer = channel.call('run', ['get_schema', '{"a":1}']);
      await pumpEventQueue();
      expect(scripts,
          ['window.atomicEmbed.aiCall(1,"run",["get_schema","{\\"a\\":1}"])']);
      expect(
          channel.handleMessage(jsonEncode(
              {'method': 'aiResult', 'callId': 1, 'ok': true, 'payload': 'P'})),
          isTrue);
      expect(await answer, 'P');
    });

    test('a failed answer throws, a late or foreign message is ignored',
        () async {
      final channel = AiCallChannel(runScript: (js) async {});
      final answer = channel.call('tools', const []);
      await pumpEventQueue();
      expect(channel.handleMessage('{"id":3,"method":"getResource"}'), isFalse);
      expect(channel.handleMessage('not json "aiResult"'), isFalse);
      channel.handleMessage(jsonEncode(
          {'method': 'aiResult', 'callId': 1, 'ok': false, 'payload': 'boom'}));
      await expectLater(answer, throwsA(isA<StateError>()));
      // Nobody waits for it any more.
      expect(
          channel.handleMessage(jsonEncode(
              {'method': 'aiResult', 'callId': 1, 'ok': true, 'payload': 'x'})),
          isTrue);
    });

    test('no answer times out; close fails what waits', () async {
      final channel = AiCallChannel(runScript: (js) async {});
      await expectLater(
          channel.call('prompt', const [],
              timeout: const Duration(milliseconds: 20)),
          throwsA(isA<TimeoutException>()));
      final waiting = channel.call('prompt', const []);
      await pumpEventQueue();
      channel.close('gone');
      await expectLater(waiting, throwsA(isA<StateError>()));
    });

    test('calls wait for the page to be ready', () async {
      final ready = Completer<void>();
      final scripts = <String>[];
      final channel = AiCallChannel(
          runScript: (js) async => scripts.add(js), ready: ready.future);
      unawaited(channel.call('tools', const []).catchError((Object _) => ''));
      await pumpEventQueue();
      expect(scripts, isEmpty);
      ready.complete();
      await pumpEventQueue();
      expect(scripts, hasLength(1));
    });
  });

  group('ChannelToolBridge', () {
    test('lists the page\'s tools once, skipping malformed entries', () async {
      var asked = 0;
      late final AiCallChannel channel;
      channel = AiCallChannel(runScript: (js) async {
        asked++;
        final id = int.parse(RegExp(r'aiCall\((\d+)').firstMatch(js)![1]!);
        channel.handleMessage(jsonEncode({
          'method': 'aiResult',
          'callId': id,
          'ok': true,
          'payload': jsonEncode([
            {
              'name': 'get_schema',
              'description': 'Reads a schema.',
              'parameters': {'type': 'object', 'properties': {}},
            },
            {'description': 'no name'},
            'junk',
          ]),
        }));
      });
      final bridge = ChannelToolBridge(channel);
      final tools = await bridge.listTools();
      expect(tools.map((t) => t.name), ['get_schema']);
      expect(tools.single.description, 'Reads a schema.');
      await bridge.listTools();
      expect(asked, 1);
      bridge.invalidate();
      await bridge.listTools();
      expect(asked, 2);
    });
  });

  group('WebViewToolBridge', () {
    test('loads the page as ?ai=1&drive=… and answers its store calls',
        () async {
      final api = _StoreApi();
      late _FakePage page;
      Uri? loaded;
      WebViewToolBridge.pageFactory = (url, onMessage) async {
        loaded = url;
        return page = _FakePage(onMessage);
      };
      addTearDown(() => WebViewToolBridge.pageFactory = null);
      final bridge =
          WebViewToolBridge(api: api, drive: () async => 'did:ad:drive');
      final prompt = await bridge.systemPrompt();
      expect(prompt, 'prompt of the page');
      expect(loaded!.queryParameters, {'ai': '1', 'drive': 'did:ad:drive'});
      // The page reads the store while it runs a tool: answered by the API.
      final result = await bridge.run('get_atomic_resource', {'a': 1});
      expect(result, '{"got":{"a":1}}');
      expect(api.calls, [('getResource', '["did:ad:x"]')]);
      expect(page.replies,
          ['window.__atomicReply(7,true,"{\\"title\\":\\"T\\"}")']);
      bridge.close();
      expect(page.released, isTrue);
    });
  });
}

class _StoreApi extends UnimplementedApi {
  final calls = <(String, String)>[];
  @override
  Future<String> embedCall(String method, String argsJson) async {
    calls.add((method, argsJson));
    return '{"title":"T"}';
  }
}

/// A page that answers `aiCall`s as the embed does.
class _FakePage implements WarmPage {
  _FakePage(this._send);
  final void Function(String) _send;
  final replies = <String>[];
  bool released = false;

  @override
  bool get isReady => true;
  @override
  Future<void> get whenReady => Future.value();
  @override
  set onMessage(void Function(String message)? handler) {}
  @override
  set onLoaded(VoidCallback? handler) {}
  @override
  void release() => released = true;
  @override
  Widget build() => const SizedBox();
  @override
  Future<Object> runJavaScriptReturningResult(String script) async => '';

  @override
  Future<void> runJavaScript(String script) async {
    final m = RegExp(r'aiCall\((\d+),"(\w+)",(.*)\)$').firstMatch(script);
    if (m == null) {
      replies.add(script);
      return;
    }
    final id = int.parse(m[1]!);
    void answer(String payload) => _send(jsonEncode(
        {'method': 'aiResult', 'callId': id, 'ok': true, 'payload': payload}));
    switch (m[2]) {
      case 'prompt':
        answer('prompt of the page');
      case 'run':
        // The tool reads the resource through the store first.
        _send(jsonEncode({
          'id': 7,
          'method': 'getResource',
          'args': ['did:ad:x'],
        }));
        await pumpEventQueue();
        final args = jsonDecode((jsonDecode(m[3]!) as List)[1] as String);
        answer(jsonEncode({'got': args}));
    }
  }
}
