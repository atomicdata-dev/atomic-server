import 'dart:async';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

Map<String, dynamic> _text(String t) => {
      'choices': [
        {
          'delta': {'content': t}
        }
      ]
    };

Map<String, dynamic> _call(String name) => {
      'choices': [
        {
          'delta': {
            'tool_calls': [
              {
                'index': 0,
                'id': 'c1',
                'function': {'name': name, 'arguments': '{}'},
              }
            ]
          }
        }
      ]
    };

/// A bridge whose page takes [boot] to come up.
class _SlowBridge implements WebToolBridge {
  _SlowBridge(this.boot);
  final Completer<void> boot;
  int listed = 0;
  final ran = <String>[];

  @override
  Future<List<ToolDef>> listTools() async {
    listed++;
    await boot.future;
    return const [
      ToolDef(
          name: 'web_tool',
          description: 'd',
          parameters: {'type': 'object', 'properties': {}}),
    ];
  }

  @override
  Future<String> systemPrompt() async {
    await boot.future;
    return 'WEB PROMPT';
  }

  @override
  Future<String> run(String name, Map<String, dynamic> args) async {
    ran.add(name);
    return '{"ok":true}';
  }
}

class _Api extends UnimplementedApi {
  _Api(this.ai, this.gate);
  final HostedAi ai;
  final Future<void> gate;
  final saved = <String>[];

  @override
  Future<HostedAi?> hostedAi() async => ai;
  @override
  Future<List<ChatMessage>> messages(String chat) async => const [];
  @override
  Future<String> newChat(String name) async {
    await gate;
    return 'did:ad:chat';
  }

  @override
  Future<void> addMessage(String chat, String role, String text) async {
    await gate;
    saved.add(role);
  }

  @override
  Future<void> addEntry(String chat, String role, List<ChatPart> parts) async {
    await gate;
    saved.add(role);
  }
}

void main() {
  testWidgets(
      'the first chunk shows within 500 ms and the request goes out while '
      'saving and the tool bridge each take 5 s', (tester) async {
    final slow = Completer<void>();
    Timer(const Duration(seconds: 5), slow.complete);
    final bridge = _SlowBridge(slow);
    final requests = <(Duration, List<String>, String)>[];
    final clock = Stopwatch()..start();
    final ai = HostedAi(
      status: {'enabled': true, 'consent': true, 'model': 'm'},
      completions: (messages, model, tools) {
        requests.add((
          clock.elapsed,
          [for (final t in tools ?? const []) t['function']['name'] as String],
          messages.first['content'] as String,
        ));
        return Stream.value(_text('First words'));
      },
      enable: () async => {},
    );
    final api = _Api(ai, slow.future);
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: [AppColors.light]),
      home: ChatScreen(api: api, toolBridge: bridge),
    ));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'Hi');
    await tester.pump();
    await tester.tap(find.byTooltip('Send'));
    // One frame: the question is there, the dots show.
    await tester.pump();
    expect(find.text('Hi'), findsOneWidget);
    expect(find.byType(CircularProgressIndicator), findsOneWidget);

    await tester.pump(const Duration(milliseconds: 500));
    expect(requests, hasLength(1));
    expect(find.textContaining('First words'), findsWidgets);
    expect(api.saved, isEmpty);
    // Sent with the short prompt: the page is not up.
    expect(requests.single.$3, isNot('WEB PROMPT'));
    await tester.pump(const Duration(seconds: 6));
    await tester.pumpAndSettle();
  });

  group('HostedAi with a bridge that is still starting', () {
    test('the request goes out at once; the web tools join the next step',
        () async {
      final boot = Completer<void>();
      final bridge = _SlowBridge(boot);
      final seen = <(List<String>, String)>[];
      var step = 0;
      final ai = HostedAi(
        status: {'enabled': true, 'consent': true, 'model': 'm'},
        completions: (messages, model, tools) {
          seen.add((
            [
              for (final t in tools ?? const []) t['function']['name'] as String
            ],
            messages.first['content'] as String,
          ));
          return step++ == 0
              ? Stream.fromIterable([_call('local')])
              : Stream.value(_text('done'));
        },
        enable: () async => {},
      );
      final local = AiTool(
        name: 'local',
        description: 'd',
        parameters: const {'type': 'object', 'properties': {}},
        execute: (_) async {
          // The page comes up while the tool runs.
          boot.complete();
          await Future<void>.delayed(const Duration(milliseconds: 10));
          return {'ok': 1};
        },
      );
      final sw = Stopwatch()..start();
      final events = ai.run([
        ChatEntry.text((id: 'u', role: 'user', text: 'hi', createdAt: 0)),
      ], tools: [
        local
      ], bridge: bridge).toList();
      await events;
      expect(seen[0].$1, ['local']);
      expect(seen[0].$2, startsWith('You are the assistant'));
      expect(seen[1].$1, ['web_tool', 'local']);
      expect(seen[1].$2, 'WEB PROMPT');
      expect(sw.elapsedMilliseconds, lessThan(1000));
    });

    test('warmWeb reads the page once; the answer then finds it ready',
        () async {
      final boot = Completer<void>()..complete();
      final bridge = _SlowBridge(boot);
      final seen = <List<String>>[];
      final ai = HostedAi(
        status: {'enabled': true, 'consent': true, 'model': 'm'},
        completions: (messages, model, tools) {
          seen.add([for (final t in tools ?? const []) t['function']['name']]);
          return Stream.value(_text('x'));
        },
        enable: () async => {},
      );
      final previous = HostedAi.webGrace;
      HostedAi.webGrace = Duration.zero;
      addTearDown(() => HostedAi.webGrace = previous);
      ai.warmWeb(bridge);
      await Future<void>.delayed(Duration.zero);
      final h = [
        ChatEntry.text((id: 'u', role: 'user', text: 'a', createdAt: 0))
      ];
      await ai.run(h, bridge: bridge).toList();
      await ai.run(h, bridge: bridge).toList();
      expect(seen, [
        ['web_tool'],
        ['web_tool']
      ]);
      expect(bridge.listed, 1);
    });
  });
}
