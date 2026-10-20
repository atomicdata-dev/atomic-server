import 'dart:convert';
import 'dart:typed_data';

import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  test('reads the text deltas of a completion stream, split anywhere',
      () async {
    const sse = 'data: {"choices":[{"delta":{"role":"assistant"}}]}\n\n'
        ': keep-alive\n\n'
        'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n'
        'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'
        'data: [DONE]\n\n'
        'data: {"choices":[{"delta":{"content":"never"}}]}\n\n';
    // Chunks that cut lines in the middle.
    final chunks = <String>[];
    for (var i = 0; i < sse.length; i += 7) {
      chunks.add(sse.substring(i, i + 7 > sse.length ? sse.length : i + 7));
    }
    final text = await AtomicAccountClient.parseCompletionStream(
            Stream.fromIterable(chunks))
        .join();
    expect(text, 'Hello');
  });

  test('chunks carry tool calls; comments and junk are skipped', () async {
    const sse = ': OPENROUTER PROCESSING\n\n'
        'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1",'
        '"function":{"name":"semantic_search","arguments":"{}"}}]},'
        '"finish_reason":"tool_calls"}]}\n\n'
        'data: not json\n\n'
        'data: [DONE]\n\n';
    final chunks =
        await AtomicAccountClient.parseCompletionChunks(Stream.value(sse))
            .toList();
    expect(chunks, hasLength(1));
    expect(chunks.single['choices'][0]['finish_reason'], 'tool_calls');
  });

  test('tools are sent along with the messages', () async {
    String? body;
    final client = AtomicAccountClient('https://portal.example',
        client: MockClient.streaming((request, bodyStream) async {
      body = await bodyStream.bytesToString();
      return http.StreamedResponse(
          Stream.value(utf8.encode('data: [DONE]\n\n')), 200);
    }))
      ..restoreSession(jsonEncode(
          {'origin': 'https://portal.example', 'token': 'secret-token'}));
    await client
        .chatCompletionChunks(
            [
              {'role': 'user', 'content': 'Hallo'}
            ],
            model: 'm',
            tools: [
              {
                'type': 'function',
                'function': {'name': 'f', 'parameters': {}}
              }
            ])
        .toList();
    final json = jsonDecode(body!);
    expect(json['tools'][0]['function']['name'], 'f');
    expect(json['tool_choice'], 'auto');
  });

  test('a stream error is thrown, not swallowed', () async {
    final stream = AtomicAccountClient.parseCompletionStream(
        Stream.value('data: {"error":{"message":"No credits left"}}\n\n'));
    expect(stream.toList(), throwsA(isA<StateError>()));
  });

  test('sends the account token and the messages, streams the answer',
      () async {
    late http.BaseRequest seen;
    String? body;
    final client = AtomicAccountClient('https://portal.example',
        client: MockClient.streaming((request, bodyStream) async {
      seen = request;
      body = await bodyStream.bytesToString();
      return http.StreamedResponse(
        Stream.value(utf8.encode(
            'data: {"choices":[{"delta":{"content":"Hoi"}}]}\n\ndata: [DONE]\n\n')),
        200,
      );
    }))
      ..restoreSession(jsonEncode(
          {'origin': 'https://portal.example', 'token': 'secret-token'}));

    final text = await client.chatCompletion([
      {'role': 'user', 'content': 'Hallo'}
    ], model: 'm').join();

    expect(text, 'Hoi');
    expect(
        seen.url.toString(), 'https://portal.example/api/ai/chat/completions');
    expect(seen.headers['Authorization'], 'Bearer secret-token');
    expect(jsonDecode(body!)['stream'], true);
    expect(jsonDecode(body!)['messages'][0]['content'], 'Hallo');
  });

  test('the portal refusal reaches the person', () async {
    final client = AtomicAccountClient('https://portal.example',
        client: MockClient.streaming((request, bodyStream) async {
      return http.StreamedResponse(
        Stream.value(utf8.encode('{"error":"No credits left"}')),
        402,
      );
    }))
      ..restoreSession(jsonEncode(
          {'origin': 'https://portal.example', 'token': 'secret-token'}));

    expect(
      client.chatCompletion([], model: 'm').toList(),
      throwsA(predicate((e) => e.toString().contains('No credits left'))),
    );
  });

  group('voice', () {
    AtomicAccountClient linked(MockClientHandler handler) =>
        AtomicAccountClient('https://portal.example',
            client: MockClient(handler))
          ..restoreSession(jsonEncode(
              {'origin': 'https://portal.example', 'token': 'secret-token'}));

    test('transcribe posts the base64 WAV with the token, reads text',
        () async {
      late http.Request seen;
      final client = linked((request) async {
        seen = request;
        return http.Response('{"text":"  Hallo wereld "}', 200);
      });
      final text = await client.transcribe(Uint8List.fromList([1, 2, 3, 4]),
          language: 'nl');
      expect(text, 'Hallo wereld');
      expect(seen.method, 'POST');
      expect(seen.url.toString(), 'https://portal.example/api/ai/voice');
      expect(seen.headers['Authorization'], 'Bearer secret-token');
      final body = jsonDecode(seen.body) as Map;
      expect(body['kind'], 'transcribe');
      expect(body['accepted'], true);
      expect(body['data'], base64Encode([1, 2, 3, 4]));
      expect(body['language'], 'nl');
    });

    test('no language key without a hint', () async {
      late http.Request seen;
      final client = linked((request) async {
        seen = request;
        return http.Response('{"text":""}', 200);
      });
      expect(await client.transcribe(Uint8List(2)), '');
      expect((jsonDecode(seen.body) as Map).containsKey('language'), isFalse);
    });

    test('failures are typed', () async {
      Future<AtomicVoiceFailure> failure(MockClientHandler handler,
          AtomicAccountClient Function(MockClientHandler) make) async {
        try {
          await make(handler).transcribe(Uint8List(2));
        } on AtomicVoiceError catch (e) {
          return e.failure;
        }
        fail('did not throw');
      }

      expect(await failure((_) async => http.Response('', 401), linked),
          AtomicVoiceFailure.notLinked);
      expect(
          await failure(
              (_) async => http.Response('{"error":"x"}', 402), linked),
          AtomicVoiceFailure.noCredits);
      expect(
          await failure(
              (_) async => http.Response('{"error":"Out of credits"}', 400),
              linked),
          AtomicVoiceFailure.noCredits);
      expect(await failure((_) async => http.Response('boom', 500), linked),
          AtomicVoiceFailure.server);
      expect(
          await failure(
              (_) async => throw http.ClientException('down'), linked),
          AtomicVoiceFailure.offline);
      expect(
          await failure(
              (_) async => http.Response('', 200),
              (h) => AtomicAccountClient('https://portal.example',
                  client: MockClient(h))),
          AtomicVoiceFailure.notLinked);
    });

    test('voiceStatus reads the status, null when not offered', () async {
      final ok = linked((request) async {
        expect(request.url.path, '/api/ai/voice/status');
        return http.Response('{"enabled":true,"remaining_micros":5}', 200);
      });
      expect((await ok.voiceStatus())!['enabled'], true);
      expect(await linked((_) async => http.Response('', 404)).voiceStatus(),
          isNull);
      expect(await linked((_) async => http.Response('', 401)).voiceStatus(),
          isNull);
    });
  });
}
