import 'dart:convert';

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
}
