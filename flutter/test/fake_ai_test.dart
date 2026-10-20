import 'package:atomic_chat/atomic_chat.dart';
import 'package:atomic_app/assistant/fake_ai.dart';
import 'package:atomic_app/assistant/file_attachment_picker.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('the fake AI is off unless built with FAKE_AI', () {
    expect(fakeAiEnabled, isFalse);
  });

  test('the fake AI searches with the real tool, then answers in Markdown',
      () async {
    final searched = <String>[];
    final tool = AiTool(
      name: 'semantic_search',
      description: 'search',
      parameters: const {'type': 'object'},
      execute: (input) async {
        searched.add(input['query'] as String);
        return [
          {'subject': 'did:ad:x', 'title': 'Trip', 'chunk': ''}
        ];
      },
    );
    final events = await fakeHostedAi().run([
      ChatEntry.text(
          (id: 'u', role: 'user', text: 'my trip plans', createdAt: 0))
    ], tools: [
      tool
    ]).toList();
    expect(searched, ['my trip plans']);
    expect(events.whereType<AiToolFinished>().single.part.state,
        ToolState.outputAvailable);
    final text = events.whereType<AiTextDelta>().map((e) => e.text).join();
    expect(text, contains('[Trip](did:ad:x)'));
    // Never mistaken for the real AI.
    expect(text, startsWith(fakeAiMark));
    expect(text, contains('```dart'));
  });

  test('media types by extension', () {
    expect(mediaTypeOf('a.JPG'), 'image/jpeg');
    expect(mediaTypeOf('notes.md'), 'text/markdown');
    expect(mediaTypeOf('x'), 'application/octet-stream');
  });
}
