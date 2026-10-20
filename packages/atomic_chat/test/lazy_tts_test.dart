import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart' show SizedBox;
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'assistant_screens_test.dart' show FakeApi, FakeSpeechInput, app;

/// The platform TTS plugin is created at engine start-up unless the host holds
/// it back, and then costs about a second of the main thread: nothing may
/// touch it (or ask the host for it) before something is spoken.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final calls = <String>[];

  setUp(() {
    calls.clear();
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(const MethodChannel('flutter_tts'),
        (call) async {
      calls.add('tts.${call.method}');
      return 1;
    });
    messenger.setMockMethodCallHandler(PluginSpeechOutput.ttsChannel,
        (call) async {
      calls.add('host.${call.method}');
      return null;
    });
    addTearDown(() {
      messenger.setMockMethodCallHandler(
          const MethodChannel('flutter_tts'), null);
      messenger.setMockMethodCallHandler(PluginSpeechOutput.ttsChannel, null);
    });
  });

  test('creating and stopping the output touches nothing', () async {
    final output = PluginSpeechOutput();
    await output.stop();
    expect(calls, isEmpty);
  });

  test('the first utterance brings the plugin up, then speaks', () async {
    final output = PluginSpeechOutput();
    await output.speak('hello');
    expect(calls, ['host.ensure', 'tts.awaitSpeakCompletion', 'tts.speak']);
    await output.speak('again');
    // Brought up once.
    expect(calls.where((c) => c == 'host.ensure'), hasLength(1));
    expect(calls.last, 'tts.speak');
    await output.stop();
    expect(calls.last, 'tts.stop');
  });

  test('a host that holds nothing back is not an error', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(PluginSpeechOutput.ttsChannel, null);
    final output = PluginSpeechOutput();
    await output.speak('hello');
    expect(calls, contains('tts.speak'));
  });

  test('a failed start is retried at the next utterance', () async {
    var tries = 0;
    final output = PluginSpeechOutput(prepare: () async {
      if (tries++ == 0) throw StateError('no host');
    });
    await output.speak('one');
    expect(calls, isEmpty);
    await output.speak('two');
    expect(tries, 2);
    expect(calls, contains('tts.speak'));
  });

  testWidgets('a chat opened, typed in and closed never touches TTS',
      (tester) async {
    await tester.pumpWidget(app(ChatScreen(
      api: FakeApi(ai: null),
      speechInput: FakeSpeechInput(),
    )));
    await tester.pumpAndSettle();
    await tester.pumpWidget(app(const SizedBox()));
    await tester.pumpAndSettle();
    expect(calls, isEmpty);
  });
}
