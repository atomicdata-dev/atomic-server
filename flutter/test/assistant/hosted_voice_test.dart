import 'dart:async';
import 'dart:typed_data';

import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:atomiccanvas_flutter/assistant/chat_screen.dart';
import 'package:atomiccanvas_flutter/assistant/hosted_ai.dart';
import 'package:atomiccanvas_flutter/assistant/hosted_voice.dart';
import 'package:atomiccanvas_flutter/assistant/voice.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, FakeSpeechInput, app;

/// The account engine without a microphone or a network: [stop] waits for the
/// test to deliver the transcription.
class FakeHostedSpeechInput implements HostedSpeechInput {
  FakeHostedSpeechInput(
      {this.availability_ = const HostedAvailability.available()});

  HostedAvailability availability_;
  int starts = 0;
  int stops = 0;
  int cancels = 0;
  String? lastLanguage;
  bool _on = false;
  final _result = Completer<String>();
  void Function(String, bool)? onText;
  void Function(String)? onError;
  void Function(double)? onLevel;

  @override
  void Function(bool)? onTranscribing;

  /// Delivers the transcription (or fails it) after [stop].
  void finish(String text) => _result.complete(text);
  void fail(String message) => _result.completeError(message);

  @override
  Future<HostedAvailability> availability() async => availability_;

  @override
  Future<List<SpeechLocale>> locales() async => const [];

  @override
  Future<String?> systemLocale() async => null;

  @override
  bool get listening => _on;

  @override
  Future<bool> start({
    required void Function(String text, bool isFinal) onText,
    required void Function(String error) onError,
    void Function(double level)? onLevel,
    String? localeId,
  }) async {
    starts++;
    lastLanguage = localeId;
    this.onText = onText;
    this.onError = onError;
    this.onLevel = onLevel;
    _on = true;
    return true;
  }

  @override
  Future<void> stop() async {
    stops++;
    if (!_on) return;
    _on = false;
    onTranscribing?.call(true);
    try {
      onText!(await _result.future, true);
    } catch (e) {
      onError!('$e');
    }
  }

  @override
  Future<void> cancel() async {
    cancels++;
    _on = false;
  }

  @override
  Future<void> dispose() async {}
}

class FakeRecorder implements PcmRecorder {
  bool allowed = true;
  int stops = 0;
  late StreamController<Uint8List> chunks;

  @override
  Future<bool> hasPermission() async => allowed;

  @override
  Future<Stream<Uint8List>> start() async {
    chunks = StreamController<Uint8List>(sync: true);
    return chunks.stream;
  }

  @override
  Future<void> stop() async => stops++;

  @override
  Future<void> dispose() async {}
}

/// [ms] of PCM at [amplitude] (0..1), as the recorder would deliver it.
Uint8List pcm(int ms, {double amplitude = 0.5}) {
  final out = Uint8List(ms * 32);
  final view = ByteData.sublistView(out);
  for (var i = 0; i < out.length ~/ 2; i++) {
    view.setInt16(i * 2, (amplitude * 32767 * (i.isEven ? 1 : -1)).round(),
        Endian.little);
  }
  return out;
}

HostedAi account({bool consent = true}) => HostedAi(
      status: {'enabled': true, 'consent': consent, 'model': 'm'},
      stream: (messages, model) => Stream.value('ok'),
      enable: () async => {},
    );

void main() {
  group('pcm helpers', () {
    test('the WAV is 16 kHz 16-bit mono PCM around the samples', () {
      final wav = pcmWav(Uint8List.fromList([1, 0, 2, 0]));
      final view = ByteData.sublistView(wav);
      expect(String.fromCharCodes(wav.sublist(0, 4)), 'RIFF');
      expect(String.fromCharCodes(wav.sublist(8, 16)), 'WAVEfmt ');
      expect(view.getUint32(4, Endian.little), wav.length - 8);
      expect(view.getUint16(20, Endian.little), 1);
      expect(view.getUint16(22, Endian.little), 1);
      expect(view.getUint32(24, Endian.little), 16000);
      expect(view.getUint32(28, Endian.little), 32000);
      expect(view.getUint16(34, Endian.little), 16);
      expect(view.getUint32(40, Endian.little), 4);
      expect(wav.sublist(44), [1, 0, 2, 0]);
    });

    test('the level is 0 for silence and grows with loudness', () {
      expect(pcmLevel(Uint8List(0)), 0);
      expect(pcmLevel(Uint8List(200)), 0);
      final quiet = pcmLevel(pcm(100, amplitude: 0.005));
      final loud = pcmLevel(pcm(100, amplitude: 0.3));
      expect(loud, greaterThan(quiet));
      expect(loud, inInclusiveRange(0, 1));
      expect(pcmLevel(pcm(100, amplitude: 1)), 1);
    });
  });

  group('error messages', () {
    test('each failure has a plain message', () {
      String m(shared.AtomicVoiceFailure f) =>
          hostedVoiceMessage(shared.AtomicVoiceError(f));
      expect(m(shared.AtomicVoiceFailure.notLinked),
          'Link your atomic.place account to use this.');
      expect(m(shared.AtomicVoiceFailure.noCredits),
          'No credits left for voice input.');
      expect(m(shared.AtomicVoiceFailure.offline),
          'No internet connection for voice input.');
      expect(m(shared.AtomicVoiceFailure.server),
          'The account could not transcribe that. Try again.');
      expect(hostedVoiceMessage(StateError('x')), 'Voice input failed.');
    });
  });

  group('availability', () {
    HostedAi withVoice(Map<String, dynamic>? voice,
            {Map<String, dynamic>? status}) =>
        HostedAi(
          status: status ?? {'enabled': true, 'consent': true, 'model': 'm'},
          stream: (messages, model) => const Stream.empty(),
          enable: () async => {},
          transcribe: (wav, {language}) async => '',
          voiceStatus: () async => voice,
        );

    test('not linked', () async {
      final a = await accountVoiceAvailability(null);
      expect(a.ok, isFalse);
      expect(a.reason, 'Link your atomic.place account to use this.');
      // AI without voice support behaves the same.
      expect((await accountVoiceAvailability(account())).ok, isFalse);
    });

    test('needs AI on, consent, voice on and credits', () async {
      expect(
          (await accountVoiceAvailability(
                  withVoice({'enabled': true, 'remaining_micros': 5})))
              .ok,
          isTrue);
      expect(
          (await accountVoiceAvailability(
                  withVoice({'enabled': true, 'remaining_micros': 0})))
              .reason,
          'No credits left.');
      expect((await accountVoiceAvailability(withVoice({'enabled': false}))).ok,
          isFalse);
      expect((await accountVoiceAvailability(withVoice(null))).ok, isFalse);
      expect(
          (await accountVoiceAvailability(withVoice({'enabled': true},
                  status: {'enabled': true, 'consent': false})))
              .ok,
          isFalse);
      expect(
          (await accountVoiceAvailability(withVoice({'enabled': true},
                  status: {'enabled': false, 'consent': true})))
              .ok,
          isFalse);
    });
  });

  group('HostedSpeechInput', () {
    late FakeRecorder recorder;
    late List<(Uint8List, String?)> sent;
    late List<(String, bool)> texts;
    late List<String> errors;
    late List<double> levels;
    late List<bool> transcribing;
    Object? failWith;
    String reply = 'hello';

    HostedSpeechInput make({Duration max = const Duration(seconds: 120)}) {
      final input = HostedSpeechInput(
        transcribe: (wav, {language}) async {
          sent.add((wav, language));
          if (failWith != null) throw failWith!;
          return reply;
        },
        availability: () async => const HostedAvailability.available(),
        recorder: recorder,
        maxRecording: max,
      );
      input.onTranscribing = transcribing.add;
      return input;
    }

    Future<bool> begin(HostedSpeechInput input, {String? language}) =>
        input.start(
          localeId: language,
          onText: (t, f) => texts.add((t, f)),
          onError: errors.add,
          onLevel: levels.add,
        );

    setUp(() {
      recorder = FakeRecorder();
      sent = [];
      texts = [];
      errors = [];
      levels = [];
      transcribing = [];
      failWith = null;
      reply = 'hello';
    });

    test('no microphone permission: start is false', () async {
      recorder.allowed = false;
      final input = make();
      expect(await begin(input), isFalse);
      expect(input.listening, isFalse);
    });

    test('reports levels about every 100 ms, then one final text', () async {
      final input = make();
      expect(await begin(input, language: 'nl'), isTrue);
      for (var i = 0; i < 5; i++) {
        recorder.chunks.add(pcm(50));
      }
      expect(levels, hasLength(2));
      expect(levels.every((l) => l > 0 && l <= 1), isTrue);
      expect(texts, isEmpty);
      for (var i = 0; i < 6; i++) {
        recorder.chunks.add(pcm(50));
      }
      await input.stop();
      expect(transcribing, [true]);
      expect(texts, [('hello', true)]);
      expect(errors, isEmpty);
      expect(recorder.stops, 1);
      expect(sent.single.$2, 'nl');
      // 550 ms of 16 kHz 16-bit mono, plus the 44 byte header.
      expect(sent.single.$1.length, 44 + 550 * 32);
    });

    test('recordings under 0.4 s are ignored without a request', () async {
      final input = make();
      await begin(input);
      recorder.chunks.add(pcm(300));
      await input.stop();
      expect(sent, isEmpty);
      expect(texts, [('', true)]);
    });

    test('the maximum length ends and transcribes the recording', () async {
      final input = make(max: const Duration(seconds: 1));
      await begin(input);
      for (var i = 0; i < 12; i++) {
        recorder.chunks.add(pcm(100));
      }
      await Future<void>.delayed(Duration.zero);
      expect(input.listening, isFalse);
      expect(sent, hasLength(1));
      expect(sent.single.$1.length, 44 + 1000 * 32);
      expect(texts, [('hello', true)]);
    });

    test('errors become plain messages', () async {
      final input = make();
      Future<String> run(Object error) async {
        failWith = error;
        errors.clear();
        await begin(input);
        recorder.chunks.add(pcm(500));
        await input.stop();
        return errors.single;
      }

      expect(
          await run(const shared.AtomicVoiceError(
              shared.AtomicVoiceFailure.noCredits)),
          'No credits left for voice input.');
      expect(
          await run(const shared.AtomicVoiceError(
              shared.AtomicVoiceFailure.notLinked)),
          'Link your atomic.place account to use this.');
      expect(
          await run(
              const shared.AtomicVoiceError(shared.AtomicVoiceFailure.offline)),
          'No internet connection for voice input.');
      expect(
          await run(
              const shared.AtomicVoiceError(shared.AtomicVoiceFailure.server)),
          'The account could not transcribe that. Try again.');
      expect(texts, isEmpty);
    });

    test('a cancelled transcription delivers nothing', () async {
      final input = make();
      await begin(input);
      recorder.chunks.add(pcm(500));
      await input.cancel();
      await input.stop();
      expect(sent, isEmpty);
      expect(texts, isEmpty);
    });
  });

  group('voice engine in the chat', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));

    Future<void> open(
      WidgetTester tester, {
      required FakeSpeechInput device,
      required FakeHostedSpeechInput hosted,
      bool hints = false,
    }) async {
      await tester.pumpWidget(app(ChatScreen(
        api: FakeApi(ai: account()),
        speechInput: device,
        hostedSpeechInput: hosted,
        speechOutput: null,
        accountLanguageHints: hints,
      )));
      await tester.pumpAndSettle();
    }

    String field(WidgetTester tester) =>
        tester.widget<TextField>(find.byType(TextField)).controller!.text;

    Future<String?> pref(String key) async =>
        (await SharedPreferences.getInstance()).getString(key);

    testWidgets(
        'choosing the account in the sheet, then the mic: hosted engine, '
        'transcribing state, text lands in the field', (tester) async {
      final device = FakeSpeechInput();
      final hosted = FakeHostedSpeechInput();
      await open(tester, device: device, hosted: hosted);
      await tester.enterText(find.byType(TextField), 'Hello');

      await tester.longPress(find.byIcon(Icons.mic));
      await tester.pumpAndSettle();
      expect(find.text('Voice input'), findsOneWidget);
      expect(find.text('atomic.place account'), findsOneWidget);
      expect(find.text('Whisper, any language, uses credits'), findsOneWidget);
      expect(find.text('This device'), findsOneWidget);
      expect(find.text('Google speech recognition, free, live words'),
          findsOneWidget);
      await tester.tap(find.byKey(const Key('engine-account')));
      await tester.pumpAndSettle();
      expect(await pref('voice_engine'), 'account');
      // Without a language hint on the server: auto-detect only.
      expect(find.text('Auto-detect'), findsOneWidget);
      expect(find.text('Dutch'), findsNothing);
      await tester.tap(find.byKey(const Key('language-auto')));
      await tester.pumpAndSettle();

      await tester.tap(find.byIcon(Icons.mic));
      await tester.pump();
      await tester.pump();
      expect(hosted.starts, 1);
      expect(device.starts, 0);
      expect(find.text('whisper'), findsOneWidget);
      expect(hosted.lastLanguage, isNull);

      // The level ring follows the hosted levels.
      double ring() =>
          tester.getSize(find.byKey(const Key('mic-level-ring'))).width;
      hosted.onLevel!(0);
      await tester.pump(const Duration(milliseconds: 300));
      final quiet = ring();
      hosted.onLevel!(1);
      await tester.pump(const Duration(milliseconds: 300));
      expect(ring(), greaterThan(quiet));
      expect(find.byKey(const Key('mic-waveform')), findsOneWidget);

      await tester.tap(find.byIcon(Icons.stop));
      await tester.pump();
      expect(hosted.stops, 1);
      expect(find.byKey(const Key('mic-transcribing')), findsOneWidget);
      expect(find.text('transcribing…'), findsOneWidget);
      expect(find.byIcon(Icons.mic), findsNothing);
      expect(tester.widget<TextField>(find.byType(TextField)).readOnly, isTrue);
      expect(field(tester), 'Hello');

      hosted.finish('goedemorgen allemaal');
      await tester.pump();
      await tester.pump();
      expect(field(tester), 'Hello goedemorgen allemaal');
      expect(find.byKey(const Key('mic-transcribing')), findsNothing);
      expect(find.byIcon(Icons.mic), findsOneWidget);
      expect(
          tester.widget<TextField>(find.byType(TextField)).readOnly, isFalse);
    });

    testWidgets('a hosted error shows its message and re-enables the mic',
        (tester) async {
      SharedPreferences.setMockInitialValues({'voice_engine': 'account'});
      final hosted = FakeHostedSpeechInput();
      await open(tester, device: FakeSpeechInput(), hosted: hosted);
      await tester.tap(find.byIcon(Icons.mic));
      await tester.pump();
      await tester.pump();
      await tester.tap(find.byIcon(Icons.stop));
      await tester.pump();
      hosted.fail('No credits left for voice input.');
      await tester.pump();
      await tester.pump();
      expect(find.text('No credits left for voice input.'), findsOneWidget);
      expect(find.byIcon(Icons.mic), findsOneWidget);
    });

    testWidgets(
        'an unavailable account is disabled with its reason; the '
        'device engine is used', (tester) async {
      final device = FakeSpeechInput();
      final hosted = FakeHostedSpeechInput(
          availability_:
              const HostedAvailability.unavailable('No credits left.'));
      await open(tester, device: device, hosted: hosted);

      await tester.longPress(find.byIcon(Icons.mic));
      await tester.pumpAndSettle();
      expect(find.text('No credits left.'), findsOneWidget);
      final tile =
          tester.widget<ListTile>(find.byKey(const Key('engine-account')));
      expect(tile.enabled, isFalse);
      await tester.tap(find.byKey(const Key('engine-account')));
      await tester.pumpAndSettle();
      expect(await pref('voice_engine'), isNull);
      // The device languages are listed.
      expect(find.text('Suggested'), findsOneWidget);
      await tester.tap(find.text('Dutch (Netherlands)'));
      await tester.pumpAndSettle();

      await tester.tap(find.byIcon(Icons.mic));
      await tester.pump();
      await tester.pump();
      expect(device.starts, 1);
      expect(hosted.starts, 0);
      expect(find.text('nl-NL'), findsOneWidget);
      // Not chosen, so no note about a fallback.
      expect(find.byKey(const Key('voice-note')), findsNothing);
    });

    testWidgets('the account chosen but unavailable falls back with a note',
        (tester) async {
      SharedPreferences.setMockInitialValues({'voice_engine': 'account'});
      final device = FakeSpeechInput();
      final hosted = FakeHostedSpeechInput(
          availability_: const HostedAvailability.unavailable(
              'Link your atomic.place account to use this.'));
      await open(tester, device: device, hosted: hosted);
      await tester.tap(find.byIcon(Icons.mic));
      await tester.pump();
      await tester.pump();
      expect(device.starts, 1);
      expect(hosted.starts, 0);
      expect(find.byKey(const Key('voice-note')), findsOneWidget);
      expect(find.textContaining('Using this device instead.'), findsOneWidget);
      // The choice itself is kept.
      expect(await pref('voice_engine'), 'account');
    });

    testWidgets('default engine: the account when usable, else the device',
        (tester) async {
      final device = FakeSpeechInput();
      final hosted = FakeHostedSpeechInput();
      await open(tester, device: device, hosted: hosted);
      await tester.tap(find.byIcon(Icons.mic));
      await tester.pump();
      await tester.pump();
      expect(hosted.starts, 1);
      expect(device.starts, 0);
      expect(await pref('voice_engine'), isNull);
    });

    testWidgets('a chosen device engine stays the device', (tester) async {
      SharedPreferences.setMockInitialValues({'voice_engine': 'device'});
      final device = FakeSpeechInput();
      final hosted = FakeHostedSpeechInput();
      await open(tester, device: device, hosted: hosted);
      await tester.tap(find.byIcon(Icons.mic));
      await tester.pump();
      await tester.pump();
      expect(device.starts, 1);
      expect(hosted.starts, 0);
    });

    testWidgets('engine and language persist separately from the locale',
        (tester) async {
      SharedPreferences.setMockInitialValues({'voice_locale': 'de_DE'});
      tester.view.physicalSize = const Size(800, 2400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      final device = FakeSpeechInput();
      final hosted = FakeHostedSpeechInput();
      await open(tester, device: device, hosted: hosted, hints: true);

      await tester.longPress(find.byIcon(Icons.mic));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('engine-device')));
      await tester.pumpAndSettle();
      expect(await pref('voice_engine'), 'device');
      await tester.tap(find.byKey(const Key('engine-account')));
      await tester.pumpAndSettle();
      expect(await pref('voice_engine'), 'account');
      for (final name in [
        'Auto-detect',
        'Dutch',
        'English',
        'German',
        'French',
        'Spanish',
        'Italian',
        'Portuguese',
        'Turkish',
        'Arabic',
      ]) {
        expect(find.text(name), findsOneWidget, reason: name);
      }
      await tester.tap(find.byKey(const Key('language-nl')));
      await tester.pumpAndSettle();
      expect(await pref('voice_language'), 'nl');
      expect(await pref('voice_locale'), 'de_DE');

      await tester.tap(find.byIcon(Icons.mic));
      await tester.pump();
      await tester.pump();
      expect(hosted.lastLanguage, 'nl');

      // Back to auto-detect clears the hint.
      await tester.tap(find.byIcon(Icons.stop));
      hosted.finish('x');
      await tester.pumpAndSettle();
      await tester.longPress(find.byIcon(Icons.mic));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('language-auto')));
      await tester.pumpAndSettle();
      expect(await pref('voice_language'), isNull);
    });
  });
}
