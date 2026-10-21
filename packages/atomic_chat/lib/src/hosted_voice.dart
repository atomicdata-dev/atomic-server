import 'dart:async';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/foundation.dart';
import 'package:record/record.dart';

import 'hosted_ai.dart';
import 'voice.dart';

/// SharedPreferences key: which engine transcribes, `account` or `device`.
const voiceEngineKey = 'voice_engine';

/// SharedPreferences key: the ISO-639-1 language hint of the account engine;
/// absent means auto-detect.
const voiceLanguageKey = 'voice_language';

const voiceEngineAccount = 'account';
const voiceEngineDevice = 'device';

/// The format the data-browser sends (`pcmWav` in voiceTurn.ts): the fixed PCM
/// lets the server check the duration before it reserves credits.
const hostedSampleRate = 16000;
const _bytesPerSecond = hostedSampleRate * 2;

/// Longest recording; it ends and is transcribed by itself at this length.
const hostedMaxRecording = Duration(seconds: 120);

/// Shorter recordings are ignored: a tap, not speech.
const hostedMinRecording = Duration(milliseconds: 400);

/// Whether the server's `/ai/voice` takes a `language` hint. Not confirmed:
/// the data-browser never sends one and the server is not in this repository.
/// Off, the sheet offers auto-detect only.
const hostedLanguageHintSupported = false;

/// Languages offered as a hint for the account engine: (ISO-639-1, name).
const hostedLanguages = <(String, String)>[
  ('nl', 'Dutch'),
  ('en', 'English'),
  ('de', 'German'),
  ('fr', 'French'),
  ('es', 'Spanish'),
  ('it', 'Italian'),
  ('pt', 'Portuguese'),
  ('tr', 'Turkish'),
  ('ar', 'Arabic'),
];

/// Whether the account engine can be used now, and if not, why in a few words.
class HostedAvailability {
  final bool ok;
  final String? reason;

  const HostedAvailability.available()
      : ok = true,
        reason = null;
  const HostedAvailability.unavailable(this.reason) : ok = false;
}

const notLinkedMessage = 'Link your atomic.place account to use this.';

/// Looks up whether [ai] (the linked account's AI, null when not linked) can
/// transcribe: AI on, terms accepted, voice on and credits left.
Future<HostedAvailability> accountVoiceAvailability(HostedAi? ai) async {
  if (ai == null || ai.transcribe == null) {
    return const HostedAvailability.unavailable(notLinkedMessage);
  }
  if (!ai.available) {
    return const HostedAvailability.unavailable(
        'Your account does not include AI.');
  }
  if (!ai.consent) {
    return const HostedAvailability.unavailable(
        'Accept the included AI terms first.');
  }
  Map<String, dynamic>? status;
  try {
    status = await ai.voiceStatus?.call();
  } catch (_) {
    return const HostedAvailability.unavailable(
        'Could not reach your account.');
  }
  if (status == null || status['enabled'] != true) {
    return const HostedAvailability.unavailable(
        'Voice is not on for your account.');
  }
  final left = (status['remaining_micros'] as num?)?.toInt();
  if (left != null && left <= 0) {
    return const HostedAvailability.unavailable('No credits left.');
  }
  return const HostedAvailability.available();
}

/// Plain wording for why a transcription failed.
String hostedVoiceMessage(Object error) {
  if (error is shared.AtomicVoiceError) {
    switch (error.failure) {
      case shared.AtomicVoiceFailure.notLinked:
        return notLinkedMessage;
      case shared.AtomicVoiceFailure.noCredits:
        return 'No credits left for voice input.';
      case shared.AtomicVoiceFailure.offline:
        return 'No internet connection for voice input.';
      case shared.AtomicVoiceFailure.server:
        return 'The account could not transcribe that. Try again.';
    }
  }
  return 'Voice input failed.';
}

/// A 16-bit mono 16 kHz PCM WAV around [pcm] (little endian samples).
Uint8List pcmWav(Uint8List pcm) {
  final out = Uint8List(44 + pcm.length);
  final view = ByteData.sublistView(out);
  void text(int at, String s) {
    for (var i = 0; i < s.length; i++) {
      out[at + i] = s.codeUnitAt(i);
    }
  }

  text(0, 'RIFF');
  view.setUint32(4, out.length - 8, Endian.little);
  text(8, 'WAVEfmt ');
  view.setUint32(16, 16, Endian.little);
  view.setUint16(20, 1, Endian.little);
  view.setUint16(22, 1, Endian.little);
  view.setUint32(24, hostedSampleRate, Endian.little);
  view.setUint32(28, _bytesPerSecond, Endian.little);
  view.setUint16(32, 2, Endian.little);
  view.setUint16(34, 16, Endian.little);
  text(36, 'data');
  view.setUint32(40, pcm.length, Endian.little);
  out.setRange(44, out.length, pcm);
  return out;
}

/// Input loudness of 16-bit little endian [pcm] as 0..1: the RMS in dB,
/// -50 dB (quiet room) to -10 dB (loud speech).
double pcmLevel(Uint8List pcm) {
  final count = pcm.length ~/ 2;
  if (count == 0) return 0;
  final view = ByteData.sublistView(pcm);
  var sum = 0.0;
  for (var i = 0; i < count; i++) {
    final v = view.getInt16(i * 2, Endian.little) / 32768;
    sum += v * v;
  }
  final rms = math.sqrt(sum / count);
  if (rms <= 0) return 0;
  final db = 20 * math.log(rms) / math.ln10;
  return ((db + 50) / 40).clamp(0.0, 1.0);
}

/// The microphone as a stream of PCM chunks; behind an interface so tests
/// need no plugin.
abstract class PcmRecorder {
  Future<bool> hasPermission();

  /// Starts recording 16-bit mono PCM at [hostedSampleRate].
  Future<Stream<Uint8List>> start();

  Future<void> stop();

  Future<void> dispose();
}

/// [PcmRecorder] on the `record` plugin.
class PluginPcmRecorder implements PcmRecorder {
  late final AudioRecorder _recorder = AudioRecorder();
  bool _made = false;

  @override
  Future<bool> hasPermission() {
    _made = true;
    return _recorder.hasPermission();
  }

  @override
  Future<Stream<Uint8List>> start() => _recorder.startStream(const RecordConfig(
        encoder: AudioEncoder.pcm16bits,
        sampleRate: hostedSampleRate,
        numChannels: 1,
      ));

  @override
  Future<void> stop() async {
    try {
      await _recorder.stop();
    } catch (_) {}
  }

  @override
  Future<void> dispose() async {
    if (!_made) return;
    try {
      await _recorder.dispose();
    } catch (_) {}
  }
}

/// A [SpeechInput] that records the microphone and has the account's Whisper
/// transcribe it when listening stops. No partial results: [start]'s `onText`
/// is called once, final. `localeId` is the ISO-639-1 hint (null: auto).
class HostedSpeechInput implements SpeechInput {
  final Future<String> Function(Uint8List wav, {String? language}) _transcribe;
  final Future<HostedAvailability> Function() _availability;
  final PcmRecorder _recorder;
  final int _maxBytes;
  final int _minBytes;

  HostedSpeechInput({
    required Future<String> Function(Uint8List wav, {String? language})
        transcribe,
    required Future<HostedAvailability> Function() availability,
    PcmRecorder? recorder,
    Duration maxRecording = hostedMaxRecording,
    Duration minRecording = hostedMinRecording,
  })  : _transcribe = transcribe,
        _availability = availability,
        _recorder = recorder ?? PluginPcmRecorder(),
        _maxBytes = maxRecording.inMilliseconds * _bytesPerSecond ~/ 1000,
        _minBytes = minRecording.inMilliseconds * _bytesPerSecond ~/ 1000;

  /// The account engine for [ai], which may be null (not linked).
  factory HostedSpeechInput.forAccount(HostedAi? ai) => HostedSpeechInput(
        transcribe: (wav, {language}) {
          final t = ai?.transcribe;
          if (t == null) {
            throw const shared.AtomicVoiceError(
                shared.AtomicVoiceFailure.notLinked);
          }
          return t(wav, language: language);
        },
        availability: () => accountVoiceAvailability(ai),
      );

  /// Told when recording ended and the transcription begins (true), also when
  /// the maximum length ended it.
  void Function(bool transcribing)? onTranscribing;

  void Function(String text, bool isFinal)? _onText;
  void Function(String error)? _onError;
  void Function(double level)? _onLevel;
  String? _language;
  final BytesBuilder _pcm = BytesBuilder(copy: false);
  StreamSubscription<Uint8List>? _sub;
  bool _recording = false;
  int _sinceLevel = 0;
  final BytesBuilder _levelBuf = BytesBuilder(copy: false);

  /// Bumped to drop the result of a transcription that was cancelled.
  int _generation = 0;

  /// Whether the account can transcribe now.
  Future<HostedAvailability> availability() => _availability();

  @override
  Future<List<SpeechLocale>> locales() async => const [];

  @override
  Future<String?> systemLocale() async => null;

  @override
  bool get listening => _recording;

  @override
  Future<bool> start({
    required void Function(String text, bool isFinal) onText,
    required void Function(String error) onError,
    void Function(double level)? onLevel,
    String? localeId,
  }) async {
    if (_recording) return true;
    _onText = onText;
    _onError = onError;
    _onLevel = onLevel;
    _language = localeId == null || localeId.isEmpty ? null : localeId;
    try {
      if (!await _recorder.hasPermission()) return false;
      _pcm.clear();
      _levelBuf.clear();
      _sinceLevel = 0;
      final generation = ++_generation;
      final stream = await _recorder.start();
      _recording = true;
      _sub = stream.listen(
        (chunk) => _onChunk(chunk, generation),
        onError: (_) {},
      );
      return true;
    } catch (e) {
      debugPrint('[voice] record start failed: $e');
      _recording = false;
      return false;
    }
  }

  void _onChunk(Uint8List chunk, int generation) {
    if (!_recording || generation != _generation) return;
    _pcm.add(chunk);
    // A level about every 100 ms of audio.
    _levelBuf.add(chunk);
    _sinceLevel += chunk.length;
    if (_sinceLevel >= _bytesPerSecond ~/ 10) {
      _onLevel?.call(pcmLevel(_levelBuf.takeBytes()));
      _sinceLevel = 0;
    }
    if (_pcm.length >= _maxBytes) stop();
  }

  /// Ends the recording and transcribes it; [start]'s `onText` gets the text
  /// (empty when too short to be speech) or `onError` a plain message.
  @override
  Future<void> stop() async {
    if (!_recording) return;
    _recording = false;
    final generation = _generation;
    await _sub?.cancel();
    _sub = null;
    await _recorder.stop();
    final pcm = _pcm.takeBytes();
    onTranscribing?.call(true);
    if (pcm.length < _minBytes) {
      _onText?.call('', true);
      return;
    }
    final wav = pcmWav(pcm.length > _maxBytes
        ? Uint8List.sublistView(pcm, 0, _maxBytes)
        : pcm);
    try {
      final text = await _transcribe(wav, language: _language);
      if (generation == _generation) _onText?.call(text, true);
    } catch (e) {
      debugPrint('[voice] transcribe failed: ${e.runtimeType}');
      if (generation == _generation) _onError?.call(hostedVoiceMessage(e));
    }
  }

  /// Drops the recording, or the transcription under way, without a result.
  Future<void> cancel() async {
    _generation++;
    if (!_recording) return;
    _recording = false;
    await _sub?.cancel();
    _sub = null;
    await _recorder.stop();
    _pcm.clear();
  }

  /// Releases the microphone; the input is not used afterwards.
  Future<void> dispose() async {
    await cancel();
    await _recorder.dispose();
  }
}
