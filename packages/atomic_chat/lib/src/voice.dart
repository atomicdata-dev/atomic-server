import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart'
    show MethodChannel, MissingPluginException;
import 'package:flutter_tts/flutter_tts.dart';
import 'package:speech_to_text/speech_to_text.dart';

/// Speech to text. Behind an interface so the chat screen can be tested
/// without the platform plugin.
/// A language the recogniser offers.
class SpeechLocale {
  final String id;
  final String name;

  const SpeechLocale(this.id, this.name);

  /// `nl_NL` -> `nl-NL`, for the small label.
  String get tag => id.replaceAll('_', '-');
}

abstract class SpeechInput {
  /// The languages the recogniser offers; the first is the system language
  /// when known. Empty when unavailable.
  Future<List<SpeechLocale>> locales();

  /// The system's language (e.g. `en_US`), if known.
  Future<String?> systemLocale();

  /// Starts listening. [onText] gets the words heard so far (the whole
  /// utterance, not a delta) and whether that is the final result. Returns
  /// false when recognition is not available or not allowed; [onError] is
  /// called for errors while listening. [onLevel] gets the input loudness
  /// normalised to 0..1, a few times a second. The returned future completes
  /// once listening has started (after the permission prompt, the first time).
  Future<bool> start({
    required void Function(String text, bool isFinal) onText,
    required void Function(String error) onError,
    void Function(double level)? onLevel,
    String? localeId,
  });

  Future<void> stop();

  bool get listening;
}

/// Maps the recogniser's dB-ish level (about -2..10 on Android, other ranges
/// elsewhere) to 0..1.
double normaliseSoundLevel(double db) {
  if (db.isNaN) return 0;
  return ((db + 2) / 12).clamp(0.0, 1.0);
}

/// Text to speech.
abstract class SpeechOutput {
  /// Speaks [text]; completes when it has been spoken or was stopped.
  Future<void> speak(String text);

  Future<void> stop();
}

/// [SpeechInput] on the `speech_to_text` plugin, in the device's locale.
class PluginSpeechInput implements SpeechInput {
  final SpeechToText _stt = SpeechToText();
  void Function(String text, bool isFinal)? _onText;
  void Function(String error)? _onError;
  String _last = '';
  bool _finished = true;
  Timer? _doneTimer;

  @override
  Future<List<SpeechLocale>> locales() async {
    try {
      if (!await _ensureInit()) return const [];
      final list = await _stt.locales();
      final out = [for (final l in list) SpeechLocale(l.localeId, l.name)];
      debugPrint('[voice] locales: ${out.length}');
      return out;
    } catch (e) {
      debugPrint('[voice] locales failed: $e');
      return const [];
    }
  }

  @override
  Future<String?> systemLocale() async {
    try {
      if (!await _ensureInit()) return null;
      final l = await _stt.systemLocale();
      debugPrint('[voice] systemLocale: ${l?.localeId}');
      return l?.localeId;
    } catch (_) {
      return null;
    }
  }

  Future<bool> _ensureInit() async {
    final ok = await _stt.initialize(
      onError: (e) {
        debugPrint('[voice] onError: ${e.errorMsg} permanent=${e.permanent}');
        _onError?.call(e.errorMsg);
      },
      onStatus: (s) {
        debugPrint('[voice] onStatus: $s');
        if (s == 'done') {
          _finish();
        } else if (s == 'notListening') {
          // Results can still arrive just after this; give them a moment.
          _doneTimer?.cancel();
          _doneTimer = Timer(const Duration(milliseconds: 800), _finish);
        }
      },
    );
    debugPrint('[voice] initialize: $ok');
    return ok;
  }

  @override
  bool get listening => _stt.isListening;

  void _finish() {
    _doneTimer?.cancel();
    if (_finished) return;
    _finished = true;
    _onText?.call(_last, true);
  }

  @override
  Future<bool> start({
    required void Function(String text, bool isFinal) onText,
    required void Function(String error) onError,
    void Function(double level)? onLevel,
    String? localeId,
  }) async {
    _onText = onText;
    _onError = onError;
    try {
      // initialize() returns once the permission prompt was answered; on
      // grant, carry straight on to listening (no second tap needed).
      final ok = await _ensureInit();
      if (!ok) return false;
      debugPrint('[voice] listen locale: $localeId');
      _last = '';
      _finished = false;
      await _stt.listen(
        onResult: (r) {
          debugPrint(
              '[voice] onResult: "${r.recognizedWords}" final=${r.finalResult}');
          _last = r.recognizedWords;
          if (r.finalResult) {
            _finished = true;
            _onText?.call(_last, true);
          } else {
            _onText?.call(_last, false);
          }
        },
        onSoundLevelChange:
            onLevel == null ? null : (db) => onLevel(normaliseSoundLevel(db)),
        listenOptions: SpeechListenOptions(
          localeId: localeId,
          // Words show up while speaking; each partial replaces the last.
          partialResults: true,
          cancelOnError: false,
          listenMode: ListenMode.dictation,
          pauseFor: const Duration(seconds: 4),
          listenFor: const Duration(seconds: 60),
        ),
      );
      return true;
    } catch (e) {
      debugPrint('[voice] start failed: $e');
      return false;
    }
  }

  @override
  Future<void> stop() async {
    try {
      await _stt.stop();
    } catch (_) {}
    _finish();
  }
}

/// [SpeechOutput] on the `flutter_tts` plugin, in the device's language.
///
/// Nothing is created before the first [speak]. On Android `flutter_tts`
/// creates a `TextToSpeech` the moment the engine attaches and reads every
/// voice on the main thread (about a second at every start), so the app
/// leaves that plugin out of engine start-up (`MainActivity`) and this class
/// asks for it just before the first use, over [ttsChannel].
class PluginSpeechOutput implements SpeechOutput {
  PluginSpeechOutput({Future<void> Function()? prepare})
      : _prepare = prepare ?? ensureNativeTts;

  /// The app's native side registers the TTS plugin when it gets "ensure".
  static const ttsChannel = MethodChannel('atomic_chat/tts');

  /// Asks the host to bring up the platform TTS plugin; a no-op where the
  /// host does not hold it back (every platform but the Android app).
  static Future<void> ensureNativeTts() async {
    try {
      await ttsChannel.invokeMethod<void>('ensure');
    } on MissingPluginException {
      // Registered at start-up: nothing to wait for.
    }
  }

  final Future<void> Function() _prepare;
  late final FlutterTts _tts = FlutterTts();
  Future<void>? _ready;

  /// Completes when the text has been spoken (or speaking was stopped).
  @override
  Future<void> speak(String text) async {
    try {
      await (_ready ??= _start());
      await _tts.speak(text);
    } catch (_) {
      // A failed start is tried again at the next utterance.
      _ready = null;
    }
  }

  Future<void> _start() async {
    await _prepare();
    await _tts.awaitSpeakCompletion(true);
  }

  @override
  Future<void> stop() async {
    // Never spoke: no plugin to stop, and none to create for it.
    if (_ready == null) return;
    try {
      await _tts.stop();
    } catch (_) {}
  }
}
