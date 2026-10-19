import 'package:flutter_tts/flutter_tts.dart';
import 'package:speech_to_text/speech_to_text.dart';

/// Speech to text. Behind an interface so the chat screen can be tested
/// without the platform plugin.
abstract class SpeechInput {
  /// Starts listening. [onText] gets the words heard so far (the whole
  /// utterance, not a delta) and whether that is the final result. Returns
  /// false when recognition is not available or not allowed; [onError] is
  /// called for errors while listening.
  Future<bool> start({
    required void Function(String text, bool isFinal) onText,
    required void Function(String error) onError,
  });

  Future<void> stop();

  bool get listening;
}

/// Text to speech.
abstract class SpeechOutput {
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

  @override
  bool get listening => _stt.isListening;

  void _finish() {
    if (_finished) return;
    _finished = true;
    _onText?.call(_last, true);
  }

  @override
  Future<bool> start({
    required void Function(String text, bool isFinal) onText,
    required void Function(String error) onError,
  }) async {
    _onText = onText;
    _onError = onError;
    try {
      final ok = await _stt.initialize(
        onError: (e) => _onError?.call(e.errorMsg),
        onStatus: (s) {
          // The recognizer stopped by itself (silence): end the utterance.
          if (s == 'done' || s == 'notListening') _finish();
        },
      );
      if (!ok) return false;
      _last = '';
      _finished = false;
      await _stt.listen(
        onResult: (r) {
          _last = r.recognizedWords;
          if (r.finalResult) {
            _finished = true;
            _onText?.call(_last, true);
          } else {
            _onText?.call(_last, false);
          }
        },
        listenOptions: SpeechListenOptions(partialResults: true),
      );
      return true;
    } catch (_) {
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
class PluginSpeechOutput implements SpeechOutput {
  final FlutterTts _tts = FlutterTts();

  @override
  Future<void> speak(String text) async {
    try {
      await _tts.speak(text);
    } catch (_) {}
  }

  @override
  Future<void> stop() async {
    try {
      await _tts.stop();
    } catch (_) {}
  }
}
