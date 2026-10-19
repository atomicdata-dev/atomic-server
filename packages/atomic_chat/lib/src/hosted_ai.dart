import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/foundation.dart';

import 'models.dart';

/// What the model is told before the conversation. Not shown to the person.
const _systemPrompt =
    'You are the assistant in atomic.place. Answer briefly and clearly, in the '
    "language the person writes in.";

/// The included AI of a linked account: chat completions through the account
/// provider, paid from the account's credits.
class HostedAi {
  HostedAi({
    required this.status,
    required Stream<String> Function(List<Map<String, String>>, String model)
        stream,
    required Future<Map<String, dynamic>> Function() enable,
    this.transcribe,
    this.voiceStatus,
  })  : _stream = stream,
        _enable = enable;

  /// Speech to text through the account's Whisper (a 16-bit mono PCM WAV and
  /// an optional ISO-639-1 language hint); null when not offered.
  final Future<String> Function(Uint8List wav, {String? language})? transcribe;

  /// The account's voice status (`enabled`, `remaining_micros`); null result
  /// when the portal offers none.
  final Future<Map<String, dynamic>?> Function()? voiceStatus;

  Map<String, dynamic> status;
  final Stream<String> Function(List<Map<String, String>>, String model)
      _stream;
  final Future<Map<String, dynamic>> Function() _enable;

  /// The provider offers AI to this account and it is switched on.
  bool get available => status['enabled'] == true;

  /// The person accepted the terms for the included AI.
  bool get consent => status['consent'] == true;

  String get model => status['model'] as String? ?? '';

  /// Credits left, in the provider's unit; null when it does not say.
  int? get remaining => (status['remaining_micros'] as num?)?.toInt();

  /// Accepts the terms; the AI can be used afterwards.
  Future<void> enable() async => status = await _enable();

  /// The answer to [history] (oldest first), as it is written.
  ///
  /// [context], when given, is sent as a second system message ahead of the
  /// history: resources the person attached. It is not part of the chat.
  Stream<String> answer(List<ChatMessage> history, {String? context}) {
    final messages = [
      {'role': 'system', 'content': _systemPrompt},
      if (context != null && context.isNotEmpty)
        {'role': 'system', 'content': context},
      for (final m in history) {'role': m.role, 'content': m.text},
    ];
    debugPrint('[ai] sending ${messages.length} messages '
        '(${history.length} of the chat) to model "$model"');
    return _stream(messages, model);
  }

  /// The AI of the account whose saved session is [session] (as
  /// [shared.AtomicAccountClient.restoreSession] takes it), or null when the
  /// provider offers none. Throws when the provider cannot be reached. The
  /// host reads the session from its own storage.
  static Future<HostedAi?> forSession(String session) async {
    final client = shared.AtomicAccountClient(
      shared.AtomicAccountClient.sessionOrigin(session).toString(),
    )..restoreSession(session);
    final status = await client.aiStatus();
    if (status == null) {
      client.close();
      return null;
    }
    return HostedAi(
      status: status,
      stream: (messages, model) =>
          client.chatCompletion(messages, model: model),
      enable: client.aiConsent,
      transcribe: (wav, {language}) =>
          client.transcribe(wav, language: language),
      voiceStatus: client.voiceStatus,
    );
  }
}
