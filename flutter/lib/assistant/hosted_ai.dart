import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/foundation.dart';

import '../atomic/account_store.dart';
import '../atomic/atomic_client.dart';

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
  })  : _stream = stream,
        _enable = enable;

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
  Stream<String> answer(List<ChatMessage> history) {
    final messages = [
      {'role': 'system', 'content': _systemPrompt},
      for (final m in history) {'role': m.role, 'content': m.text},
    ];
    debugPrint('[ai] sending ${messages.length} messages '
        '(${history.length} of the chat) to model "$model"');
    return _stream(messages, model);
  }

  /// The linked account's AI, or null when no account is linked or the
  /// provider offers none. Throws when the provider cannot be reached.
  static Future<HostedAi?> load() async {
    var saved = await AccountStore.read();
    if (saved == null && await AccountStore.signInWithAgent()) {
      saved = await AccountStore.read();
    }
    if (saved == null) return null;
    final client = shared.AtomicAccountClient(
      shared.AtomicAccountClient.sessionOrigin(saved).toString(),
    )..restoreSession(saved);
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
    );
  }
}
