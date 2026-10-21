import 'dart:convert';

import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/foundation.dart';

import 'chat_parts.dart';
import 'models.dart';

/// What the model is told before the conversation. Not shown to the person.
const _systemPrompt =
    'You are the assistant in atomic.place. Answer briefly and clearly, in the '
    'language the person writes in. Use Markdown where it helps.';

/// Added to [_systemPrompt] when the model is given tools.
const _toolsPrompt =
    ' When the person asks about their own data, use the tools to search '
    'their drives and read resources; link a resource as [title](subject).';

/// The OpenAI-compatible `chat/completions` stream, chunk by chunk (the
/// decoded JSON of each `data:` line): [messages] may carry tool calls and
/// results, [tools] the functions the model may call.
typedef CompletionChunks = Stream<Map<String, dynamic>> Function(
  List<Map<String, dynamic>> messages,
  String model,
  List<Map<String, dynamic>>? tools,
);

/// A function the model may call while it answers; this app runs it and
/// gives the model its result (as the web app's chat does: the account's AI
/// only passes the calls on).
class AiTool {
  /// The function's name, the same as the web app's tool of that name.
  final String name;
  final String description;

  /// The JSON Schema of its input.
  final Map<String, dynamic> parameters;

  /// Runs the call with the model's [input]; the result goes back to the
  /// model as JSON. A thrown error goes back as the call's failure.
  final Future<Object?> Function(Map<String, dynamic> input) execute;

  const AiTool({
    required this.name,
    required this.description,
    required this.parameters,
    required this.execute,
  });

  /// The definition the model is given.
  Map<String, dynamic> get definition => {
        'type': 'function',
        'function': {
          'name': name,
          'description': description,
          'parameters': parameters,
        },
      };
}

/// What happens while the model answers.
sealed class AiEvent {
  const AiEvent();
}

/// More text of the answer.
class AiTextDelta extends AiEvent {
  final String text;
  const AiTextDelta(this.text);
}

/// The model called a tool; it runs now ([part] is `input-available`).
class AiToolStarted extends AiEvent {
  final ToolPart part;
  const AiToolStarted(this.part);
}

/// A tool call ended: [part] is `output-available` or `output-error`.
class AiToolFinished extends AiEvent {
  final ToolPart part;
  const AiToolFinished(this.part);
}

/// The included AI of a linked account: chat completions through the account
/// provider, paid from the account's credits.
class HostedAi {
  HostedAi({
    required this.status,
    Stream<String> Function(List<Map<String, String>>, String model)? stream,
    CompletionChunks? completions,
    required Future<Map<String, dynamic>> Function() enable,
    this.transcribe,
    this.voiceStatus,
    this.acceptsImages = false,
  })  : assert(stream != null || completions != null),
        _stream = stream,
        _completions = completions,
        _enable = enable;

  /// Speech to text through the account's Whisper (a 16-bit mono PCM WAV and
  /// an optional ISO-639-1 language hint); null when not offered.
  final Future<String> Function(Uint8List wav, {String? language})? transcribe;

  /// The account's voice status (`enabled`, `remaining_micros`); null result
  /// when the portal offers none.
  final Future<Map<String, dynamic>?> Function()? voiceStatus;

  /// Whether images may be sent to the model. The account's included AI
  /// takes text and tools only (it refuses image and file parts).
  final bool acceptsImages;

  /// The most of a chat sent to the model: its latest messages.
  static const maxHistoryMessages = 40;
  static const maxHistoryChars = 24000;

  /// The most rounds of tool calls in one answer (as the web app's hosted
  /// chat).
  static const maxSteps = 8;

  /// The most of an attached text file sent to the model.
  static const maxFileChars = 20000;

  Map<String, dynamic> status;
  final Stream<String> Function(List<Map<String, String>>, String model)?
      _stream;
  final CompletionChunks? _completions;
  final Future<Map<String, dynamic>> Function() _enable;

  /// The provider offers AI to this account and it is switched on.
  bool get available => status['enabled'] == true;

  /// The person accepted the terms for the included AI.
  bool get consent => status['consent'] == true;

  /// Whether the model can be given tools (the stream reports tool calls).
  bool get supportsTools => _completions != null;

  String get model => status['model'] as String? ?? '';

  /// Credits left, in the provider's unit; null when it does not say.
  int? get remaining => (status['remaining_micros'] as num?)?.toInt();

  /// Accepts the terms; the AI can be used afterwards.
  Future<void> enable() async => status = await _enable();

  /// The answer to [history] (oldest first), as it is written.
  Stream<String> answer(List<ChatMessage> history, {String? context}) => run(
        [for (final m in history) ChatEntry.text(m)],
        context: context,
      ).where((e) => e is AiTextDelta).map((e) => (e as AiTextDelta).text);

  /// The answer to [history] (oldest first): its text as it is written, and
  /// each call to one of [tools] as it starts and ends. Calls are run here,
  /// and the model goes on with their results, at most [maxSteps] rounds.
  ///
  /// [context], when given, is sent as a second system message ahead of the
  /// history: resources the person attached. It is not part of the chat.
  Stream<AiEvent> run(
    List<ChatEntry> history, {
    String? context,
    List<AiTool> tools = const [],
  }) async* {
    final recent = _recent(history);
    final system = [
      {
        'role': 'system',
        'content': tools.isEmpty || _completions == null
            ? _systemPrompt
            : '$_systemPrompt$_toolsPrompt',
      },
      if (context != null && context.isNotEmpty)
        {'role': 'system', 'content': context},
    ];
    final completions = _completions;
    if (completions == null) {
      final messages = <Map<String, String>>[
        for (final m in system) {'role': m['role']!, 'content': m['content']!},
        for (final e in recent) {'role': e.role, 'content': _flatText(e)},
      ];
      debugPrint('[ai] sending ${messages.length} messages '
          '(${recent.length} of ${history.length} of the chat) to model "$model"');
      yield* _stream!(messages, model).map(AiTextDelta.new);
      return;
    }
    final messages = <Map<String, dynamic>>[
      ...system,
      for (final e in recent) ..._wire(e),
    ];
    final defs = tools.isEmpty ? null : [for (final t in tools) t.definition];
    debugPrint('[ai] sending ${messages.length} messages '
        '(${recent.length} of ${history.length} of the chat, '
        '${tools.length} tools) to model "$model"');
    for (var step = 0; step < maxSteps; step++) {
      final text = StringBuffer();
      final calls = <_Call>[];
      await for (final chunk in completions(messages, model, defs)) {
        final choices = chunk['choices'];
        if (choices is! List || choices.isEmpty) continue;
        final delta = (choices.first as Map)['delta'];
        if (delta is! Map) continue;
        final content = delta['content'];
        if (content is String && content.isNotEmpty) {
          text.write(content);
          yield AiTextDelta(content);
        }
        final toolCalls = delta['tool_calls'];
        if (toolCalls is List) {
          for (final raw in toolCalls) {
            if (raw is Map) _addCallDelta(calls, raw);
          }
        }
      }
      if (calls.isEmpty) return;
      messages.add({
        'role': 'assistant',
        'content': text.isEmpty ? null : text.toString(),
        'tool_calls': [
          for (final c in calls)
            {
              'id': c.id,
              'type': 'function',
              'function': {'name': c.name, 'arguments': c.args.toString()},
            },
        ],
      });
      for (final c in calls) {
        final input = _decodeArgs(c.args.toString());
        final part = ToolPart(
          toolCallId: c.id,
          toolName: c.name,
          state: ToolState.inputAvailable,
          input: input,
        );
        yield AiToolStarted(part);
        String result;
        AiToolFinished finished;
        final tool = tools.where((t) => t.name == c.name).firstOrNull;
        try {
          if (tool == null) throw StateError('Unknown tool ${c.name}');
          final output = await tool.execute(input);
          finished = AiToolFinished(part.done(output));
          result = jsonEncode(output);
        } catch (e) {
          final message = e is StateError ? e.message : '$e';
          finished = AiToolFinished(part.failed(message));
          result = 'Error: $message';
        }
        yield finished;
        messages.add({
          'role': 'tool',
          'tool_call_id': c.id,
          'content': result,
        });
      }
    }
  }

  /// A long chat is cut to its latest part: the model reads (and the
  /// account bills) every token, and an old chat made the first word slow.
  /// The newest message is always sent.
  static List<ChatEntry> _recent(List<ChatEntry> history) {
    var recent = history.length > maxHistoryMessages
        ? history.sublist(history.length - maxHistoryMessages)
        : history;
    var chars = 0;
    var start = recent.length;
    while (start > 0 && chars + _size(recent[start - 1]) <= maxHistoryChars) {
      chars += _size(recent[--start]);
    }
    return recent.sublist(start == recent.length ? start - 1 : start);
  }

  /// About how much of the model's budget an entry takes.
  static int _size(ChatEntry e) {
    var n = 0;
    for (final p in e.parts) {
      n += switch (p) {
        TextPart(:final text) => text.length,
        FilePart() => p.isImage ? 1000 : (p.text?.length ?? 100),
        ToolPart(:final input, :final output, :final errorText) =>
          jsonEncode(input).length +
              jsonEncode(output).length +
              (errorText?.length ?? 0),
        RawPart() => 0,
      };
    }
    return n;
  }

  /// A file as the model reads it: a text file's text, otherwise a note.
  static String _fileText(FilePart f) {
    final name = f.filename ?? 'file';
    final text = f.text;
    if (text != null) {
      final cut = text.length > maxFileChars
          ? '${text.substring(0, maxFileChars)}\n…(cut)'
          : text;
      return 'Attached file "$name":\n```\n$cut\n```';
    }
    return f.isImage
        ? '[The person attached an image, "$name", which you cannot see.]'
        : '[The person attached "$name" (${f.mediaType}), which you cannot '
            'read.]';
  }

  /// An entry as text only (for a stream without tools).
  static String _flatText(ChatEntry e) => [
        for (final p in e.parts)
          if (p is TextPart && p.text.trim().isNotEmpty)
            p.text
          else if (p is FilePart)
            _fileText(p),
      ].join('\n\n');

  /// An entry as model messages: a user's text and files; an assistant's
  /// text, and its tool calls with their results.
  List<Map<String, dynamic>> _wire(ChatEntry e) {
    if (e.role != 'assistant') {
      final content = <Map<String, dynamic>>[];
      for (final p in e.parts) {
        if (p is TextPart && p.text.trim().isNotEmpty) {
          content.add({'type': 'text', 'text': p.text});
        } else if (p is FilePart) {
          content.add(p.isImage && acceptsImages
              ? {
                  'type': 'image_url',
                  'image_url': {'url': p.url},
                }
              : {'type': 'text', 'text': _fileText(p)});
        }
      }
      if (content.length == 1 && content.single['type'] == 'text') {
        return [
          {'role': e.role, 'content': content.single['text']},
        ];
      }
      return [
        {'role': e.role, 'content': content},
      ];
    }
    final out = <Map<String, dynamic>>[];
    final text = StringBuffer();
    final calls = <ToolPart>[];
    void flushCalls() {
      if (calls.isEmpty) return;
      out.add({
        'role': 'assistant',
        'content': text.isEmpty ? null : text.toString(),
        'tool_calls': [
          for (final c in calls)
            {
              'id': c.toolCallId,
              'type': 'function',
              'function': {
                'name': c.toolName,
                'arguments': jsonEncode(c.input ?? const {}),
              },
            },
        ],
      });
      text.clear();
      for (final c in calls) {
        out.add({
          'role': 'tool',
          'tool_call_id': c.toolCallId,
          'content': c.state == ToolState.outputError
              ? 'Error: ${c.errorText ?? ''}'
              : jsonEncode(c.output),
        });
      }
      calls.clear();
    }

    for (final p in e.parts) {
      if (p is TextPart) {
        if (calls.isNotEmpty) flushCalls();
        if (p.text.trim().isEmpty) continue;
        if (text.isNotEmpty) text.write('\n\n');
        text.write(p.text);
      } else if (p is ToolPart) {
        if (p.state.running) {
          // No result was recorded: the model is told, not given a call.
          flushCalls();
          if (text.isNotEmpty) text.write('\n\n');
          text.write('Previous tool call ${p.toolCallId} (${p.toolName}) has '
              'no recorded result. Its outcome is unknown.');
        } else {
          calls.add(p);
        }
      }
    }
    flushCalls();
    if (text.isNotEmpty) {
      out.add({'role': 'assistant', 'content': text.toString()});
    }
    return out;
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
      completions: (messages, model, tools) =>
          client.chatCompletionChunks(messages, model: model, tools: tools),
      enable: client.aiConsent,
      transcribe: (wav, {language}) =>
          client.transcribe(wav, language: language),
      voiceStatus: client.voiceStatus,
    );
  }
}

/// A tool call as its pieces arrive.
class _Call {
  String id;
  String name;
  final int index;
  final StringBuffer args = StringBuffer();
  _Call(this.index, this.id, this.name);
}

/// Adds a `tool_calls` delta: a new call (by its index, or a new id at an
/// index already taken), or more of an argument string.
void _addCallDelta(List<_Call> calls, Map raw) {
  final index = (raw['index'] as num?)?.toInt() ?? calls.length;
  final id = raw['id'] as String?;
  final fn = raw['function'];
  final name = fn is Map ? fn['name'] as String? : null;
  final args = fn is Map ? fn['arguments'] : null;
  var call = calls.where((c) => c.index == index).lastOrNull;
  if (call == null ||
      (id != null && id.isNotEmpty && call.id != id && call.id.isNotEmpty)) {
    call = _Call(index, id ?? 'call_${calls.length}', name ?? '');
    calls.add(call);
  }
  if (call.id.isEmpty && id != null) call.id = id;
  if (name != null && name.isNotEmpty && call.name.isEmpty) call.name = name;
  if (args is String) {
    call.args.write(args);
  } else if (args is Map) {
    call.args.write(jsonEncode(args));
  }
}

Map<String, dynamic> _decodeArgs(String raw) {
  if (raw.trim().isEmpty) return {};
  try {
    final v = jsonDecode(raw);
    return v is Map ? Map<String, dynamic>.from(v) : {'value': v};
  } catch (_) {
    return {'arguments': raw};
  }
}
