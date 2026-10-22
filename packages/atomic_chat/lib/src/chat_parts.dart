import 'dart:convert';
import 'dart:typed_data';

/// One part of an AI chat message, as the web app stores it in a `ChatLog`
/// entry (`parts`, the AI SDK's UI message parts): text, a file (a data URL),
/// a tool call with its result, or anything else (reasoning, a source), which
/// is kept as it was.
sealed class ChatPart {
  const ChatPart();

  Map<String, dynamic> toJson();

  /// The part of [json]; one this app does not show stays a [RawPart].
  static ChatPart fromJson(Map<String, dynamic> json) {
    final type = json['type'];
    if (type == 'text') return TextPart(json['text'] as String? ?? '');
    if (type == 'file' && json['url'] is String) {
      return FilePart(
        url: json['url'] as String,
        mediaType: json['mediaType'] as String? ?? '',
        filename: json['filename'] as String?,
      );
    }
    if (type is String && type.startsWith('tool-')) {
      return ToolPart(
        toolCallId: json['toolCallId'] as String? ?? '',
        toolName: type.substring(5),
        state: ToolState.parse(json['state'] as String?),
        input: json['input'],
        output: json['output'],
        errorText: json['errorText'] as String?,
      );
    }
    return RawPart(json);
  }
}

class TextPart extends ChatPart {
  final String text;
  const TextPart(this.text);

  @override
  Map<String, dynamic> toJson() => {'type': 'text', 'text': text};
}

/// A file: an image or a document the person attached, as a data URL.
class FilePart extends ChatPart {
  final String url;
  final String mediaType;
  final String? filename;

  const FilePart({required this.url, required this.mediaType, this.filename});

  /// [bytes] as a part with a data URL.
  factory FilePart.bytes(Uint8List bytes,
          {required String mediaType, String? filename}) =>
      FilePart(
        url: 'data:$mediaType;base64,${base64Encode(bytes)}',
        mediaType: mediaType,
        filename: filename,
      );

  bool get isImage => mediaType.startsWith('image/');

  /// The bytes of a data URL; null for any other URL or a broken one.
  Uint8List? get bytes {
    if (!url.startsWith('data:')) return null;
    final comma = url.indexOf(',');
    if (comma < 0) return null;
    final meta = url.substring(5, comma);
    final data = url.substring(comma + 1);
    try {
      return meta.endsWith(';base64')
          ? base64Decode(data)
          : Uint8List.fromList(utf8.encode(Uri.decodeComponent(data)));
    } catch (_) {
      return null;
    }
  }

  /// The text of a text file (null for a binary one).
  String? get text {
    if (!isTextMediaType(mediaType, filename)) return null;
    final b = bytes;
    if (b == null) return null;
    return utf8.decode(b, allowMalformed: true);
  }

  @override
  Map<String, dynamic> toJson() => {
        'type': 'file',
        'url': url,
        'mediaType': mediaType,
        if (filename != null) 'filename': filename,
      };
}

/// Whether a file of [mediaType] (or, when that says nothing, named
/// [filename]) is text a model can read as is.
bool isTextMediaType(String mediaType, [String? filename]) {
  if (mediaType.startsWith('text/')) return true;
  const textual = {
    'application/json',
    'application/xml',
    'application/x-yaml',
    'application/yaml',
    'application/javascript',
    'application/x-sh',
    'application/sql',
    'application/csv',
    'application/ld+json',
  };
  if (textual.contains(mediaType)) return true;
  final name = (filename ?? '').toLowerCase();
  final dot = name.lastIndexOf('.');
  if (dot < 0) return false;
  const exts = {
    'txt',
    'md',
    'markdown',
    'csv',
    'tsv',
    'json',
    'yaml',
    'yml',
    'xml',
    'html',
    'htm',
    'css',
    'js',
    'ts',
    'tsx',
    'jsx',
    'dart',
    'rs',
    'py',
    'java',
    'kt',
    'swift',
    'c',
    'h',
    'cpp',
    'go',
    'rb',
    'sh',
    'toml',
    'ini',
    'log',
    'sql',
    'svg',
    'tex',
    'org',
    'rst',
  };
  return exts.contains(name.substring(dot + 1));
}

/// Where a tool call is, as the AI SDK names it.
enum ToolState {
  inputStreaming('input-streaming'),
  inputAvailable('input-available'),
  outputAvailable('output-available'),
  outputError('output-error');

  final String wire;
  const ToolState(this.wire);

  static ToolState parse(String? s) => values.firstWhere(
        (v) => v.wire == s,
        orElse: () => ToolState.inputAvailable,
      );

  bool get running => this == inputStreaming || this == inputAvailable;
}

/// A call the model made to a tool, and its outcome once known.
class ToolPart extends ChatPart {
  final String toolCallId;
  final String toolName;
  final ToolState state;
  final Object? input;
  final Object? output;
  final String? errorText;

  const ToolPart({
    required this.toolCallId,
    required this.toolName,
    this.state = ToolState.inputAvailable,
    this.input,
    this.output,
    this.errorText,
  });

  ToolPart done(Object? output) => ToolPart(
        toolCallId: toolCallId,
        toolName: toolName,
        state: ToolState.outputAvailable,
        input: input,
        output: output,
      );

  ToolPart failed(String error) => ToolPart(
        toolCallId: toolCallId,
        toolName: toolName,
        state: ToolState.outputError,
        input: input,
        errorText: error,
      );

  @override
  Map<String, dynamic> toJson() => {
        'type': 'tool-$toolName',
        'toolCallId': toolCallId,
        'state': state.wire,
        if (input != null) 'input': input,
        if (state == ToolState.outputAvailable) 'output': output,
        if (state == ToolState.outputError) 'errorText': errorText ?? '',
      };
}

/// A part this app keeps but does not show (reasoning, a source, …).
class RawPart extends ChatPart {
  final Map<String, dynamic> json;
  const RawPart(this.json);

  @override
  Map<String, dynamic> toJson() => json;
}

/// A resource given to the AI as context with a message (the web app's
/// `atomic-resource` context, an entry's `ctx`).
typedef ContextResource = ({
  String subject,
  String title,
  String className,
  String? emoji
});

/// One message of an AI chat with all its parts.
class ChatEntry {
  final String id;
  final String role;
  final int createdAt;
  final List<ChatPart> parts;

  /// Resources the person attached to it, as context.
  final List<ContextResource> context;

  const ChatEntry({
    required this.id,
    required this.role,
    required this.createdAt,
    required this.parts,
    this.context = const [],
  });

  /// A message of text only.
  factory ChatEntry.text(
          ({String id, String role, String text, int createdAt}) m) =>
      ChatEntry(
        id: m.id,
        role: m.role,
        createdAt: m.createdAt,
        parts: [TextPart(m.text)],
      );

  /// The text parts, a blank line between them.
  String get text => textOf(parts);

  static String textOf(List<ChatPart> parts) => [
        for (final p in parts)
          if (p is TextPart && p.text.trim().isNotEmpty) p.text,
      ].join('\n\n').trim();

  /// The parts as `appendChatEntry` stores them.
  String get partsJson => jsonEncode([for (final p in parts) p.toJson()]);
}
