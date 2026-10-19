import 'dart:convert';

/// An AI chat of the active drive; `lastActivity` is unix ms, 0 when empty.
typedef ChatSummary = ({String subject, String name, int lastActivity});

/// One message of a chat: the text parts of an entry, `role` user or assistant.
typedef ChatMessage = ({String id, String role, String text, int createdAt});

/// One message of a conversation (a DM or group chat): who wrote it, and its
/// text once opened (null when this device cannot decrypt it).
typedef ConversationMessage = ({
  String id,
  String author,
  String authorName,
  bool mine,
  String? text,
  int createdAt
});

/// A row of the Messages list: the conversation and the text of its newest
/// message ('' when there is none or it cannot be read). `resource.openedAt`
/// is the time of that message in ms (0 when none).
typedef ConversationRow = ({RecentResource resource, String lastMessage});

typedef SearchHit = ({
  String subject,
  String title,
  String className,
  // The drive the hit lives in; '' when unknown.
  String drive,
  double score,
  // The resource's own icon (an emoji); null when it has none.
  String? emoji
});

/// A Notification of the Inbox in the private drive (as the web app records
/// it): `title` the one-line summary, `body` a short excerpt, `about` what to
/// open ('' when unknown), `occurredAt` in unix ms, `read` once seen.
typedef NotificationItem = ({
  String subject,
  String title,
  String body,
  String about,
  String kind,
  int occurredAt,
  bool read
});

typedef DriveInfo = ({String subject, String name, String? emoji});

typedef RecentResource = ({
  String subject,
  String title,
  String className,
  int openedAt,
  // The resource's own icon (an emoji); null when it has none.
  String? emoji
});

/// One change in the activity feed.
class ActivityEntry {
  final String subject;
  final String drive;

  /// `created`, `changed` or `deleted`.
  final String kind;

  /// Unix ms.
  final int at;

  /// Display name of the agent that did it; null when the store does not
  /// know who, or does not have that agent's resource.
  final String? actor;
  final String name;
  final String className;

  const ActivityEntry({
    required this.subject,
    required this.drive,
    required this.kind,
    required this.at,
    this.actor,
    required this.name,
    required this.className,
  });

  @override
  int get hashCode =>
      Object.hash(subject, drive, kind, at, actor, name, className);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ActivityEntry &&
          subject == other.subject &&
          drive == other.drive &&
          kind == other.kind &&
          at == other.at &&
          actor == other.actor &&
          name == other.name &&
          className == other.className;
}

/// The identifier without its scheme: `did:ad:X` and `atomic:X` are one drive.
String driveKey(String subject) =>
    subject.replaceFirst(RegExp(r'^(did:ad:|atomic:)'), '').split('?').first;

/// The drives worth showing: each drive once (the personal drive is listed
/// under both spellings), and only those that are on this device with a name
/// — a drive the personal drive lists but this device has not received has
/// nothing to show yet. The [active] drive stays whatever its state.
List<DriveInfo> visibleDrives(List<DriveInfo> all, {String? active}) {
  final seen = <String>{};
  final out = <DriveInfo>[];
  for (final d in all) {
    final key = driveKey(d.subject);
    if (!seen.add(key)) continue;
    if (d.name.isEmpty && (active == null || driveKey(active) != key)) {
      continue;
    }
    out.add(d);
  }
  return out;
}

/// The JSON the host's store answers with (`atomic_lib::host`), read into the
/// types above. A host whose store speaks this JSON can use these directly.
abstract final class AssistantJson {
  static String? _emoji(Map e) {
    final v = e['emoji'];
    return v is String && v.isNotEmpty ? v : null;
  }

  /// `[{subject, name, emoji}]`, filtered by [visibleDrives].
  static List<DriveInfo> parseDrives(String json, {String? active}) =>
      visibleDrives([
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            name: e['name'] as String? ?? '',
            emoji: _emoji(e),
          ),
      ], active: active);

  static List<ConversationMessage> parseConversationMessages(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            id: e['id'] as String,
            author: e['author'] as String? ?? '',
            authorName: e['author_name'] as String? ?? '',
            mine: e['mine'] == true,
            text: e['text'] as String?,
            createdAt: (e['c'] as num?)?.toInt() ?? 0,
          ),
      ];

  /// Conversation rows: resources with their `last_message`.
  static List<ConversationRow> parseConversations(String json) {
    final rows = jsonDecode(json) as List;
    final resources = parseRecentResources(json);
    return [
      for (var i = 0; i < rows.length; i++)
        (
          resource: resources[i],
          lastMessage: (rows[i]['last_message'] as String?) ?? '',
        ),
    ];
  }

  static List<NotificationItem> parseNotifications(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            title: e['title'] as String? ?? '',
            body: e['body'] as String? ?? '',
            about: e['about'] as String? ?? '',
            kind: e['kind'] as String? ?? '',
            occurredAt: (e['occurred_at'] as num?)?.toInt() ?? 0,
            read: e['read'] == true,
          ),
      ];

  static Map<String, String> parseIcons(String json) => {
        for (final e in (jsonDecode(json) as Map).entries)
          if (e.value is String && (e.value as String).isNotEmpty)
            e.key as String: e.value as String,
      };

  static List<ChatSummary> parseChats(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            name: e['name'] as String? ?? '',
            lastActivity: (e['last_activity'] as num?)?.toInt() ?? 0,
          ),
      ];

  /// Text parts only (tool calls, reasoning and files are left out); entries
  /// without text, and roles other than user and assistant, are skipped.
  static List<ChatMessage> parseChatMessages(String json) {
    final out = <ChatMessage>[];
    for (final e in jsonDecode(json) as List) {
      final role = e['role'] as String? ?? '';
      if (role != 'user' && role != 'assistant') continue;
      final text = [
        for (final p in (e['parts'] as List? ?? const []))
          if (p is Map && p['type'] == 'text') p['text'] as String? ?? '',
      ].join('\n\n').trim();
      if (text.isEmpty) continue;
      out.add((
        id: e['id'] as String,
        role: role,
        text: text,
        createdAt: (e['c'] as num?)?.toInt() ?? 0,
      ));
    }
    return out;
  }

  static List<RecentResource> parseRecentResources(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            title: e['title'] as String? ?? '',
            className: e['class_name'] as String? ?? '',
            openedAt: (e['opened_at'] as num?)?.toInt() ?? 0,
            emoji: _emoji(e),
          ),
      ];

  static List<SearchHit> parseHits(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            title: e['title'] as String? ?? '',
            className: e['class_name'] as String? ?? '',
            drive: e['drive'] as String? ?? '',
            score: (e['score'] as num?)?.toDouble() ?? 0,
            emoji: _emoji(e),
          ),
      ];

  /// The body of a text chat entry, as `appendChatEntry` takes it.
  static String textParts(String text) => jsonEncode([
        {'type': 'text', 'text': text}
      ]);
}
