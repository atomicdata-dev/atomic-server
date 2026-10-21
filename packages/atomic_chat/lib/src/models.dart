import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart' show listEquals;

import 'chat_parts.dart';
import 'chat_window.dart';

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

/// What a line of a meeting or chat room is: a message from someone, or a
/// system line of a meeting ("Joep is viewing Roadmap", "Started the meeting").
enum ChatRoomKind { text, event }

/// One line of a meeting or chat room (`atomic_lib::host::chat_rooms`): a
/// message with its author, or an event line. `authorName` is '' until the
/// name is known. An event that follows someone to a resource has `about` (that
/// resource) and `aboutTitle`.
typedef ChatRoomMessage = ({
  String id,
  ChatRoomKind kind,
  String author,
  String authorName,
  bool mine,
  String text,
  int createdAt,
  String? about,
  String aboutTitle
});

/// A row of the Messages list: the conversation and the text of its newest
/// message ('' when there is none or it cannot be read). `resource.openedAt`
/// is the time of that message in ms (0 when none).
typedef ConversationRow = ({RecentResource resource, String lastMessage});

/// The picture a row shows for what it lists, besides its emoji: a File
/// (`file`, whose bytes this device may hold) and/or a URL a server serves.
/// `person` marks an agent's picture (round, with the initial of `name` as
/// fallback); `group` a conversation with several others (no picture).
class ResourcePicture {
  final String? file;
  final String? url;
  final String? name;
  final String? emoji;
  final bool person;
  final bool group;

  const ResourcePicture(
      {this.file,
      this.url,
      this.name,
      this.emoji,
      this.person = false,
      this.group = false});

  /// Null when [e] (a row's JSON object) names no picture and is no person.
  static ResourcePicture? fromJson(Object? e, {bool person = false}) {
    if (e is! Map) return null;
    String? s(String k) {
      final v = e[k];
      return v is String && v.trim().isNotEmpty ? v.trim() : null;
    }

    final p = ResourcePicture(
        file: s('icon_file'),
        url: s('image_url'),
        name: s('name'),
        emoji: s('emoji'),
        person: person);
    return p.file == null && p.url == null && !person ? null : p;
  }

  bool get hasImage => file != null || url != null;

  @override
  bool operator ==(Object other) =>
      other is ResourcePicture &&
      other.file == file &&
      other.url == url &&
      other.name == name &&
      other.emoji == emoji &&
      other.person == person &&
      other.group == group;

  @override
  int get hashCode => Object.hash(file, url, name, emoji, person, group);
}

typedef SearchHit = ({
  String subject,
  String title,
  String className,
  // The drive the hit lives in; '' when unknown.
  String drive,
  double score,
  // The resource's own icon (an emoji); null when it has none.
  String? emoji,
  // The resource's own picture (its `icon` File); null when it has none.
  ResourcePicture? picture
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
  bool read,
  // Who did it (their picture and name); null when unknown to this device.
  ResourcePicture? actor
});

typedef DriveInfo = ({
  String subject,
  String name,
  String? emoji,
  ResourcePicture? picture
});

typedef RecentResource = ({
  String subject,
  String title,
  String className,
  int openedAt,
  // The resource's own icon (an emoji); null when it has none.
  String? emoji,
  // The resource's own picture (its `icon` File); null when it has none. A
  // DM's is the other member's, a group's is marked `group`.
  ResourcePicture? picture
});

/// One change in the activity feed: something another member did (the
/// person's own changes are not activity; they show in Recents).
class ActivityEntry {
  final String subject;
  final String drive;

  /// `created`, `changed` or `deleted`.
  final String kind;

  /// Unix ms.
  final int at;

  /// Display name of the member that did it: their name, or the start of
  /// their key (`a3f9…`) while it is not known; null only from an older host.
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
  /// A window `{<field>: [...], older, newest, more}` from the host, its
  /// items read with [parse] (one of the list parsers below).
  static ChatPage<T> parsePage<T>(
      String json, String field, List<T> Function(String) parse) {
    final m = jsonDecode(json) as Map;
    return ChatPage<T>(parse(jsonEncode(m[field] ?? const [])),
        older: m['older'] as String?,
        newest: m['newest'] as String?,
        more: m['more'] == true);
  }

  static String? _emoji(Map e) {
    final v = e['emoji'];
    return v is String && v.isNotEmpty ? v : null;
  }

  /// A row's picture: its DM peer's (round), a group's marker, else its own.
  static ResourcePicture? _picture(Map e) {
    if (e['group'] == true) return const ResourcePicture(group: true);
    if (e['peer'] is Map) {
      return ResourcePicture.fromJson(e['peer'], person: true);
    }
    return ResourcePicture.fromJson(e);
  }

  /// `[{subject, name, emoji}]`, filtered by [visibleDrives].
  static List<DriveInfo> parseDrives(String json, {String? active}) =>
      visibleDrives([
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            name: e['name'] as String? ?? '',
            emoji: _emoji(e),
            picture: ResourcePicture.fromJson(e),
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

  static List<ChatRoomMessage> parseChatRoomMessages(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            id: e['id'] as String,
            kind: e['kind'] == 'event' ? ChatRoomKind.event : ChatRoomKind.text,
            author: e['author'] as String? ?? '',
            authorName: e['author_name'] as String? ?? '',
            mine: e['mine'] == true,
            text: e['text'] as String? ?? '',
            createdAt: (e['c'] as num?)?.toInt() ?? 0,
            about: e['about'] as String?,
            aboutTitle: e['about_title'] as String? ?? '',
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
            actor: ResourcePicture.fromJson(e['actor_picture'], person: true),
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

  /// Every message of a chat with all its parts (text, files, tool calls,
  /// and the rest as is), user and assistant only; an entry without any
  /// part is skipped. `ctx` (resources attached as context) is read too.
  static List<ChatEntry> parseChatEntries(String json) {
    final out = <ChatEntry>[];
    for (final e in jsonDecode(json) as List) {
      final role = e['role'] as String? ?? '';
      if (role != 'user' && role != 'assistant') continue;
      final parts = [
        for (final p in (e['parts'] as List? ?? const []))
          if (p is Map) ChatPart.fromJson(Map<String, dynamic>.from(p)),
      ];
      if (parts.isEmpty) continue;
      out.add(ChatEntry(
        id: e['id'] as String,
        role: role,
        createdAt: (e['c'] as num?)?.toInt() ?? 0,
        parts: parts,
        context: _context(e['ctx']),
      ));
    }
    return out;
  }

  static List<ContextResource> _context(Object? raw) {
    Object? list = raw;
    if (raw is String && raw.isNotEmpty) {
      try {
        list = jsonDecode(raw);
      } catch (_) {
        return const [];
      }
    }
    if (list is! List) return const [];
    return [
      for (final c in list)
        if (c is Map &&
            c['type'] == 'atomic-resource' &&
            c['subject'] is String)
          (
            subject: c['subject'] as String,
            title: c['title'] as String? ?? '',
            className: c['class_name'] as String? ?? '',
            emoji: null,
          ),
    ];
  }

  static List<RecentResource> parseRecentResources(String json) => [
        for (final e in jsonDecode(json) as List)
          (
            subject: e['subject'] as String,
            title: e['title'] as String? ?? '',
            className: e['class_name'] as String? ?? '',
            openedAt: (e['opened_at'] as num?)?.toInt() ?? 0,
            emoji: _emoji(e),
            picture: _picture(e),
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
            picture: ResourcePicture.fromJson(e),
          ),
      ];

  /// The body of a text chat entry, as `appendChatEntry` takes it.
  static String textParts(String text) => jsonEncode([
        {'type': 'text', 'text': text}
      ]);
}

/// Who the person is, for the bar's profile button: the name, picture and
/// emoji of this device's agent. Every part is optional.
class ProfileIdentity {
  final String? name;

  /// The picture's download URL.
  final String? imageUrl;

  /// The picture's bytes, when this device holds the profile's picture file.
  final Uint8List? imageBytes;
  final String? emoji;

  /// The profile has a picture this device could not show yet (the file or
  /// its bytes have not arrived): worth loading again soon.
  final bool pendingImage;

  const ProfileIdentity(
      {this.name,
      this.imageUrl,
      this.imageBytes,
      this.emoji,
      this.pendingImage = false});

  @override
  bool operator ==(Object other) =>
      other is ProfileIdentity &&
      other.name == name &&
      other.imageUrl == imageUrl &&
      other.pendingImage == pendingImage &&
      (identical(other.imageBytes, imageBytes) ||
          (other.imageBytes != null &&
              imageBytes != null &&
              listEquals(other.imageBytes, imageBytes))) &&
      other.emoji == emoji;

  @override
  int get hashCode =>
      Object.hash(name, imageUrl, imageBytes?.length, emoji, pendingImage);
}
