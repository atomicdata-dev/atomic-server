import 'dart:typed_data';

import 'package:flutter/foundation.dart' show Listenable;
import 'chat_parts.dart';
import 'chat_window.dart';
import 'hosted_ai.dart';
import 'models.dart';

/// What the assistant screens read and write: the seam between this package
/// and the host's store. The host implements it over its own client (the
/// atomic.place app does so over its Rust bridge); tests pass a fake with
/// canned answers. Nothing in this package talks to a store any other way.
abstract class AssistantApi {
  const AssistantApi();

  /// The agent's drives worth showing (see [visibleDrives]).
  Future<List<DriveInfo>> drives();

  /// How many chats [chats] returns at most, and the size of the pages the
  /// full list is read in ([chatsPage]).
  static const chatsPageSize = 50;

  /// The person's newest AI chats, across all drives (the first
  /// [chatsPageSize]).
  Future<List<ChatSummary>> chats();

  /// [limit] chats after the [offset] newest ones, newest first; fewer than
  /// [limit] means there are no more. A host that cannot page lists only
  /// [chats].
  Future<List<ChatSummary>> chatsPage(
          {required int offset, required int limit}) async =>
      offset == 0 ? chats() : const [];

  /// The text messages of an AI chat, oldest first.
  Future<List<ChatMessage>> messages(String chat);

  /// Searches every drive, or only [drive] when given.
  Future<List<SearchHit>> search(String query, {String? drive});

  /// [search] for only resources of one of [classes] (`drive`, `aichat`,
  /// `conversation`, `chatroom`), chosen before the result limit, so a query
  /// whose best hits are documents still finds a chat. A host that cannot
  /// filter searches everything; the screen drops the rest.
  Future<List<SearchHit>> searchClasses(String query,
          {String? drive, required List<String> classes}) =>
      search(query, drive: drive);

  /// Reads the search index once so the first keystroke is not cold; called
  /// after the home is drawn. Best effort.
  Future<void> warmSearch() async {}

  /// What this device opened lately in [drive], newest first.
  Future<List<RecentResource>> recentResources(String drive);

  /// The person's favorites (all drives), newest added first.
  Future<List<RecentResource>> favorites();

  /// The notifications in the Inbox of the person's private drive, newest
  /// first (what the web app recorded there).
  Future<List<NotificationItem>> notifications();

  /// Marks a notification read, as the web app does.
  Future<void> markNotificationRead(String subject);

  /// The person's conversations (DMs and group chats), newest message first.
  Future<List<ConversationRow>> conversations();

  /// The messages of a conversation, oldest first.
  Future<List<ConversationMessage>> conversationMessages(String subject);

  /// Sends [text] in a conversation as this device's agent.
  Future<void> sendConversationMessage(String subject, String text);

  /// Get the conversation onto this device and follow it; best effort.
  Future<void> followConversation(String subject);

  /// Fires when the local store may have changed without this app doing it:
  /// a background sync finished, so conversations and messages other people
  /// sent can be there. The lists and open conversations read again. Null:
  /// the host cannot tell (they poll).
  Listenable? get storeChanges => null;

  /// The chat of a meeting or chat room, oldest first.
  Future<List<ChatRoomMessage>> chatRoomMessages(String subject);

  /// Sends [text] in a meeting or chat room as this device's agent.
  Future<void> sendChatRoomMessage(String subject, String text);

  /// What changed lately in every drive, newest first, by whom: what other
  /// members did.
  Future<List<ActivityEntry>> activity(int limit);

  /// [activity] with the person's own changes too (the feed's "Show mine"),
  /// whose actor is `You`.
  Future<List<ActivityEntry>> activityWithMine(int limit) => activity(limit);

  /// How many entries one page of the full Activity page holds.
  static const activityPageSize = 50;

  /// One page of the full Activity page, newest first: the entries after
  /// [before] (the last of the previous page; null for the first). A page
  /// shorter than [limit] is the end of the feed. The default reads
  /// everything [activity] has and cuts the page out of it.
  Future<List<ActivityEntry>> activityPage(
      {ActivityEntry? before,
      int limit = activityPageSize,
      bool includeOwn = false}) async {
    final all = includeOwn
        ? await activityWithMine(100000)
        : await activity(100000);
    final i = before == null
        ? -1
        : all.indexWhere(
            (a) => a.subject == before.subject && a.at == before.at);
    return all.skip(i + 1).take(limit).toList();
  }

  /// The emojis (`{subject: emoji}`) of those of [subjects] that have one.
  Future<Map<String, String>> resourceIcons(List<String> subjects);

  /// The bytes of a File resource (a row's picture) when this device holds
  /// them; null otherwise. Rows read them lazily and keep them in
  /// `RowPictures`. A host without files leaves this.
  Future<Uint8List?> fileBytes(String file) async => null;

  /// Remember that this device opened [subject] in [drive].
  void noteOpened(String drive, String subject);

  /// The name of this device's agent, if known.
  Future<String?> agentName();

  /// The name, picture and emoji of this device's agent for the bar's profile
  /// button; null when unknown (the button then shows a person icon).
  Future<ProfileIdentity?> ownIdentity() async => null;

  /// The AI of the linked account; null when none is linked.
  Future<HostedAi?> hostedAi();

  /// Starts an AI chat named [name]; returns its subject.
  Future<String> newChat(String name);

  /// Creates a resource of [classUrl] named [name] (`Untitled` when empty)
  /// directly in [drive], as this device's agent; returns its subject.
  Future<String> createResource(String drive, String classUrl, String name);

  /// Adds a text message by [role] (`user` or `assistant`) to [chat].
  Future<void> addMessage(String chat, String role, String text);

  /// The messages of an AI chat with all their parts (files, tool calls),
  /// oldest first. A host that stores only text can leave this: it reads
  /// [messages].
  Future<List<ChatEntry>> chatEntries(String chat) async =>
      [for (final m in await messages(chat)) ChatEntry.text(m)];

  /// Adds a message by [role] with all its [parts] to [chat], in the web
  /// app's format. A host that stores only text can leave this: it writes
  /// the text parts with [addMessage].
  Future<void> addEntry(String chat, String role, List<ChatPart> parts) =>
      addMessage(chat, role, ChatEntry.textOf(parts));

  // Windows of long chats (see [ChatWindow]): the newest [limit] items
  // before the cursor [before] (null: the newest of all), and the items
  // after a `newest` cursor. A host that reads a chat whole can leave these:
  // they cut the whole list, with positions in it for cursors.

  /// A window of an AI chat's messages.
  Future<ChatPage<ChatEntry>> chatEntriesPage(String chat,
          {String? before, int limit = 50}) async =>
      pageOfAll(await chatEntries(chat), before, limit);

  /// The messages of an AI chat after [after].
  Future<ChatPage<ChatEntry>> chatEntriesAfter(String chat, String after,
          {int limit = 100}) async =>
      afterOfAll(await chatEntries(chat), after, limit);

  /// A window of a meeting's or chat room's lines.
  Future<ChatPage<ChatRoomMessage>> chatRoomMessagesPage(String subject,
          {String? before, int limit = 50}) async =>
      pageOfAll(await chatRoomMessages(subject), before, limit);

  /// The lines of a meeting or chat room after [after].
  Future<ChatPage<ChatRoomMessage>> chatRoomMessagesAfter(
          String subject, String after,
          {int limit = 100}) async =>
      afterOfAll(await chatRoomMessages(subject), after, limit);

  /// A window of a conversation's messages (only those are decrypted).
  Future<ChatPage<ConversationMessage>> conversationMessagesPage(String subject,
          {String? before, int limit = 50}) async =>
      pageOfAll(await conversationMessages(subject), before, limit);

  /// The messages of a conversation after [after].
  Future<ChatPage<ConversationMessage>> conversationMessagesAfter(
          String subject, String after,
          {int limit = 100}) async =>
      afterOfAll(await conversationMessages(subject), after, limit);

  /// Readable text of [subject] (for an AI's context), at most [maxChars].
  Future<String> resourceText(String subject, {int maxChars = 4000});

  /// Where the connected server's web app shows [subject]. Throws when no
  /// server is connected.
  String webUrl(String subject);

  /// One call from the embedded renderer's page to the store: a method and
  /// its arguments as JSON, answered as JSON (see `ResourceView`).
  Future<String> embedCall(String method, String argsJson);

  /// The children of a drive or folder [parent] as the web sidebar lists them
  /// (its order, without the folders it hides). Empty by default.
  Future<DriveChildren> driveChildren(String parent) async =>
      const DriveChildren.empty();

  /// Makes [subject] the store's active drive, which the app opens on again
  /// after a restart. Does nothing by default.
  Future<void> setActiveDrive(String subject) async {}

  /// Gives [subject] a new name (a chat room shown natively, which has no web
  /// page to edit its title on).
  Future<void> renameResource(String subject, String name);
}
