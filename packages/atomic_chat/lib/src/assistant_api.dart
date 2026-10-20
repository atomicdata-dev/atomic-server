import 'chat_parts.dart';
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

  /// The chat of a meeting or chat room, oldest first.
  Future<List<ChatRoomMessage>> chatRoomMessages(String subject);

  /// Sends [text] in a meeting or chat room as this device's agent.
  Future<void> sendChatRoomMessage(String subject, String text);

  /// What changed lately in every drive, newest first, by whom.
  Future<List<ActivityEntry>> activity(int limit);

  /// The emojis (`{subject: emoji}`) of those of [subjects] that have one.
  Future<Map<String, String>> resourceIcons(List<String> subjects);

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

  /// Readable text of [subject] (for an AI's context), at most [maxChars].
  Future<String> resourceText(String subject, {int maxChars = 4000});

  /// Where the connected server's web app shows [subject]. Throws when no
  /// server is connected.
  String webUrl(String subject);

  /// One call from the embedded renderer's page to the store: a method and
  /// its arguments as JSON, answered as JSON (see `ResourceView`).
  Future<String> embedCall(String method, String argsJson);

  /// Gives [subject] a new name (a chat room shown natively, which has no web
  /// page to edit its title on).
  Future<void> renameResource(String subject, String name);
}
