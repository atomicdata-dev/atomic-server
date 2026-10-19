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

  /// The person's newest AI chats, across all drives.
  Future<List<ChatSummary>> chats();

  /// The text messages of an AI chat, oldest first.
  Future<List<ChatMessage>> messages(String chat);

  /// Searches every drive, or only [drive] when given.
  Future<List<SearchHit>> search(String query, {String? drive});

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

  /// What changed lately in every drive, newest first, by whom.
  Future<List<ActivityEntry>> activity(int limit);

  /// The emojis (`{subject: emoji}`) of those of [subjects] that have one.
  Future<Map<String, String>> resourceIcons(List<String> subjects);

  /// Remember that this device opened [subject] in [drive].
  void noteOpened(String drive, String subject);

  /// The name of this device's agent, if known.
  Future<String?> agentName();

  /// The AI of the linked account; null when none is linked.
  Future<HostedAi?> hostedAi();

  /// Starts an AI chat named [name]; returns its subject.
  Future<String> newChat(String name);

  /// Creates a resource of [classUrl] named [name] (`Untitled` when empty)
  /// directly in [drive], as this device's agent; returns its subject.
  Future<String> createResource(String drive, String classUrl, String name);

  /// Adds a text message by [role] (`user` or `assistant`) to [chat].
  Future<void> addMessage(String chat, String role, String text);

  /// Readable text of [subject] (for an AI's context), at most [maxChars].
  Future<String> resourceText(String subject, {int maxChars = 4000});

  /// Where the connected server's web app shows [subject]. Throws when no
  /// server is connected.
  String webUrl(String subject);

  /// One call from the embedded renderer's page to the store: a method and
  /// its arguments as JSON, answered as JSON (see `ResourceView`).
  Future<String> embedCall(String method, String argsJson);
}
