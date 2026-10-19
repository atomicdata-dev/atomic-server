import '../atomic/atomic_client.dart';
import 'hosted_ai.dart';

/// What the assistant screens read. The default goes to the local node through
/// [AtomicClient]; tests pass a subclass with canned answers.
class AssistantApi {
  const AssistantApi();

  Future<List<DriveInfo>> drives() => AtomicClient.listDrivesWithNames();
  Future<List<ChatSummary>> chats() => AtomicClient.listAiChats();
  Future<List<ChatMessage>> messages(String chat) =>
      AtomicClient.readChat(chat);

  /// Searches every drive, or only [drive] when given.
  Future<List<SearchHit>> search(String query, {String? drive}) =>
      AtomicClient.search(query, drive: drive);
  Future<List<RecentResource>> recentResources(String drive) =>
      AtomicClient.recentResources(drive);
  Future<List<RecentResource>> favorites() => AtomicClient.favorites();
  Future<List<ConversationRow>> conversations() => AtomicClient.conversations();

  /// The messages of a conversation, oldest first.
  Future<List<ConversationMessage>> conversationMessages(String subject) =>
      AtomicClient.readConversation(subject);
  Future<void> sendConversationMessage(String subject, String text) =>
      AtomicClient.sendConversationMessage(subject, text);

  /// Get the conversation onto this device and follow it; best effort.
  Future<void> followConversation(String subject) =>
      AtomicClient.followConversation(subject);
  Future<List<ActivityEntry>> activity(int limit) =>
      AtomicClient.activity(limit: limit);

  /// The emojis (`{subject: emoji}`) of those of [subjects] that have one.
  Future<Map<String, String>> resourceIcons(List<String> subjects) =>
      AtomicClient.resourceIcons(subjects);
  void noteOpened(String drive, String subject) =>
      AtomicClient.noteResourceOpened(drive, subject);
  Future<String?> agentName() async =>
      (await AtomicClient.getActiveAgent())?.name;

  /// The AI of the linked account; null when none is linked.
  Future<HostedAi?> hostedAi() => HostedAi.load();
  Future<String> newChat(String name) => AtomicClient.createAiChat(name);
  Future<void> addMessage(String chat, String role, String text) =>
      AtomicClient.appendChatEntry(chat, role, text);
  Future<String> resourceText(String subject, {int maxChars = 4000}) =>
      AtomicClient.resourceText(subject, maxChars: maxChars);
  String webUrl(String subject) => AtomicClient.resourceWebUrl(subject);
}
