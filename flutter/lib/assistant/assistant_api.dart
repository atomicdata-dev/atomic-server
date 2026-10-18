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
  Future<List<SearchHit>> search(String drive, String query) =>
      AtomicClient.search(drive, query);
  Future<List<RecentResource>> recentResources(String drive) =>
      AtomicClient.recentResources(drive);
  void noteOpened(String drive, String subject) =>
      AtomicClient.noteResourceOpened(drive, subject);
  Future<String?> agentName() async =>
      (await AtomicClient.getActiveAgent())?.name;

  /// The AI of the linked account; null when none is linked.
  Future<HostedAi?> hostedAi() => HostedAi.load();
  Future<String> newChat(String name) => AtomicClient.createAiChat(name);
  Future<void> addMessage(String chat, String role, String text) =>
      AtomicClient.appendChatEntry(chat, role, text);
  String webUrl(String subject) => AtomicClient.resourceWebUrl(subject);
}
