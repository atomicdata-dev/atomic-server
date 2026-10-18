import '../atomic/atomic_client.dart';

/// What the assistant screens read. The default goes to the local node through
/// [AtomicClient]; tests pass a subclass with canned answers.
class AssistantApi {
  const AssistantApi();

  Future<List<DriveInfo>> drives() => AtomicClient.listDrivesWithNames();
  Future<List<ChatSummary>> chats(String drive) =>
      AtomicClient.listAiChats(drive);
  Future<List<ChatMessage>> messages(String chat) =>
      AtomicClient.readChat(chat);
  Future<List<SearchHit>> search(String drive, String query) =>
      AtomicClient.search(drive, query);
  Future<List<RecentResource>> recentResources(String drive) =>
      AtomicClient.recentResources(drive);
  void noteOpened(String drive, String subject) =>
      AtomicClient.noteResourceOpened(drive, subject);
  String webUrl(String subject) => AtomicClient.resourceWebUrl(subject);
}
