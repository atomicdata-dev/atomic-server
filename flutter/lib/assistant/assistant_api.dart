import '../atomic/atomic_client.dart';

/// What the assistant screens read. The default goes to the local node through
/// [AtomicClient]; tests pass a subclass with canned answers.
class AssistantApi {
  const AssistantApi();

  Future<List<ChatSummary>> chats() => AtomicClient.listAiChats();
  Future<List<ChatMessage>> messages(String chat) =>
      AtomicClient.readChat(chat);
  Future<List<SearchHit>> search(String query) => AtomicClient.search(query);
  String webUrl(String subject) => AtomicClient.resourceWebUrl(subject);
}
