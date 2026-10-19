import 'package:atomic_chat/atomic_chat.dart';

/// An [AssistantApi] that answers nothing: every call throws. Fakes extend it
/// and override what their test reads.
class UnimplementedApi extends AssistantApi {
  const UnimplementedApi();

  Never _no(String what) => throw UnimplementedError('AssistantApi.$what');

  @override
  Future<List<DriveInfo>> drives() => _no('drives');
  @override
  Future<List<ChatSummary>> chats() => _no('chats');
  @override
  Future<List<ChatMessage>> messages(String chat) => _no('messages');
  @override
  Future<List<SearchHit>> search(String query, {String? drive}) =>
      _no('search');
  @override
  Future<List<RecentResource>> recentResources(String drive) =>
      _no('recentResources');
  @override
  Future<List<RecentResource>> favorites() => _no('favorites');
  @override
  Future<List<ConversationRow>> conversations() => _no('conversations');
  @override
  Future<List<ConversationMessage>> conversationMessages(String subject) =>
      _no('conversationMessages');
  @override
  Future<void> sendConversationMessage(String subject, String text) =>
      _no('sendConversationMessage');
  @override
  Future<void> followConversation(String subject) => _no('followConversation');
  @override
  Future<List<ActivityEntry>> activity(int limit) => _no('activity');
  @override
  Future<Map<String, String>> resourceIcons(List<String> subjects) =>
      _no('resourceIcons');
  @override
  void noteOpened(String drive, String subject) => _no('noteOpened');
  @override
  Future<String?> agentName() => _no('agentName');
  @override
  Future<HostedAi?> hostedAi() => _no('hostedAi');
  @override
  Future<String> newChat(String name) => _no('newChat');
  @override
  Future<String> createResource(String drive, String classUrl, String name) =>
      _no('createResource');
  @override
  Future<void> addMessage(String chat, String role, String text) =>
      _no('addMessage');
  @override
  Future<String> resourceText(String subject, {int maxChars = 4000}) =>
      _no('resourceText');
  @override
  String webUrl(String subject) => _no('webUrl');
  @override
  Future<String> embedCall(String method, String argsJson) => _no('embedCall');
}
