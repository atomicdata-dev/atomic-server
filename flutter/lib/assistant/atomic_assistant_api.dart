import 'package:atomic_chat/atomic_chat.dart';

import '../atomic/account_store.dart';
import '../atomic/atomic_client.dart';

/// The app's [AssistantApi]: the local node through [AtomicClient] (the Rust
/// bridge), and the linked account from [AccountStore].
class AtomicAssistantApi extends AssistantApi {
  const AtomicAssistantApi();

  @override
  Future<List<DriveInfo>> drives() => AtomicClient.listDrivesWithNames();
  @override
  Future<List<ChatSummary>> chats() => AtomicClient.listAiChats();
  @override
  Future<List<ChatMessage>> messages(String chat) =>
      AtomicClient.readChat(chat);
  @override
  Future<List<SearchHit>> search(String query, {String? drive}) =>
      AtomicClient.search(query, drive: drive);
  @override
  Future<List<RecentResource>> recentResources(String drive) =>
      AtomicClient.recentResources(drive);
  @override
  Future<List<RecentResource>> favorites() => AtomicClient.favorites();
  @override
  Future<List<NotificationItem>> notifications() =>
      AtomicClient.notifications();
  @override
  Future<void> markNotificationRead(String subject) =>
      AtomicClient.markNotificationRead(subject);
  @override
  Future<List<ConversationRow>> conversations() => AtomicClient.conversations();
  @override
  Future<List<ConversationMessage>> conversationMessages(String subject) =>
      AtomicClient.readConversation(subject);
  @override
  Future<void> sendConversationMessage(String subject, String text) =>
      AtomicClient.sendConversationMessage(subject, text);
  @override
  Future<void> followConversation(String subject) =>
      AtomicClient.followConversation(subject);
  @override
  Future<List<ChatRoomMessage>> chatRoomMessages(String subject) =>
      AtomicClient.readChatRoom(subject);
  @override
  Future<void> sendChatRoomMessage(String subject, String text) =>
      AtomicClient.sendChatRoomMessage(subject, text);
  @override
  Future<List<ActivityEntry>> activity(int limit) =>
      AtomicClient.activity(limit: limit);
  @override
  Future<Map<String, String>> resourceIcons(List<String> subjects) =>
      AtomicClient.resourceIcons(subjects);
  @override
  void noteOpened(String drive, String subject) =>
      AtomicClient.noteResourceOpened(drive, subject);
  @override
  Future<String?> agentName() async =>
      (await AtomicClient.getActiveAgent())?.name;

  /// The linked account's AI. With no session saved, the active agent signs
  /// the account in first (as the web app does).
  @override
  Future<HostedAi?> hostedAi() async {
    var saved = await AccountStore.read();
    if (saved == null && await AccountStore.signInWithAgent()) {
      saved = await AccountStore.read();
    }
    if (saved == null) return null;
    return HostedAi.forSession(saved);
  }

  @override
  Future<String> newChat(String name) => AtomicClient.createAiChat(name);
  @override
  Future<String> createResource(String drive, String classUrl, String name) =>
      AtomicClient.createResourceOfClass(drive, classUrl, name);
  @override
  Future<void> addMessage(String chat, String role, String text) =>
      AtomicClient.appendChatEntry(chat, role, text);
  @override
  Future<List<ChatEntry>> chatEntries(String chat) =>
      AtomicClient.readChatEntries(chat);
  @override
  Future<void> addEntry(String chat, String role, List<ChatPart> parts) =>
      AtomicClient.appendChatEntryParts(chat, role, parts);
  @override
  Future<String> resourceText(String subject, {int maxChars = 4000}) =>
      AtomicClient.resourceText(subject, maxChars: maxChars);
  @override
  String webUrl(String subject) => AtomicClient.resourceWebUrl(subject);
  @override
  Future<String> embedCall(String method, String argsJson) =>
      AtomicClient.embedCall(method, argsJson);
  @override
  Future<void> renameResource(String subject, String name) =>
      AtomicClient.setProperty(
          subject, 'https://atomicdata.dev/properties/name', name);
}
