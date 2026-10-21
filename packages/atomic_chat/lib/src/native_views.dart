import 'package:flutter/widgets.dart';

import 'assistant_api.dart';
import 'chat_room_screen.dart';
import 'chat_screen.dart';
import 'conversation_screen.dart';
import 'resource_view.dart';

/// Builds the native view of one resource.
typedef NativeViewBuilder = Widget Function(
    AssistantApi api, String drive, String subject, String title);

/// The classes with a native view, by class subject.
const aiChatClass =
    'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/ai-chat';
const conversationClass = 'https://atomicdata.dev/classes/Conversation';
const chatRoomClass = 'https://atomicdata.dev/classes/ChatRoom';

/// Resource classes that have a native view, by the class's subject URL
/// (what recents, activity, search and drive rows carry as `classUrl`),
/// matched exactly. Everything else is drawn by the web page in a
/// [ResourceView]. A native view is one more entry here: a host adds its own
/// (or replaces or removes a default) with [registerNativeView] before the
/// views open. The package registers AI chats, conversations and chat rooms
/// (a meeting's chat is a chat room's).
final Map<String, NativeViewBuilder> nativeViews = {
  aiChatClass: (api, drive, subject, title) =>
      ChatScreen(api: api, subject: subject, title: title),
  conversationClass: (api, drive, subject, title) =>
      ConversationScreen(api: api, subject: subject, title: title),
  chatRoomClass: (api, drive, subject, title) =>
      ChatRoomScreen(api: api, drive: drive, subject: subject, title: title),
};

/// Whether resources of the class [classUrl] have a native view.
bool hasNativeView(String classUrl) => nativeViews.containsKey(classUrl);

/// Shows resources of the class [classUrl] in [builder] instead of the web
/// page; a null [builder] sends them to the web page again.
void registerNativeView(String classUrl, NativeViewBuilder? builder) {
  if (builder == null) {
    nativeViews.remove(classUrl);
  } else {
    nativeViews[classUrl] = builder;
  }
}

/// The view to open a resource in: the native one for its class ([classUrl],
/// the class's subject) when there is one, else the web app's rendering of
/// it. [className] is only the class's display name and does not choose the
/// view.
Widget openResourceView({
  required AssistantApi api,
  required String drive,
  required String subject,
  String title = '',
  String classUrl = '',
  String className = '',
}) {
  final native = nativeViews[classUrl];
  if (native != null) return native(api, drive, subject, title);
  return ResourceView(api: api, drive: drive, subject: subject, title: title);
}
