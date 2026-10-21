import 'package:flutter/widgets.dart';

import 'assistant_api.dart';
import 'chat_room_screen.dart';
import 'chat_screen.dart';
import 'conversation_screen.dart';
import 'resource_view.dart';

/// Builds the native view of one resource.
typedef NativeViewBuilder = Widget Function(
    AssistantApi api, String drive, String subject, String title);

/// Resource classes that have a native view, by class name (what recents,
/// activity and search rows carry: the class's shortname, as the Rust side
/// reports it). Everything else is drawn by the web page in a [ResourceView].
/// A native view is one more entry here: a host adds its own (or replaces or
/// removes a default) with [registerNativeView] before the views open. The
/// package registers AI chats, conversations and chat rooms (a meeting's chat
/// is a chat room's).
final Map<String, NativeViewBuilder> nativeViews = {
  'aichat': (api, drive, subject, title) =>
      ChatScreen(api: api, subject: subject, title: title),
  'conversation': (api, drive, subject, title) =>
      ConversationScreen(api: api, subject: subject, title: title),
  'chatroom': (api, drive, subject, title) =>
      ChatRoomScreen(api: api, drive: drive, subject: subject, title: title),
};

/// Whether resources of [className] (a shortname or a class URL) have a
/// native view.
bool hasNativeView(String className) =>
    nativeViews.containsKey(_key(className));

/// Shows resources of [className] (a shortname or a class URL) in [builder]
/// instead of the web page; a null [builder] sends them to the web page again.
void registerNativeView(String className, NativeViewBuilder? builder) {
  final key = _key(className);
  if (builder == null) {
    nativeViews.remove(key);
  } else {
    nativeViews[key] = builder;
  }
}

/// The view to open a resource in: the native one for its class when there is
/// one, else the web app's rendering of it.
Widget openResourceView({
  required AssistantApi api,
  required String drive,
  required String subject,
  String title = '',
  String className = '',
}) {
  final native = nativeViews[_key(className)];
  if (native != null) return native(api, drive, subject, title);
  return ResourceView(api: api, drive: drive, subject: subject, title: title);
}

/// A class name arrives as a full class URL, a shortname (`ai-chat`) or the
/// class's own name (`AI Chat`): compare on the last segment's letters and
/// digits, as `iconForClass` does.
String _key(String className) => className
    .split('/')
    .last
    .toLowerCase()
    .replaceAll(RegExp(r'[^a-z0-9]'), '');
