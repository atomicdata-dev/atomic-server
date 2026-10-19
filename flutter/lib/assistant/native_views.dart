import 'package:flutter/widgets.dart';

import 'assistant_api.dart';
import 'chat_screen.dart';
import 'conversation_screen.dart';
import 'resource_view.dart';

typedef _NativeBuilder = Widget Function(
    AssistantApi api, String drive, String subject, String title);

/// Resource classes that have a native view, by class name (what recents,
/// activity and search rows carry: the class's shortname, as the Rust side
/// reports it). Everything else is drawn by the web page in a [ResourceView].
/// A native view is one more entry here.
final Map<String, _NativeBuilder> _nativeViews = {
  'ai-chat': (api, drive, subject, title) =>
      ChatScreen(api: api, subject: subject, title: title),
  'conversation': (api, drive, subject, title) =>
      ConversationScreen(api: api, subject: subject, title: title),
};

/// The view to open a resource in: the native one for its class when there is
/// one, else the web app's rendering of it.
Widget openResourceView({
  required AssistantApi api,
  required String drive,
  required String subject,
  String title = '',
  String className = '',
}) {
  final native = _nativeViews[_key(className)];
  if (native != null) return native(api, drive, subject, title);
  return ResourceView(api: api, drive: drive, subject: subject, title: title);
}

/// A class name may arrive as a full class URL; compare on its last segment.
String _key(String className) {
  final name = className.trim().toLowerCase();
  final slash = name.lastIndexOf('/');
  return slash < 0 ? name : name.substring(slash + 1);
}
