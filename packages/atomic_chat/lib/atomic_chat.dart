/// The assistant screens of atomic.place (home, AI chat, conversations,
/// search, resources in the embedded web renderer, voice) on an injectable
/// [AssistantApi]. See README.md for how a host app wires it.
library;

export 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt, HoldFan, HoldFanItem, HoldFanLayout;

// The seam to the host's store, and what goes through it.
export 'src/assistant_api.dart';
export 'src/models.dart';
export 'src/chat_parts.dart';
export 'src/chat_window.dart';
export 'src/scroll_to_bottom_button.dart';
export 'src/hosted_ai.dart';
export 'src/ai_tools.dart';

// The shell: pages above a bottom bar that never moves.
export 'src/app_shell.dart';
export 'src/app_bottom_bar.dart';
export 'src/profile_avatar.dart';
export 'src/app_top_bar.dart';
export 'src/app_theme.dart';
export 'src/app_sidebar_icons.dart';
export 'src/slide_back_route.dart';
export 'src/covered_insets_freeze.dart';
export 'src/toast.dart';

// Screens.
export 'src/chats_screen.dart';
export 'src/home_sections.dart';
export 'src/chat_room_screen.dart';
export 'src/chat_screen.dart';
export 'src/conversation_screen.dart';
export 'src/search_screen.dart';
export 'src/new_document_sheet.dart';

// Resources: native views, else the embedded web renderer.
export 'src/native_views.dart';
export 'src/resource_view.dart';
export 'src/warm_resource_web_view.dart';
export 'src/resource_web_view.dart';
export 'src/embed_server.dart';
export 'src/resource_row.dart';

// Voice.
export 'src/voice.dart';
export 'src/hosted_voice.dart';

// Small widgets.
export 'src/markdown_view.dart';
export 'src/tool_step.dart';
export 'src/attachments.dart';
export 'src/list_and_field.dart';
