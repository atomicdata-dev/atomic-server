import 'package:flutter/material.dart';

import '../screens/sync_screen.dart';
import '../theme.dart';
import '../widgets/slide_back_route.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'resource_view.dart';
import 'search_screen.dart';

/// The one row at the bottom of every main view, within the thumb's reach, the
/// same everywhere: back (when there is somewhere to go back to), the
/// resource's "more" menu (when the view has a resource), search, a new chat,
/// the user (agent, sync and account) and settings.
class AppBottomBar extends StatelessWidget {
  final AssistantApi api;

  /// The drive search looks in.
  final String drive;

  /// Opens the resource menu. Without a resource there is no menu to open.
  final VoidCallback? onMore;

  /// Goes back; by default pops the screen.
  final VoidCallback? onBack;

  /// Opens the user's page; by default the sync screen.
  final VoidCallback? onUser;

  /// Pushes a screen; the home screen uses it to refresh when it comes back.
  final Future<void> Function(Widget screen)? onPush;

  const AppBottomBar({
    super.key,
    required this.api,
    required this.drive,
    this.onMore,
    this.onBack,
    this.onUser,
    this.onPush,
  });

  Future<void> _push(BuildContext context, Widget screen) async {
    final push = onPush;
    if (push != null) return push(screen);
    await Navigator.of(context)
        .push(SlideBackRoute<void>(builder: (_) => screen));
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Material(
      color: c.bgBody,
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
          child:
              Row(mainAxisAlignment: MainAxisAlignment.spaceEvenly, children: [
            if (Navigator.of(context).canPop())
              IconButton(
                tooltip: 'Back',
                onPressed: onBack ?? () => Navigator.of(context).maybePop(),
                icon: const Icon(Icons.arrow_back),
              ),
            if (onMore != null)
              IconButton(
                tooltip: 'More',
                onPressed: onMore,
                icon: const Icon(Icons.more_vert),
              ),
            IconButton(
              tooltip: 'Search',
              onPressed: () =>
                  _push(context, SearchScreen(drive: drive, api: api)),
              icon: const Icon(Icons.search),
            ),
            IconButton.filled(
              tooltip: 'New chat',
              onPressed: () => _push(
                  context, ChatScreen(api: api, subject: null, title: '')),
              icon: const Icon(Icons.add),
            ),
            IconButton(
              tooltip: 'Profile',
              onPressed: onUser ?? () => _push(context, const SyncScreen()),
              icon: FutureBuilder<String?>(
                future: api.agentName(),
                builder: (_, s) => AgentAvatar(name: s.data),
              ),
            ),
            IconButton(
              tooltip: 'Settings',
              onPressed: () => _push(context,
                  ResourceView(api: api, drive: drive, path: '/app/settings')),
              icon: const Icon(Icons.settings_outlined),
            ),
          ]),
        ),
      ),
    );
  }
}
