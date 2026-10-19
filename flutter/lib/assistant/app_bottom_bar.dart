import 'package:flutter/material.dart';

import '../screens/sync_screen.dart';
import '../theme.dart';
import '../widgets/slide_back_route.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'resource_view.dart';
import 'search_screen.dart';

/// The one row at the bottom of the app, within the thumb's reach, the same on
/// every page and never moving with them: search, a new chat, the user (agent,
/// sync and account) and, last, settings, or the "more" menu of the resource
/// the page on top shows. Back is the system back and the swipe from the left
/// edge.
class AppBottomBar extends StatelessWidget {
  final AssistantApi api;
  final ShellController shell;

  const AppBottomBar({super.key, required this.api, required this.shell});

  Future<void> _push(Widget screen) async {
    await shell.navigatorKey.currentState
        ?.push(SlideBackRoute<void>(builder: (_) => screen));
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Material(
      color: c.bgBody,
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
          child: ListenableBuilder(
            listenable: Listenable.merge([shell, shell.drive]),
            builder: (context, _) {
              final onMore = shell.topMenu;
              return Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    IconButton(
                      tooltip: 'Search',
                      onPressed: () => _push(
                          SearchScreen(drive: shell.drive.value, api: api)),
                      icon: const Icon(Icons.search),
                    ),
                    IconButton(
                      tooltip: 'New chat',
                      onPressed: () =>
                          _push(ChatScreen(api: api, subject: null, title: '')),
                      icon: const Icon(Icons.add),
                    ),
                    IconButton(
                      tooltip: 'Profile',
                      onPressed: shell.onUser ??
                          () => Navigator.of(context, rootNavigator: true).push(
                              MaterialPageRoute<bool>(
                                  builder: (_) => const SyncScreen())),
                      icon: const Icon(Icons.person_outline),
                    ),
                    // The only button that changes with the page.
                    AnimatedSwitcher(
                      duration: const Duration(milliseconds: 200),
                      child: onMore != null
                          ? IconButton(
                              key: const ValueKey('more'),
                              tooltip: 'More',
                              onPressed: onMore,
                              icon: const Icon(Icons.more_vert),
                            )
                          : IconButton(
                              key: const ValueKey('settings'),
                              tooltip: 'Settings',
                              onPressed: () => _push(ResourceView(
                                  api: api,
                                  drive: shell.drive.value,
                                  path: '/app/settings')),
                              icon: const Icon(Icons.settings_outlined),
                            ),
                    ),
                  ]);
            },
          ),
        ),
      ),
    );
  }
}
