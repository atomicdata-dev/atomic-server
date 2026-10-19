import 'package:flutter/material.dart';

import '../theme.dart';
import '../widgets/slide_back_route.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'search_screen.dart';

/// The bar at the bottom of every main view, within the thumb's reach, with
/// the same actions everywhere: back (when there is somewhere to go back to),
/// the resource's "more" menu (when the view has a resource), search, and a
/// new chat.
class AppBottomBar extends StatelessWidget {
  final AssistantApi api;

  /// The drive search looks in.
  final String drive;
  final String hint;

  /// Opens the resource menu. Without a resource there is no menu to open.
  final VoidCallback? onMore;

  /// Goes back; by default pops the screen.
  final VoidCallback? onBack;

  /// Pushes a screen; the home screen uses it to refresh when it comes back.
  final Future<void> Function(Widget screen)? onPush;

  const AppBottomBar({
    super.key,
    required this.api,
    required this.drive,
    this.hint = 'Search',
    this.onMore,
    this.onBack,
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
          padding: const EdgeInsets.fromLTRB(8, 8, 16, 12),
          child: Row(children: [
            if (Navigator.of(context).canPop())
              IconButton(
                tooltip: 'Back',
                onPressed: onBack ?? () => Navigator.of(context).maybePop(),
                icon: const Icon(Icons.arrow_back),
              )
            else
              const SizedBox(width: 8),
            if (onMore != null)
              IconButton(
                tooltip: 'More',
                onPressed: onMore,
                icon: const Icon(Icons.more_vert),
              ),
            Expanded(
              child: TextField(
                readOnly: true,
                decoration: InputDecoration(
                  hintText: hint,
                  prefixIcon: const Icon(Icons.search),
                  filled: true,
                  fillColor: c.bg1,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(9),
                    borderSide: BorderSide.none,
                  ),
                ),
                onTap: () =>
                    _push(context, SearchScreen(drive: drive, api: api)),
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              tooltip: 'New chat',
              iconSize: 26,
              onPressed: () => _push(
                  context, ChatScreen(api: api, subject: null, title: '')),
              icon: const Icon(Icons.add),
            ),
          ]),
        ),
      ),
    );
  }
}
