import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColorsExt, HoldFan, HoldFanItem, HoldFanLayout;
import 'package:flutter/material.dart';

import 'atomic_place_mark.dart';
import 'slide_back_route.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'models.dart';
import 'native_views.dart';
import 'new_document_sheet.dart';
import 'resource_view.dart';
import 'search_screen.dart';

/// What the New button's fan offers.
enum NewChoice { aiChat, aiVoice, document, other }

/// The web app's full "New" page, in [drive] when given.
String newResourcePath(String? drive) => drive == null || drive.isEmpty
    ? '/app/new'
    : Uri(path: '/app/new', queryParameters: {'parentSubject': drive})
        .toString();

/// Most drives the Search button's fan lists by name.
const _fanDrives = 4;

/// The one row at the bottom of the app, within the thumb's reach, the same on
/// every page and never moving with them: home (the atomic.place mark), search, a new chat, the user (agent,
/// sync and account) and, last, settings, or the "more" menu of the resource
/// the page on top shows. Back is the system back and the swipe from the left
/// edge.
///
/// The button of the page on top is shown as the current one (in the main
/// colour) and does nothing; a page of the bar is never opened twice (see
/// [ShellController.open]). Search and New have more choices on touch and
/// hold ([HoldFan]): Search in one drive; a voice chat, a document or anything
/// else the web app makes.
class AppBottomBar extends StatelessWidget {
  final AssistantApi api;
  final ShellController shell;

  const AppBottomBar({super.key, required this.api, required this.shell});

  void _newChat() => shell.openPage<void>(
      ShellPage.newChat, (_) => ChatScreen(api: api, subject: null, title: ''));

  void _voiceChat() => shell.openPage<void>(ShellPage.voiceChat,
      (_) => ChatScreen(api: api, subject: null, title: '', voiceMode: true));

  Future<void> _newDocument(BuildContext context) async {
    final created = await showNewDocumentSheet(context,
        api: api, fallbackDrive: shell.drive.value);
    if (created == null) return;
    api.noteOpened(created.drive, created.subject);
    await shell.navigatorKey.currentState?.push(SlideBackRoute<void>(
      builder: (_) => openResourceView(
          api: api,
          drive: created.drive,
          subject: created.subject,
          title: created.name),
    ));
  }

  Future<void> _newOther() async {
    final drive = await lastNewResourceDrive() ?? shell.drive.value;
    await shell.openPage<void>(
        ShellPage.newResource,
        (_) =>
            ResourceView(api: api, drive: drive, path: newResourcePath(drive)));
  }

  void _new(BuildContext context, NewChoice choice) {
    switch (choice) {
      case NewChoice.aiChat:
        _newChat();
      case NewChoice.aiVoice:
        _voiceChat();
      case NewChoice.document:
        _newDocument(context);
      case NewChoice.other:
        _newOther();
    }
  }

  /// Search opens fast: the keyboard comes up with it. [scope] searches one
  /// drive.
  Future<void> _openSearch({String? scope}) => shell.open<void>(
      scope == null ? ShellPage.search : ShellPage.searchIn(scope),
      (settings) => SearchScreen.route(
          drive: shell.drive.value,
          api: api,
          scopeDrive: scope,
          settings: settings));

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Material(
      color: c.bgBody,
      child: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
          child: ListenableBuilder(
            listenable: Listenable.merge([shell, shell.drive]),
            builder: (context, _) {
              final onMore = shell.topMenu;
              final top = shell.topKind;
              final onUser = shell.onUser ??
                  switch (shell.profile) {
                    final profile? => () =>
                        shell.openPage<void>(ShellPage.profile, profile),
                    null => null,
                  };
              final newCurrent =
                  top == ShellPage.newChat || top == ShellPage.voiceChat;
              return Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    _Current(
                      current: top == ShellPage.home,
                      label: 'Home',
                      child: IconButton(
                        tooltip: 'Home',
                        onPressed: top == ShellPage.home ? null : shell.goHome,
                        icon: const AtomicPlaceMark(size: 24),
                      ),
                    ),
                    _Current(
                      current: ShellPage.isSearch(top),
                      label: 'Search',
                      child: _SearchButton(
                        api: api,
                        current: ShellPage.isSearch(top),
                        onSearch: _openSearch,
                      ),
                    ),
                    _Current(
                      current: newCurrent,
                      label: 'New chat',
                      child: HoldFan<NewChoice>(
                        tooltip: 'New chat',
                        selected: newCurrent,
                        onTap: newCurrent ? null : _newChat,
                        items: const [
                          HoldFanItem('AI chat', NewChoice.aiChat),
                          HoldFanItem('AI voice', NewChoice.aiVoice),
                          HoldFanItem('Document', NewChoice.document),
                          HoldFanItem('Other', NewChoice.other),
                        ],
                        onSelected: (choice) => _new(context, choice),
                        child: _barIcon(context, Icons.add, newCurrent),
                      ),
                    ),
                    _Current(
                      current: top == ShellPage.profile,
                      label: 'Profile',
                      child: IconButton(
                        tooltip: 'Profile',
                        onPressed: top == ShellPage.profile ? null : onUser,
                        icon: const Icon(Icons.person_outline),
                      ),
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
                          : _Current(
                              key: const ValueKey('settings'),
                              current: top == ShellPage.settings,
                              label: 'Settings',
                              child: IconButton(
                                tooltip: 'Settings',
                                onPressed: top == ShellPage.settings
                                    ? null
                                    : () => shell.openPage<void>(
                                        ShellPage.settings,
                                        (_) => ResourceView(
                                            api: api,
                                            drive: shell.drive.value,
                                            path: '/app/settings')),
                                icon: const Icon(Icons.settings_outlined),
                              ),
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

/// A bar icon drawn by a [HoldFan] (an [IconButton] draws its own): in the
/// main colour when its page is the current one.
Widget _barIcon(BuildContext context, IconData icon, bool current) {
  // What an IconButton draws its icon in.
  final color = Theme.of(context).colorScheme.onSurfaceVariant;
  return Icon(icon, color: current ? context.appColors.main : color);
}

/// Marks the button of the page on top: its icon is drawn in the main colour
/// (the others stay neutral).
class _Current extends StatelessWidget {
  final bool current;
  final String label;
  final Widget child;

  const _Current({
    super.key,
    required this.current,
    required this.label,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    final main = context.appColors.main;
    // The same tree whether current or not: the button below keeps its state.
    return Semantics(
      selected: current,
      child: IconButtonTheme(
        data: current
            ? IconButtonThemeData(
                style: IconButton.styleFrom(
                  foregroundColor: main,
                  disabledForegroundColor: main,
                ),
              )
            : const IconButtonThemeData(),
        child: Stack(
          alignment: Alignment.center,
          children: [
            child,
            if (current) SizedBox.shrink(key: ValueKey('current:$label')),
          ],
        ),
      ),
    );
  }
}

/// Search: a tap searches every drive; holding offers the drives used last
/// (and the rest in a list) to search only one.
class _SearchButton extends StatefulWidget {
  final AssistantApi api;
  final bool current;
  final Future<void> Function({String? scope}) onSearch;

  const _SearchButton({
    required this.api,
    required this.current,
    required this.onSearch,
  });

  @override
  State<_SearchButton> createState() => _SearchButtonState();
}

/// The fan's value for "every drive" and for the list of the rest.
const _allDrives = '';
const _moreDrives = '\u0000more';

class _SearchButtonState extends State<_SearchButton> {
  List<DriveInfo> _drives = const [];

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final drives = await drivesByRecent(widget.api);
      if (mounted) setState(() => _drives = drives);
    } catch (_) {
      // The fan offers every drive only.
    }
  }

  Future<void> _pick(String value) async {
    if (value == _allDrives) return widget.onSearch();
    if (value != _moreDrives) return widget.onSearch(scope: value);
    final picked = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      builder: (context) => SafeArea(
        child: ConstrainedBox(
          constraints: BoxConstraints(
              maxHeight: MediaQuery.sizeOf(context).height * 0.7),
          child: ListView(
            shrinkWrap: true,
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
                child: Text('Search in',
                    style: Theme.of(context).textTheme.titleMedium),
              ),
              for (final d in _drives)
                ListTile(
                  title: Text(driveLabel(d)),
                  onTap: () => Navigator.of(context).pop(d.subject),
                ),
            ],
          ),
        ),
      ),
    );
    if (picked != null) await widget.onSearch(scope: picked);
  }

  @override
  Widget build(BuildContext context) {
    final drives = _drives;
    return HoldFan<String>(
      tooltip: 'Search',
      layout: HoldFanLayout.list,
      selected: widget.current,
      onTap: widget.current ? null : () => widget.onSearch(),
      onOpen: _load,
      items: [
        const HoldFanItem('All drives', _allDrives),
        for (final d in drives.take(_fanDrives))
          HoldFanItem(d.name.isEmpty ? 'Untitled drive' : d.name, d.subject,
              emoji: d.emoji),
        if (drives.length > _fanDrives) const HoldFanItem('More…', _moreDrives),
      ],
      onSelected: _pick,
      child: _barIcon(context, Icons.search, widget.current),
    );
  }
}
