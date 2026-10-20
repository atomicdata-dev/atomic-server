import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColorsExt, HoldFan, HoldFanItem, HoldFanLayout;
import 'package:flutter/material.dart';

import 'app_shell.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'models.dart';
import 'native_views.dart';
import 'new_document_sheet.dart';
import 'resource_view.dart';
import 'search_screen.dart';

/// What the New button's list offers.
enum NewChoice { aiChat, aiVoice, document, other }

/// The web app's full "New" page, in [drive] when given.
String newResourcePath(String? drive) => drive == null || drive.isEmpty
    ? '/app/new'
    : Uri(path: '/app/new', queryParameters: {'parentSubject': drive})
        .toString();

/// Most drives the Search button's list names.
const _listDrives = 4;

/// The one row at the bottom of the app, within the thumb's reach, the same on
/// every page and never moving with them: home (the atomic.place mark), search, new (a list), the user (agent,
/// sync and account) and, last, settings, or the "more" menu of the resource
/// the page on top shows. Back is the system back and the swipe from the left
/// edge.
///
/// The button of the page on top is shown as the current one (in the main
/// colour) and does nothing; a page of the bar is never opened twice (see
/// [ShellController.open]). A tap on New lists what to make: an AI chat (always
/// a fresh one), a voice chat, a document or anything else the web app makes;
/// holding it opens the same list and the finger drags to a choice
/// ([HoldFan]). Search has the drives on touch and hold.
class AppBottomBar extends StatelessWidget {
  final AssistantApi api;
  final ShellController shell;

  const AppBottomBar({super.key, required this.api, required this.shell});

  _ShellActions get _actions => _ShellActions(api, shell);

  void _new(BuildContext context, NewChoice choice) =>
      _actions.newOf(context, choice);
  Future<void> _openSearch({String? scope}) => _actions.search(scope: scope);

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Material(
      color: c.barSurface,
      child: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
          child: ListenableBuilder(
            listenable: Listenable.merge([shell, shell.drive]),
            builder: (context, _) {
              final onMore = shell.topMenu;
              final top = shell.topKind;
              final onUser = _actions.onUser;
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
                        icon: _barIcon(
                            context,
                            top == ShellPage.home
                                ? Icons.home
                                : Icons.home_outlined,
                            top == ShellPage.home),
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
                      label: 'New',
                      child: HoldFan<NewChoice>(
                        tooltip: 'New',
                        selected: newCurrent,
                        tapOpensMenu: true,
                        holdDuration: _newHold,
                        items: _newItems,
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
                          ? Builder(
                              key: const ValueKey('more'),
                              builder: (button) => IconButton(
                                tooltip: 'More',
                                onPressed: () {
                                  final box =
                                      button.findRenderObject() as RenderBox;
                                  onMore(box.localToGlobal(Offset.zero) &
                                      box.size);
                                },
                                icon: const Icon(Icons.more_vert),
                              ),
                            )
                          : _Current(
                              key: const ValueKey('settings'),
                              current: top == ShellPage.settings,
                              label: 'Settings',
                              child: IconButton(
                                tooltip: 'Settings',
                                onPressed: top == ShellPage.settings
                                    ? null
                                    : _actions.settings,
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

/// What the bar's and the rail's buttons do.
class _ShellActions {
  final AssistantApi api;
  final ShellController shell;

  const _ShellActions(this.api, this.shell);

  void newChat() => shell.openPage<void>(
      ShellPage.newChat, (_) => ChatScreen(api: api, subject: null, title: ''));

  void voiceChat() => shell.openPage<void>(ShellPage.voiceChat,
      (_) => ChatScreen(api: api, subject: null, title: '', voiceMode: true));

  Future<void> newDocument(BuildContext context) async {
    final created = await showNewDocumentSheet(context,
        api: api, fallbackDrive: shell.drive.value);
    if (created == null) return;
    api.noteOpened(created.drive, created.subject);
    await shell.openDetail<void>(
      (_) => openResourceView(
          api: api,
          drive: created.drive,
          subject: created.subject,
          title: created.name),
      subject: created.subject,
    );
  }

  Future<void> newOther() async {
    final drive = await lastNewResourceDrive() ?? shell.drive.value;
    await shell.openPage<void>(
        ShellPage.newResource,
        (_) =>
            ResourceView(api: api, drive: drive, path: newResourcePath(drive)));
  }

  void newOf(BuildContext context, NewChoice choice) {
    switch (choice) {
      case NewChoice.aiChat:
        newChat();
      case NewChoice.aiVoice:
        voiceChat();
      case NewChoice.document:
        newDocument(context);
      case NewChoice.other:
        newOther();
    }
  }

  /// Search opens fast: the keyboard comes up with it. [scope] searches one
  /// drive. Next to the detail pane it is the list pane that searches.
  ///
  /// The button (no [scope]) always starts over: a search that is open, or
  /// further down the pages, is shown with an empty field and the keyboard
  /// up ([ShellController.resetSearch]); a new one never has an old query.
  Future<void> search({String? scope}) async {
    final kind = scope == null ? ShellPage.search : ShellPage.searchIn(scope);
    if (shell.split) {
      final open = shell.list.value;
      if (ShellPage.isSearch(open) && (scope == null || open == kind)) {
        return shell.resetSearch();
      }
      return shell.showList(kind);
    }
    if (scope == null) {
      final open = shell.pages
          .where((r) => ShellPage.isSearch(shell.kindOf(r)))
          .lastOrNull;
      if (open != null) {
        shell.navigatorKey.currentState?.popUntil((r) => r == open);
        return shell.resetSearch();
      }
    }
    await shell.open<void>(
        kind,
        (settings) => SearchScreen.route(
            drive: shell.drive.value,
            api: api,
            scopeDrive: scope,
            settings: settings));
  }

  void settings() => shell.openPage<void>(
      ShellPage.settings,
      (_) => ResourceView(
          api: api,
          drive: shell.drive.value,
          title: 'Settings',
          path: '/app/settings'));

  VoidCallback? get onUser =>
      shell.onUser ??
      switch (shell.profile) {
        final profile? => () =>
            shell.openPage<void>(ShellPage.profile, profile),
        null => null,
      };
}

/// The bar's buttons in a column at the left edge, for a wide window
/// ([ShellLayout.rail] and [ShellLayout.split]): the same pages and actions,
/// each with its name under it. Next to the list pane, Home and Search show
/// what the list pane holds, the others what the detail pane shows. The
/// resource's "more" menu is not here but at the detail pane's top right.
class AppNavRail extends StatelessWidget {
  final AssistantApi api;
  final ShellController shell;

  static const width = 80.0;

  const AppNavRail({super.key, required this.api, required this.shell});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final actions = _ShellActions(api, shell);
    return Material(
      color: c.barSurface,
      child: SafeArea(
        right: false,
        bottom: false,
        child: SizedBox(
          width: width,
          child: ListenableBuilder(
            listenable: Listenable.merge([shell, shell.drive, shell.list]),
            builder: (context, _) {
              final top = shell.topKind;
              final split = shell.split;
              final list = shell.list.value;
              final homeCurrent =
                  split ? list == ShellPage.home : top == ShellPage.home;
              final searchCurrent =
                  split ? ShellPage.isSearch(list) : ShellPage.isSearch(top);
              final newCurrent =
                  top == ShellPage.newChat || top == ShellPage.voiceChat;
              final onUser = actions.onUser;
              // Home on the list pane that shows it already closes what
              // the detail pane shows.
              final VoidCallback? onHome = split
                  ? (list != ShellPage.home
                      ? () => shell.showList(ShellPage.home)
                      : (shell.atHome ? null : shell.goHome))
                  : (homeCurrent ? null : shell.goHome);
              return SingleChildScrollView(
                padding: const EdgeInsets.symmetric(vertical: 8),
                child: Column(children: [
                  _RailItem(
                    label: 'Home',
                    current: homeCurrent,
                    child: IconButton(
                      tooltip: 'Home',
                      onPressed: onHome,
                      icon: _barIcon(
                          context,
                          homeCurrent ? Icons.home : Icons.home_outlined,
                          homeCurrent),
                    ),
                  ),
                  _RailItem(
                    label: 'Search',
                    current: searchCurrent,
                    child: _SearchButton(
                      api: api,
                      current: searchCurrent,
                      layout: HoldFanLayout.side,
                      onSearch: actions.search,
                    ),
                  ),
                  _RailItem(
                    label: 'New',
                    current: newCurrent,
                    child: HoldFan<NewChoice>(
                      tooltip: 'New',
                      selected: newCurrent,
                      layout: HoldFanLayout.side,
                      tapOpensMenu: true,
                      holdDuration: _newHold,
                      items: _newItems,
                      onSelected: (choice) => actions.newOf(context, choice),
                      child: _barIcon(context, Icons.add, newCurrent),
                    ),
                  ),
                  _RailItem(
                    label: 'Profile',
                    current: top == ShellPage.profile,
                    child: IconButton(
                      tooltip: 'Profile',
                      onPressed: top == ShellPage.profile ? null : onUser,
                      icon: const Icon(Icons.person_outline),
                    ),
                  ),
                  _RailItem(
                    label: 'Settings',
                    current: top == ShellPage.settings,
                    child: IconButton(
                      tooltip: 'Settings',
                      onPressed:
                          top == ShellPage.settings ? null : actions.settings,
                      icon: const Icon(Icons.settings_outlined),
                    ),
                  ),
                ]),
              );
            },
          ),
        ),
      ),
    );
  }
}

/// How long a hold on New takes before the list opens for the drag.
const _newHold = Duration(milliseconds: 250);

const _newItems = [
  HoldFanItem('AI chat', NewChoice.aiChat, icon: Icons.chat_bubble_outline),
  HoldFanItem('AI voice', NewChoice.aiVoice, icon: Icons.mic_none),
  HoldFanItem('Document', NewChoice.document, icon: Icons.description_outlined),
  HoldFanItem('Other…', NewChoice.other, icon: Icons.add_box_outlined),
];

/// A rail button with its name under it, both in the main colour when its
/// page is the current one.
class _RailItem extends StatelessWidget {
  final String label;

  final bool current;
  final Widget child;

  const _RailItem({
    required this.label,
    required this.current,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        _Current(current: current, label: label, child: child),
        ExcludeSemantics(
          child: Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.fade,
            softWrap: false,
            style: TextStyle(
              fontSize: 12,
              fontWeight: current ? FontWeight.w600 : FontWeight.w500,
              color: current ? c.main : c.textSecondary,
            ),
          ),
        ),
      ]),
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

/// Search: a tap searches every drive; holding lists the drives used last
/// (and the rest in a sheet) to search only one.
class _SearchButton extends StatefulWidget {
  final AssistantApi api;
  final bool current;
  final Future<void> Function({String? scope}) onSearch;
  final HoldFanLayout layout;

  const _SearchButton({
    required this.api,
    required this.current,
    required this.onSearch,
    this.layout = HoldFanLayout.list,
  });

  @override
  State<_SearchButton> createState() => _SearchButtonState();
}

/// The list's value for "every drive" and for the list of the rest.
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
      // The list offers every drive only.
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
      layout: widget.layout,
      selected: widget.current,
      // Also on the open search: it starts over.
      onTap: () => widget.onSearch(),
      onOpen: _load,
      items: [
        const HoldFanItem('All drives', _allDrives),
        for (final d in drives.take(_listDrives))
          HoldFanItem(d.name.isEmpty ? 'Untitled drive' : d.name, d.subject,
              emoji: d.emoji),
        if (drives.length > _listDrives)
          const HoldFanItem('More…', _moreDrives),
      ],
      onSelected: _pick,
      child: _barIcon(context, Icons.search, widget.current),
    );
  }
}
