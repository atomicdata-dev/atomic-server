import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColorsExt, HoldFan, HoldFanItem;
import 'package:flutter/material.dart';

import 'app_shell.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'home_sections.dart';
import 'models.dart';
import 'native_views.dart';
import 'profile_avatar.dart';
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
/// [ShellController.open]). New lists what to make as soon as the finger is
/// down: an AI chat (always a fresh one), a voice chat, a document or anything
/// else the web app makes. Lifted at once, the list waits for a tap; moved,
/// the finger drags to a choice and lets go on it ([HoldFan.opensOnDown]).
/// Search has the drives on touch and hold.
///
/// On a tablet ([ShellLayout.split]) the bar is the foot of the sidebar (the
/// list pane). Home and Search show what the sidebar holds (Home on the home
/// closes the detail page), the others open in the detail pane; Settings
/// stays and the resource's "more" menu comes last.
class AppBottomBar extends StatelessWidget {
  final AssistantApi api;
  final ShellController shell;

  /// The widest the row of buttons gets on a wide window.
  static const maxButtonsWidth = 560.0;

  /// The height of the row of buttons, above the system inset.
  static const rowHeight = 56.0;

  const AppBottomBar({super.key, required this.api, required this.shell});

  ShellActions get _actions => ShellActions(api, shell);

  void _new(BuildContext context, NewChoice choice) =>
      _actions.newOf(context, choice);
  Future<void> _openSearch({String? scope}) => _actions.search(scope: scope);

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    // Rebuilt when the window changes layout (the bar itself is kept).
    final split = ShellScope.layoutOf(context) == ShellLayout.split;
    return Material(
      color: c.barSurface,
      // The row of buttons, centred in its own height; the system inset
      // (gesture handle, buttons) under it in the bar's colour.
      child: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: SizedBox(
            height: rowHeight,
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: maxButtonsWidth),
                child: LayoutBuilder(builder: (context, box) {
                  // Room for the name next to the avatar: a wide sidebar or
                  // window, not a phone.
                  final roomy = box.maxWidth + 16 >= 400;
                  return ListenableBuilder(
                    listenable: Listenable.merge([
                      shell,
                      shell.drive,
                      shell.list,
                      shell.listCollapsed,
                      shell.searching,
                      shell.homeSections
                    ]),
                    builder: (context, _) {
                      final onMore = shell.topMenu;
                      final top = shell.topKind;
                      final onUser = _actions.onUser;
                      final list = shell.list.value;
                      final folded = split && shell.listCollapsed.value;
                      final newCurrent = top == ShellPage.newChat ||
                          top == ShellPage.voiceChat;
                      final searchCurrent = split
                          ? shell.searching.value ||
                              (ShellPage.isSearch(list) && !folded)
                          : ShellPage.isSearch(top);
                      final homeCurrent = split
                          ? list == ShellPage.home && !folded && !searchCurrent
                          : top == ShellPage.home;
                      // Next to the pages Home shows the home in the list pane (and
                      // brings it back when folded); on the home it closes what the
                      // detail pane shows.
                      final VoidCallback? onHome = split
                          ? (folded || list != ShellPage.home
                              ? () => shell.showList(ShellPage.home)
                              : (shell.atHome ? null : shell.goHome))
                          : (homeCurrent ? null : shell.goHome);
                      final more = onMore == null
                          ? null
                          : Builder(
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
                            );
                      final settings = _Current(
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
                      );
                      final buttons = <Widget>[
                        _Current(
                          current: homeCurrent,
                          label: 'Home',
                          child: HoldFan<HomeSection>(
                            tooltip: 'Home',
                            selected: homeCurrent,
                            menuLabel: 'Home sections',
                            cardMenu: true,
                            // A tap goes home; hold and drag to a section.
                            defaultIndex: null,
                            onTap: onHome,
                            items: [
                              for (final s in shell.homeSections.value)
                                HoldFanItem(s.title, s, icon: _sectionIcon(s)),
                            ],
                            onSelected: shell.openHomeSection,
                            child: _barIcon(
                                context,
                                homeCurrent ? Icons.home : Icons.home_outlined,
                                homeCurrent),
                          ),
                        ),
                        _Current(
                          current: searchCurrent,
                          label: 'Search',
                          child: _SearchButton(
                            api: api,
                            current: searchCurrent,
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
                            // The list at once; a drag from + picks.
                            opensOnDown: true,
                            items: newItems,
                            onSelected: (choice) => _new(context, choice),
                            child: _barIcon(context, Icons.add, newCurrent),
                          ),
                        ),
                        _Current(
                          current: top == ShellPage.profile,
                          label: 'Profile',
                          child: _ProfileButton(
                            shell: shell,
                            current: top == ShellPage.profile,
                            // Next to the pages every slot is the same.
                            wide: roomy && !split,
                            onPressed: onUser,
                          ),
                        ),
                        if (split) ...[
                          settings,
                          // Room for it whether or not a resource is open: the
                          // other buttons do not move.
                          AnimatedSwitcher(
                            duration: const Duration(milliseconds: 200),
                            child: more ?? const SizedBox(width: 48),
                          ),
                          // Under the thumb, where the button that opens
                          // it again is when it is folded.
                          IconButton(
                            tooltip: 'Close sidebar',
                            onPressed: () => shell.setListCollapsed(true),
                            icon: const Icon(Icons.menu_open),
                          ),
                        ] else
                          // The only button that changes with the page.
                          AnimatedSwitcher(
                            duration: const Duration(milliseconds: 200),
                            child: more ?? settings,
                          ),
                      ];
                      // Next to the pages: equal slots across the sidebar,
                      // which fit its narrowest width too.
                      if (split) {
                        return Row(children: [
                          for (final b in buttons)
                            Expanded(child: Center(child: b)),
                        ]);
                      }
                      return Row(
                          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                          children: buttons);
                    },
                  );
                }),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// What the bar's buttons (and the home's section buttons) do.
class ShellActions {
  final AssistantApi api;
  final ShellController shell;

  const ShellActions(this.api, this.shell);

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

  /// The web app's page for a new drive.
  Future<void> newDrive() => shell.openPage<void>(
      ShellPage.newResource,
      (_) => ResourceView(
          api: api,
          drive: shell.drive.value,
          title: 'New drive',
          path: '/app/new-drive'));

  /// The web app's form for a new chat room (a conversation) in the drive.
  Future<void> newConversation() {
    final drive = shell.drive.value;
    return shell.openPage<void>(
        ShellPage.newResource,
        (_) => ResourceView(
            api: api,
            drive: drive,
            title: 'New chat room',
            path: Uri(path: '/app/new', queryParameters: {
              'classSubject': chatRoomClass,
              if (drive.isNotEmpty) 'parentSubject': drive,
            }).toString()));
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
  /// drive, [of] one kind of resource (a home section's search). Next to the
  /// detail pane it is the list pane that searches (unfolded if need be).
  ///
  /// The button (no [scope]) always starts over: a search that is open, or
  /// further down the pages, is shown with an empty field and the keyboard
  /// up ([ShellController.resetSearch]); a new one never has an old query.
  Future<void> search({String? scope, SearchKind of = SearchKind.any}) async {
    final kind = ShellPage.searchFor(scope: scope, kind: of);
    if (shell.split) {
      // A card over the window; the sidebar and the page stay as they are.
      return showSearchPalette(shell: shell, api: api, scope: scope, kind: of);
    }
    if (scope == null && of == SearchKind.any) {
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
            kind: of,
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

/// The class of a chat room (a conversation), as the web app names it.
const chatRoomClass = 'https://atomicdata.dev/classes/ChatRoom';

/// How long a hold on a New outside the bar (the home's Recents) takes
/// before the list opens for the drag; the bar's opens as the finger goes
/// down.
const newHold = Duration(milliseconds: 150);

/// What New offers.
const newItems = [
  HoldFanItem('AI chat', NewChoice.aiChat, icon: Icons.chat_bubble_outline),
  HoldFanItem('AI voice', NewChoice.aiVoice, icon: Icons.mic_none),
  HoldFanItem('Document', NewChoice.document, icon: Icons.description_outlined),
  HoldFanItem('Other…', NewChoice.other, icon: Icons.add_box_outlined),
];

/// The icon of a Home section in the Home button's menu.
IconData _sectionIcon(HomeSection s) => switch (s) {
      HomeSection.notifications => Icons.notifications_none,
      HomeSection.drives => Icons.folder_outlined,
      HomeSection.recents => Icons.history,
      HomeSection.activity => Icons.bolt_outlined,
      HomeSection.chats => Icons.chat_bubble_outline,
      HomeSection.favorites => Icons.star_border,
      HomeSection.messages => Icons.forum_outlined,
    };

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

/// The widest the name next to the avatar gets.
const _profileNameWidth = 96.0;

/// The profile button: the person's avatar (ringed in the main colour when
/// their page is on top) and, on a wide bar, their name; a person icon until
/// the identity is loaded. The name is the tooltip and the semantics label.
class _ProfileButton extends StatelessWidget {
  final ShellController shell;
  final bool current;
  final bool wide;
  final VoidCallback? onPressed;

  const _ProfileButton({
    required this.shell,
    required this.current,
    required this.wide,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    final main = context.appColors.main;
    return ValueListenableBuilder<ProfileIdentity?>(
      valueListenable: shell.identity,
      builder: (context, who, _) {
        if (who == null) {
          return IconButton(
            tooltip: 'Profile',
            onPressed: current ? null : onPressed,
            icon: const Icon(Icons.person_outline),
          );
        }
        final name = who.name?.trim() ?? '';
        final label = name.isEmpty ? 'Profile' : name;
        final showName = wide && name.isNotEmpty;
        // As big as the bar's icons (24 dp); its page on top rings it.
        final avatar = Container(
          foregroundDecoration: BoxDecoration(
            shape: BoxShape.circle,
            border: Border.all(
                color: current ? main : Colors.transparent, width: 2),
          ),
          // Neutral unless the profile is the page shown: the main colour's
          // tint read as "this is where you are".
          child: ProfileAvatar.of(who,
              radius: 12,
              background: current
                  ? null
                  : Theme.of(context).colorScheme.surfaceContainerHighest,
              foreground: current
                  ? null
                  : Theme.of(context).colorScheme.onSurfaceVariant),
        );
        return Tooltip(
          message: label,
          child: Semantics(
            button: true,
            label: label,
            excludeSemantics: true,
            onTap: current ? null : onPressed,
            child: InkResponse(
              onTap: current ? null : onPressed,
              radius: 28,
              child: ConstrainedBox(
                constraints: const BoxConstraints(minWidth: 48, minHeight: 48),
                // Its own height, whatever room the bar is given: without
                // the factors it took all of it, and next to the pages the
                // bar (with a signed-in person) then filled the sidebar.
                child: Center(
                  widthFactor: 1,
                  heightFactor: 1,
                  child: showName
                      ? Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 4),
                          child: Row(mainAxisSize: MainAxisSize.min, children: [
                            avatar,
                            const SizedBox(width: 6),
                            ConstrainedBox(
                              constraints: const BoxConstraints(
                                  maxWidth: _profileNameWidth),
                              child: Text(
                                name,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(
                                    color: current
                                        ? main
                                        : Theme.of(context)
                                            .colorScheme
                                            .onSurfaceVariant),
                              ),
                            ),
                          ]),
                        )
                      : avatar,
                ),
              ),
            ),
          ),
        );
      },
    );
  }
}

/// Search: a tap searches every drive; holding lists the drives used last
/// (and the rest in a sheet) to search only one.
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
