import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt, HoldFan, HoldFanItem, HoldFanLayout, Perf;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'app_bottom_bar.dart';
import 'app_top_bar.dart';
import 'home_sections.dart';
import 'search_screen.dart';

import 'models.dart';
import 'slide_back_route.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'resource_row.dart';
import 'resource_view.dart';
import 'native_views.dart';
import 'new_document_sheet.dart';

/// Items per section on the home; the rest is behind the All button.
const _homeItems = 4;

/// Most items the merged recents list holds.
const _maxRecents = 100;

/// Most entries the activity feed holds.
const _maxActivity = 100;

enum _SectionOp { up, down, hide, show }

/// A choice of a heading's hold menu.
class _SectionAction {
  final _SectionOp op;
  final HomeSection section;
  const _SectionAction(this.op, this.section);
}

/// How a section folds, what its heading's hold menu offers, and the
/// buttons at its right (search, new; All comes from the section itself).
typedef _Fold = ({
  bool collapsed,
  VoidCallback onToggle,
  List<HoldFanItem<_SectionAction>> menu,
  ValueChanged<_SectionAction> onMenu,
  HomeSection section,
  VoidCallback? onSearch,
  Widget? plus,
});

typedef _Recent = ({String drive, RecentResource resource});

/// How an activity row says what happened (`kind` as the host names it).
String activityVerb(String kind) => switch (kind) {
      'changed' => 'edited',
      _ => kind,
    };

/// Home screen: one scrollable page of small sections (Drives, Recents, Activity,
/// AI Chats), each with its newest few items. A section's heading folds it on
/// a tap and arranges the sections on a hold; at its right are small buttons
/// to search that kind of thing, make a new one, and list all of them (in the
/// detail pane on a tablet, a page of its own on a phone). A section is one
/// [_Section]; adding another is one more entry in the list. Every section
/// shows as soon as its own data arrives.
class ChatsScreen extends StatefulWidget {
  final AssistantApi api;

  /// The drive the home opens on; the search looks in it.
  final String drive;

  final VoidCallback? onSignOut;

  /// The user's page; the shell's [ShellController.profile] when null. It
  /// pops with `true` when the person signed out there.
  final WidgetBuilder? profile;

  const ChatsScreen({
    super.key,
    required this.drive,
    required this.api,
    this.onSignOut,
    this.profile,
  });

  @override
  State<ChatsScreen> createState() => _ChatsScreenState();
}

class _ChatsScreenState extends State<ChatsScreen> {
  late Future<List<DriveInfo>> _drives = _timed('drives', _loadDrives());
  late Future<List<ChatSummary>> _chats = _timed('chats', widget.api.chats());
  late Future<List<_Recent>> _recents = _timed('recents', _loadRecents());
  late Future<List<RecentResource>> _favorites =
      _timed('favorites', widget.api.favorites());
  late Future<List<ConversationRow>> _conversations =
      _timed('conversations', widget.api.conversations());
  late Future<List<ActivityEntry>> _activity =
      _timed('activity', _loadActivity());
  late Future<List<NotificationItem>> _notifications =
      _timed('notifications', _loadNotifications());

  Future<List<NotificationItem>> _loadNotifications() async =>
      widget.api.notifications();

  /// How long a home list took, in debug and profile builds (`[perf] home
  /// LIST` in logcat).
  Future<T> _timed<T>(String what, Future<T> future) {
    if (kReleaseMode) return future;
    final watch = Stopwatch()..start();
    return future
        .whenComplete(() => Perf.span('home $what', watch.elapsedMilliseconds));
  }

  /// The emojis of the activity's resources, filled in after the list shows.
  Map<String, String> _icons = const {};

  /// The most recent drive: the one the home opened on, else the first.
  String _drive = '';

  /// Drive subject → name, for the drive shown in front of a recent.
  Map<String, String> _driveNames = const {};

  /// Which sections show, in which order, and which are folded (per device).
  HomeLayout _layout = const HomeLayout();

  @override
  void initState() {
    super.initState();
    if (!kReleaseMode) _markLoaded();
    // Once the home is drawn: read the search index so the first keystroke is
    // not the first read.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      widget.api.warmSearch().catchError((Object _) {});
    });
    HomeLayout.load().then((layout) {
      if (mounted) setState(() => _layout = layout);
    });
    _loadMine();
  }

  /// SharedPreferences key: the activity feed's "Show mine" (per device).
  static const showMineKey = 'activity_show_mine';

  /// The activity feed shows the person's own changes too.
  bool _mine = false;

  Future<void> _loadMine() async {
    try {
      final p = await SharedPreferences.getInstance();
      if (mounted && (p.getBool(showMineKey) ?? false)) _setMine(true);
    } catch (_) {}
  }

  void _setMine(bool mine) {
    if (mine == _mine) return;
    setState(() {
      _mine = mine;
      _activity = _loadActivity();
    });
    _publishActivity();
    SharedPreferences.getInstance()
        .then((p) => p.setBool(showMineKey, mine))
        .catchError((Object _) => false);
  }

  /// `[perf] home data` once every list of the first load is in, and `home
  /// painted` after the frame that shows them.
  void _markLoaded() {
    Perf.once('home start');
    Future.wait<Object?>([
      for (final f in <Future<Object?>>[
        _drives,
        _chats,
        _recents,
        _favorites,
        _conversations,
        _activity,
        _notifications,
      ])
        f.then((_) => null, onError: (Object _) => null),
    ]).then((_) {
      Perf.once('home data');
      WidgetsBinding.instance
          .addPostFrameCallback((_) => Perf.once('home painted'));
    });
  }

  void _setLayout(HomeLayout layout) {
    setState(() => _layout = layout);
    layout.save();
  }

  /// The hold menu of a section's heading: move it, hide it, and bring back
  /// the hidden ones.
  List<HoldFanItem<_SectionAction>> _menuFor(HomeSection s) => [
        if (_layout.canMove(s, -1))
          HoldFanItem('Move up', _SectionAction(_SectionOp.up, s), emoji: '⬆️'),
        if (_layout.canMove(s, 1))
          HoldFanItem('Move down', _SectionAction(_SectionOp.down, s),
              emoji: '⬇️'),
        HoldFanItem('Hide ${s.title}', _SectionAction(_SectionOp.hide, s),
            emoji: '🙈'),
        for (final h in _layout.order)
          if (_layout.hidden.contains(h))
            HoldFanItem('Show ${h.title}', _SectionAction(_SectionOp.show, h),
                emoji: '👁️'),
      ];

  void _applyAction(_SectionAction a) => _setLayout(switch (a.op) {
        _SectionOp.up => _layout.move(a.section, -1),
        _SectionOp.down => _layout.move(a.section, 1),
        _SectionOp.hide => _layout.setHidden(a.section, true),
        _SectionOp.show => _layout.setHidden(a.section, false),
      });
  ShellController? _shell;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final shell = ShellScope.maybeOf(context);
    if (!identical(shell, _shell)) {
      _shell?.removeListener(_onShellChanged);
      shell?.addListener(_onShellChanged);
    }
    _shell = shell;
    _publishActivity();
    // The profile button of the shell signs out through the home.
    if (_profile != null) _shell?.onUser = _settings;
  }

  /// A page of the bar (search, a new document, a resource opened from
  /// search) covered the home.
  bool _covered = false;

  /// The page the detail pane showed last (split layout).
  Route<dynamic>? _lastTop;

  /// Back on the home after the bar's pages: they can have opened, made or
  /// changed resources, so the lists are read again (the home's own pages
  /// reload in [_push]). Next to the detail pane the home is always in view:
  /// it is read again whenever another page is shown there.
  void _onShellChanged() {
    final shell = _shell;
    if (shell == null) return;
    if (shell.split) {
      if (!identical(shell.top, _lastTop)) {
        _lastTop = shell.top;
        _reload();
      }
      return;
    }
    _lastTop = shell.top;
    if (!shell.atHome) {
      _covered = true;
    } else if (_covered) {
      _covered = false;
      _reload();
    }
  }

  @override
  void dispose() {
    _shell?.removeListener(_onShellChanged);
    _shell?.activity.value = null;
    if (_shell?.onUser == _settings) _shell?.onUser = null;
    super.dispose();
  }

  /// The agent's drives; when there are none (not synced yet) just the one
  /// the app opened on.
  Future<List<DriveInfo>> _loadDrives() async {
    var drives = await widget.api.drives();
    if (drives.isEmpty) {
      drives = [(subject: widget.drive, name: '', emoji: null)];
    }
    _drive = drives.any((d) => d.subject == widget.drive)
        ? widget.drive
        : drives.first.subject;
    _driveNames = {for (final d in drives) d.subject: d.name};
    if (mounted) _shell?.drive.value = _drive;
    // The most recently visited first.
    return sortDrivesByRecent(widget.api, drives);
  }

  /// What was opened lately in every drive, newest first.
  Future<List<_Recent>> _loadRecents() async {
    final drives = await _drives;
    final lists = await Future.wait([
      for (final d in drives)
        widget.api.recentResources(d.subject).then(
              (list) => [for (final r in list) (drive: d.subject, resource: r)],
              onError: (Object _) => <_Recent>[],
            ),
    ]);
    return [for (final l in lists) ...l]
      ..sort((a, b) => b.resource.openedAt.compareTo(a.resource.openedAt));
  }

  /// The activity feed: what other members changed in the person's drives
  /// (the host leaves out the person's own changes; those are Recents). Its
  /// rows do not carry the resources' own icons, so those are looked up after
  /// the list is out (never blocking it).
  Future<List<ActivityEntry>> _loadActivity() async {
    final all = _mine
        ? await widget.api.activityWithMine(_maxActivity)
        : await widget.api.activity(_maxActivity);
    final drives = await _drives.then(
        (ds) => {for (final d in ds) driveKey(d.subject)},
        onError: (Object _) => <String>{});
    final list = drives.isEmpty
        ? all
        : [
            for (final a in all)
              if (drives.contains(driveKey(a.drive))) a
          ];
    widget.api.resourceIcons([for (final a in list) a.subject]).then((icons) {
      if (mounted && !_sameIcons(icons)) {
        setState(() => _icons = icons);
        _publishActivity();
      }
    }).catchError((Object _) {});
    return list;
  }

  /// Hands the activity feed to the shell, for the detail pane while nothing
  /// is open next to the home (the split layout shows it there, big, instead
  /// of as a section). The rows are the home's own.
  void _publishActivity() {
    final shell = _shell;
    if (shell == null) return;
    final future = _activity;
    future
        .then((list) => list, onError: (Object _) => <ActivityEntry>[])
        .then((list) {
      if (!mounted || !identical(future, _activity)) return;
      shell.activity.value =
          (entries: list, row: _activityRow, mine: _mine, onMine: _setMine);
    });
  }

  bool _sameIcons(Map<String, String> icons) =>
      icons.length == _icons.length &&
      icons.entries.every((e) => _icons[e.key] == e.value);

  bool _reloadQueued = false;

  /// Fetch every section again. Calls in the same frame are one reload; the
  /// sections keep showing what they have until the new data arrives.
  void _reload() {
    if (_reloadQueued) return;
    _reloadQueued = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _reloadQueued = false;
      if (!mounted) return;
      setState(() {
        // First: the recents read the drives.
        _drives = _loadDrives();
        _chats = widget.api.chats();
        _recents = _loadRecents();
        _favorites = widget.api.favorites();
        _conversations = widget.api.conversations();
        _activity = _loadActivity();
        _notifications = _loadNotifications();
      });
      _publishActivity();
    });
    // A frame must run for the callback to fire.
    WidgetsBinding.instance.scheduleFrame();
  }

  /// Whether `screen` can have changed what the home lists: a section's list
  /// and a settings page only show things (what is opened from a list
  /// reloads by itself when it is closed).
  static bool _changesData(Widget screen) =>
      !(screen is _ListPage || (screen is ResourceView && screen.path != null));

  /// Opens [screen]: pushed over the home on a phone, in the detail pane
  /// next to it on a tablet. [subject] is what it shows, to mark its row.
  Future<void> _push(Widget screen,
      {String? subject, VoidCallback? onLeave}) async {
    await openFromList<void>(context, (_) => screen,
        subject: subject, onLeave: onLeave);
    if (mounted && _changesData(screen)) _reload();
  }

  /// Opens [subject] of [drive] and notes the visit once it is left: the
  /// lists (Recents, the drives' order) do not move under the finger that
  /// opened it, only when the person goes on.
  Future<void> _visit(Widget screen,
      {required String drive, required String subject}) async {
    await openFromList<void>(context, (_) => screen, subject: subject,
        onLeave: () {
      widget.api.noteOpened(drive, subject);
      noteDriveVisited(drive);
    });
    if (mounted && _changesData(screen)) _reload();
  }

  WidgetBuilder? get _profile => widget.profile ?? _shell?.profile;

  ShellActions? get _actions =>
      _shell == null ? null : ShellActions(widget.api, _shell!);

  /// A section's search: for its kind of resource where search knows it.
  void _search(SearchKind kind) {
    final actions = _actions;
    if (actions != null) {
      actions.search(of: kind);
      return;
    }
    Navigator.of(context)
        .push(SearchScreen.route(drive: _drive, api: widget.api, kind: kind));
  }

  /// A section's full list: in the detail pane next to the home (where the
  /// resources open), a page of its own on a phone. Opened once. The rows are
  /// built when they scroll into view, from [item].
  void _openAll(HomeSection id, int count, Widget Function(int) item) =>
      _openPage(
          id, (_) => _ListPage(title: id.title, count: count, item: item));

  /// The AI chats' full list: pages of chats from the host, the next one
  /// read when the list is scrolled near its end, so every chat is reachable.
  /// [first] is what the home already has.
  void _openAllChats(HomeSection id, List<ChatSummary> first, AppColors c) =>
      _openPage(
          id,
          (_) => _ChatsPage(
                title: id.title,
                api: widget.api,
                first: first,
                colors: c,
                row: _chatRow,
              ));

  void _openPage(HomeSection id, WidgetBuilder page) {
    final shell = _shell;
    if (shell != null && shell.navigatorKey.currentState != null) {
      shell.openPage<void>(ShellPage.listOf(id.name), page);
      return;
    }
    Navigator.of(context).push(SlideBackRoute<void>(builder: page));
  }

  /// A section's "new": what it lists, made fresh; for the activity its
  /// "Show mine". Null where that makes no sense (notifications, favorites)
  /// or there is no shell.
  Widget? _plusFor(HomeSection id) {
    final actions = _actions;
    if (actions == null) return null;
    Widget button(String tooltip, VoidCallback onPressed) => _HeadingButton(
        key: ValueKey('section-new-${id.name}'),
        tooltip: tooltip,
        icon: Icons.add,
        onPressed: onPressed);
    return switch (id) {
      // Not a "new": the feed's own switch.
      HomeSection.activity => Padding(
          padding: const EdgeInsets.only(left: 4, right: 8),
          child: ShowMineChip(value: _mine, onChanged: _setMine)),
      HomeSection.drives => button('New drive', actions.newDrive),
      HomeSection.chats => button('New AI chat', actions.newChat),
      HomeSection.messages => button('New chat room', actions.newConversation),
      // Anything: the same list as the bar's New.
      HomeSection.recents => HoldFan<NewChoice>(
          key: ValueKey('section-new-${id.name}'),
          tooltip: 'Make something new',
          tapOpensMenu: true,
          holdDuration: newHold,
          items: newItems,
          onSelected: (choice) => actions.newOf(context, choice),
          child:
              Icon(Icons.add, size: 24, color: context.appColors.textSecondary),
        ),
      HomeSection.notifications || HomeSection.favorites => null,
    };
  }

  /// What a section's Search looks for; null: no search button.
  static SearchKind? _searchKind(HomeSection id) => switch (id) {
        HomeSection.drives => SearchKind.drives,
        HomeSection.chats => SearchKind.chats,
        HomeSection.messages => SearchKind.messages,
        HomeSection.recents ||
        HomeSection.activity ||
        HomeSection.favorites =>
          SearchKind.any,
        HomeSection.notifications => null,
      };

  Future<void> _settings() async {
    final profile = _profile;
    if (profile == null) return;
    // In the shell's navigator, so the bottom bar stays under it.
    // Through the shell when there is one: it is the bar's Profile page,
    // opened once.
    final shell = _shell;
    final signedOut = await (shell != null
            ? shell.openPage<bool>(ShellPage.profile, profile)
            : Navigator.of(context).push<bool>(
                SlideBackRoute<bool>(builder: profile),
              )) ??
        false;
    if (signedOut) {
      widget.onSignOut?.call();
    } else {
      setState(() {
        _drives = _loadDrives();
      });
      _reload();
    }
  }

  void _openChat(ChatSummary? chat) => _push(
      ChatScreen(
        api: widget.api,
        subject: chat?.subject,
        title: chat?.name ?? '',
      ),
      subject: chat?.subject);

  void _openResource(String drive, RecentResource r) {
    _visit(
        openResourceView(
            api: widget.api,
            drive: drive,
            subject: r.subject,
            title: r.title,
            className: r.className),
        drive: drive,
        subject: r.subject);
  }

  Widget _driveRow(DriveInfo d) => ResourceRow(
        subject: d.subject,
        icon: Icons.folder_outlined,
        emoji: d.emoji,
        title: d.name.isEmpty ? 'Untitled drive' : d.name,
        // The drive itself, drawn by the page: everything in it, read from
        // the store with the same query the web app uses.
        onTap: () => _push(
            openResourceView(
                api: widget.api,
                drive: d.subject,
                subject: d.subject,
                title: d.name),
            subject: d.subject,
            // The drives' order follows the visit once it is left.
            onLeave: () => noteDriveVisited(d.subject)),
      );

  Widget _chatRow(ChatSummary chat) => ResourceRow(
        subject: chat.subject,
        title: chat.name.isEmpty ? 'Untitled chat' : chat.name,
        onTap: () => _openChat(chat),
      );

  /// `<drive> · <class> · <when>`: the drive first, when it has a name.
  Widget _recentRow(_Recent r) =>
      _resourceRow(r.resource, _openResource, r.drive,
          driveName: _driveNames[r.drive]);

  /// Favorites and conversations are not tied to one drive: they open in the
  /// current one.
  Widget _homeRow(RecentResource r) => _resourceRow(r, _openResource, _drive);

  /// A notification: its title and excerpt, when it happened and an unread
  /// dot. A tap opens what it is about and marks it read.
  Widget _notificationRow(NotificationItem n) {
    final c = context.appColors;
    final body = n.body.replaceAll(RegExp(r'\s+'), ' ').trim();
    return ResourceRow(
      key: ValueKey('notification-${n.subject}'),
      subject: n.about.isEmpty ? null : n.about,
      icon: Icons.notifications_none,
      title: n.title.isEmpty ? n.about : n.title,
      detail: body.length > 80 ? '${body.substring(0, 79)}…' : body,
      trailing: Row(mainAxisSize: MainAxisSize.min, children: [
        if (n.occurredAt > 0)
          Text(timeAgo(n.occurredAt),
              style: TextStyle(color: c.textSecondary, fontSize: 12)),
        if (!n.read) ...[
          const SizedBox(width: 8),
          Container(
            key: const Key('notification-unread'),
            width: 10,
            height: 10,
            decoration: BoxDecoration(color: c.main, shape: BoxShape.circle),
          ),
        ],
      ]),
      onTap: () => _openNotification(n),
    );
  }

  void _openNotification(NotificationItem n) {
    if (!n.read) {
      widget.api.markNotificationRead(n.subject).then((_) {
        if (!mounted) return;
        setState(() {
          _notifications = _loadNotifications();
        });
      }, onError: (Object _) {});
    }
    if (n.about.isEmpty) return;
    _visit(
        openResourceView(
            api: widget.api, drive: _drive, subject: n.about, title: ''),
        drive: _drive,
        subject: n.about);
  }

  /// A conversation: who is in it, the newest message and when it was sent.
  Widget _conversationRow(ConversationRow c) {
    final r = c.resource;
    final preview = c.lastMessage.replaceAll(RegExp(r'\s+'), ' ').trim();
    return ResourceRow(
      subject: r.subject,
      icon: iconForClass(r.className),
      emoji: r.emoji,
      title: r.title.isEmpty ? r.subject : r.title,
      detail: preview.length > 80 ? '${preview.substring(0, 79)}…' : preview,
      trailing: r.openedAt > 0
          ? Text(timeAgo(r.openedAt),
              style: TextStyle(
                  color: context.appColors.textSecondary, fontSize: 12))
          : null,
      onTap: () => _openResource(_drive, r),
    );
  }

  /// `<who> created/edited/deleted · <when>`. A deleted resource is gone, so
  /// its row is not tappable.
  Widget _activityRow(ActivityEntry a) => ResourceRow(
        subject: a.subject,
        icon: iconForClass(a.className),
        emoji: _icons[a.subject],
        title: a.name.isEmpty ? a.subject : a.name,
        detail: '${a.actor ?? 'Unknown member'} ${activityVerb(a.kind)} · '
            '${timeAgo(a.at.toInt())}',
        onTap: a.kind == 'deleted'
            ? null
            : () {
                _visit(
                    openResourceView(
                        api: widget.api,
                        drive: a.drive,
                        subject: a.subject,
                        title: a.name,
                        className: a.className),
                    drive: a.drive,
                    subject: a.subject);
              },
      );

  Widget _showSectionsButton() => Padding(
        padding: const EdgeInsets.all(32),
        child: Center(
          child: TextButton(
            onPressed: () => _setLayout(const HomeLayout()),
            child: const Text('Show all sections'),
          ),
        ),
      );

  /// One section of the home, with the layout's fold state and hold menu.
  Widget _sectionFor(HomeSection id, AppColors c) {
    final key = ValueKey(id);
    final kind = _searchKind(id);
    final fold = (
      collapsed: _layout.collapsed.contains(id),
      onToggle: () => _setLayout(_layout.toggleCollapsed(id)),
      menu: _menuFor(id),
      onMenu: _applyAction,
      section: id,
      onSearch: kind == null ? null : () => _search(kind),
      plus: _plusFor(id),
    );
    switch (id) {
      case HomeSection.notifications:
        return _Section<NotificationItem>(
          key: key,
          title: id.title,
          fold: fold,
          future: _notifications,
          empty: 'No notifications',
          hideEmpty: true,
          rows: (list) => [for (final n in list) _notificationRow(n)],
          onShowAll: (list) =>
              _openAll(id, list.length, (i) => _notificationRow(list[i])),
        );
      case HomeSection.drives:
        return _Section<DriveInfo>(
          key: key,
          title: id.title,
          fold: fold,
          future: _drives,
          empty: 'No drives yet',
          rows: (list) => [for (final d in list) _driveRow(d)],
          onShowAll: (list) =>
              _openAll(id, list.length, (i) => _driveRow(list[i])),
        );
      case HomeSection.recents:
        return _Section<_Recent>(
          key: key,
          title: id.title,
          fold: fold,
          future: _recents,
          empty: 'Nothing opened yet',
          rows: (list) => [for (final r in list) _recentRow(r)],
          onShowAll: (list) {
            final shown = list.take(_maxRecents).toList();
            _openAll(id, shown.length, (i) => _recentRow(shown[i]));
          },
        );
      case HomeSection.activity:
        return _Section<ActivityEntry>(
          key: key,
          title: id.title,
          fold: fold,
          future: _activity,
          empty: _mine ? 'Nothing changed yet' : 'No activity from others yet',
          rows: (list) => [for (final a in list) _activityRow(a)],
          onShowAll: (list) {
            final shown = list.take(_maxActivity).toList();
            _openAll(id, shown.length, (i) => _activityRow(shown[i]));
          },
        );
      case HomeSection.chats:
        return _Section<ChatSummary>(
          key: key,
          title: id.title,
          fold: fold,
          future: _chats,
          empty: 'No chats yet',
          rows: (list) => [for (final chat in list) _chatRow(chat)],
          onShowAll: (list) => _openAllChats(id, list, c),
        );
      case HomeSection.favorites:
        return _Section<RecentResource>(
          key: key,
          title: id.title,
          fold: fold,
          future: _favorites,
          empty: 'No favorites yet',
          hideEmpty: true,
          rows: (list) => [for (final r in list) _homeRow(r)],
          onShowAll: (list) =>
              _openAll(id, list.length, (i) => _homeRow(list[i])),
        );
      case HomeSection.messages:
        return _Section<ConversationRow>(
          key: key,
          title: id.title,
          fold: fold,
          future: _conversations,
          empty: 'No messages yet',
          hideEmpty: true,
          rows: (list) => [for (final r in list) _conversationRow(r)],
          onShowAll: (list) =>
              _openAll(id, list.length, (i) => _conversationRow(list[i])),
        );
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final split = ShellScope.layoutOf(context) == ShellLayout.split;
    return FutureBuilder<List<DriveInfo>>(
      future: _drives,
      builder: (context, snapshot) {
        return Scaffold(
          backgroundColor: c.bgBody,
          appBar: AppTopBar(
            titleWidget: const AtomicWordmark(),
          ),
          // Clamped, with no stretch or glow at the edges: the Material 3
          // stretch overscroll of Android 12+ pulls the whole page past the
          // top and springs it back, which on a flick up reads as the list
          // bouncing down again from the top.
          body: ScrollConfiguration(
            behavior: ScrollConfiguration.of(context).copyWith(
                overscroll: false, physics: const ClampingScrollPhysics()),
            // Sideways the camera cutout is at a side: the rows (ListTiles)
            // keep out of it, and so do the headings.
            child: SafeArea(
              top: false,
              bottom: false,
              child: ListView(
                physics: const ClampingScrollPhysics(),
                children: [
                  // Next to the pages the activity is the detail pane's.
                  for (final id in _layout.visible)
                    if (!(split && id == HomeSection.activity))
                      _sectionFor(id, c),
                  if (_layout.visible.isEmpty) _showSectionsButton(),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

/// The current drive; tapping it lets you pick another.

ResourceRow _resourceRow(RecentResource r,
        void Function(String drive, RecentResource) onOpen, String drive,
        {String? driveName}) =>
    ResourceRow(
      subject: r.subject,
      icon: iconForClass(r.className),
      emoji: r.emoji,
      title: r.title.isEmpty ? r.subject : r.title,
      detail: [
        if (driveName != null) driveName,
        classLabel(r.className),
        if (r.openedAt > 0) timeAgo(r.openedAt)
      ].where((t) => t.isNotEmpty).join(' · '),
      onTap: () => onOpen(drive, r),
    );

/// One home section: a heading with its buttons (search, new, all), the
/// first [_homeItems] rows, and the loading, error or empty state
/// while there is nothing to list.
///
/// Stale while revalidating: when [future] is replaced, the rows of the
/// previous one stay until the new data is there, so a refresh neither
/// flashes a spinner nor moves the page. The spinner shows only for the very
/// first load, and a refresh that fails keeps the old rows without an error.
///
/// Kept alive while scrolled out of view. Otherwise the list disposes it, and
/// when it scrolls back in it is built afresh with a spinner for a frame (its
/// future's answer arrives a microtask later), so the list places it at the
/// wrong height and then corrects: scrolling back up the page jumped, and
/// at the top went down again.
class _Section<T> extends StatefulWidget {
  final String title;
  final _Fold fold;
  final Future<List<T>> future;
  final String empty;
  final List<Widget> Function(List<T>) rows;
  final void Function(List<T>) onShowAll;

  /// Show nothing at all (no heading) while there is nothing to list, while
  /// it is still being read, and when the data cannot be read.
  final bool hideEmpty;

  const _Section({
    super.key,
    required this.title,
    required this.fold,
    required this.future,
    required this.empty,
    required this.rows,
    required this.onShowAll,
    this.hideEmpty = false,
  });

  @override
  State<_Section<T>> createState() => _SectionState<T>();
}

class _SectionState<T> extends State<_Section<T>>
    with AutomaticKeepAliveClientMixin {
  List<T>? _list;

  @override
  bool get wantKeepAlive => true;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _follow(widget.future);
  }

  @override
  void didUpdateWidget(_Section<T> old) {
    super.didUpdateWidget(old);
    if (old.future != widget.future) _follow(widget.future);
  }

  void _follow(Future<List<T>> future) {
    future.then((list) {
      if (!mounted || widget.future != future) return;
      setState(() {
        _list = list;
        _error = null;
      });
    }, onError: (Object e) {
      if (!mounted || widget.future != future) return;
      // Keep what is on screen; an error shows only when there is nothing.
      if (_list == null) setState(() => _error = e);
    });
  }

  /// The heading's title: a tap folds the section, a hold opens the menu to
  /// move or hide sections. Pressed, a faint rounded wash hugs the title and
  /// its chevron (not the row), and the chevron turns instead of changing.
  Widget _foldHeading(BuildContext context) {
    final c = context.appColors;
    final fold = widget.fold;
    return HoldFan<_SectionAction>(
      key: ValueKey('section-heading-${fold.section.name}'),
      size: 48,
      borderRadius: BorderRadius.circular(8),
      tooltip: widget.title,
      menuLabel: 'Arrange sections',
      layout: HoldFanLayout.list,
      defaultIndex: null,
      onTap: fold.onToggle,
      items: fold.menu,
      onSelected: fold.onMenu,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Flexible(
            // A title in proportion to the rows and the bar's 24 dp icons
            // (it was a 13 sp grey label): 15 sp, nearly the text colour.
            child: Text(widget.title,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                    color: c.textPrimary.withValues(alpha: 0.85),
                    fontSize: 15,
                    fontWeight: FontWeight.w600)),
          ),
          const SizedBox(width: 4),
          AnimatedRotation(
            turns: fold.collapsed ? -0.25 : 0,
            duration: const Duration(milliseconds: 150),
            child: Icon(Icons.expand_more, size: 22, color: c.textSecondary),
          ),
        ]),
      ),
    );
  }

  /// The heading row: the title at the left, the section's buttons at the
  /// right (only those that make sense for it).
  Widget _headingRow(BuildContext context, List<T>? list) {
    final fold = widget.fold;
    final name = fold.section.name;
    final onSearch = fold.onSearch;
    final plus = fold.plus;
    // 48 dp like the bar's buttons (more with a large font), with room
    // above it between sections; the title at the rows' 16 dp inset.
    return Padding(
      padding: const EdgeInsets.only(top: 8),
      child: ConstrainedBox(
        constraints: const BoxConstraints(minHeight: 48),
        child: Row(children: [
          const SizedBox(width: 8),
          // The title as wide as it is (and no wider than the room), the
          // buttons at the right edge.
          Expanded(
            child: Align(
              alignment: Alignment.centerLeft,
              child: _foldHeading(context),
            ),
          ),
          if (onSearch != null)
            _HeadingButton(
              key: ValueKey('section-search-$name'),
              tooltip: 'Search ${widget.title}',
              icon: Icons.search,
              onPressed: onSearch,
            ),
          if (plus != null) plus,
          if (list != null && list.isNotEmpty)
            _HeadingButton(
              key: ValueKey('section-all-$name'),
              tooltip: 'All ${widget.title}',
              icon: Icons.format_list_bulleted,
              onPressed: () => widget.onShowAll(list),
            ),
          const SizedBox(width: 4),
        ]),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final c = context.appColors;
    final list = _list;
    final error = list == null ? _error : null;
    // A section that is left out when empty is also left out until it is
    // known not to be: a heading and spinner for each of them filled the
    // first screen of the home, and then went away, moving everything up.
    if (widget.hideEmpty && (error != null || (list?.isEmpty ?? true))) {
      return const SizedBox.shrink();
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _headingRow(context, list),
        if (widget.fold.collapsed)
          const SizedBox.shrink()
        else if (error != null)
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text('$error', style: TextStyle(color: c.alert)),
          )
        else if (list == null)
          const Padding(
            padding: EdgeInsets.all(16),
            child: Center(child: CircularProgressIndicator()),
          )
        else if (list.isEmpty)
          _Empty(widget.empty, c)
        else
          ...widget.rows(list.take(_homeItems).toList()),
      ],
    );
  }
}

/// A small icon button at the right of a section's heading: a 24 dp icon in
/// a 48 dp target, in the heading's quiet colour.
class _HeadingButton extends StatelessWidget {
  final String tooltip;
  final IconData icon;
  final VoidCallback onPressed;

  const _HeadingButton({
    super.key,
    required this.tooltip,
    required this.icon,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) => IconButton(
        tooltip: tooltip,
        onPressed: onPressed,
        color: context.appColors.textSecondary,
        style: IconButton.styleFrom(
          minimumSize: const Size(48, 48),
          fixedSize: const Size(48, 48),
          tapTargetSize: MaterialTapTargetSize.shrinkWrap,
        ),
        icon: Icon(icon, size: 24),
      );
}

/// A full-height page listing everything of one section: [count] rows, each
/// built by [item] only when it scrolls into view.
class _ListPage extends StatelessWidget {
  final String title;
  final int count;
  final Widget Function(int index) item;

  const _ListPage(
      {required this.title, required this.count, required this.item});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppTopBar(title: title),
      body: SafeArea(
          top: false,
          bottom: false,
          child: ListView.builder(
              itemCount: count, itemBuilder: (_, i) => item(i))),
    );
  }
}

/// How close to the end of the chats (in rows) the next page is read.
const _chatsPrefetch = 10;

/// The AI chats' full list: [first] (what the home read), then pages from the
/// host as the list is scrolled within [_chatsPrefetch] rows of its end, under
/// headings by age. Only the rows in view are built.
class _ChatsPage extends StatefulWidget {
  final String title;
  final AssistantApi api;
  final List<ChatSummary> first;
  final AppColors colors;
  final Widget Function(ChatSummary) row;

  const _ChatsPage({
    required this.title,
    required this.api,
    required this.first,
    required this.colors,
    required this.row,
  });

  @override
  State<_ChatsPage> createState() => _ChatsPageState();
}

/// A row of the list: a heading (a String) or a chat.
typedef _ChatEntry = Object;

class _ChatsPageState extends State<_ChatsPage> {
  /// Since the page was made, for the `chats all painted` mark.
  final Stopwatch _opened = Stopwatch()..start();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => Perf.span(
        'chats all painted ${_chats.length}', _opened.elapsedMilliseconds));
  }

  late List<ChatSummary> _chats = widget.first;
  late List<_ChatEntry> _entries = _entriesOf(_chats);

  /// No more pages: the last one was short, or reading one failed.
  late bool _done = widget.first.length < AssistantApi.chatsPageSize;
  bool _loading = false;

  static List<_ChatEntry> _entriesOf(List<ChatSummary> chats) => [
        for (final (label, group) in groupChatsByAge(chats)) ...[
          label,
          ...group
        ],
      ];

  Future<void> _loadMore() async {
    if (_loading || _done) return;
    _loading = true;
    final watch = Stopwatch()..start();
    try {
      final page = await widget.api
          .chatsPage(offset: _chats.length, limit: AssistantApi.chatsPageSize);
      Perf.span('chats page ${_chats.length}+${page.length}',
          watch.elapsedMilliseconds);
      if (!mounted) return;
      final known = {for (final c in _chats) c.subject};
      setState(() {
        _chats = [
          ..._chats,
          for (final c in page)
            if (known.add(c.subject)) c
        ];
        _entries = _entriesOf(_chats);
        if (page.length < AssistantApi.chatsPageSize) _done = true;
      });
    } catch (_) {
      // Keep what is shown; do not ask again in a loop.
      if (mounted) setState(() => _done = true);
    } finally {
      _loading = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    // A spinner row while more may come.
    final count = _entries.length + (_done ? 0 : 1);
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppTopBar(title: widget.title),
      body: SafeArea(
        top: false,
        bottom: false,
        child: ListView.builder(
          key: const Key('chats-all-list'),
          itemCount: count,
          findChildIndexCallback: (key) {
            if (key is! ValueKey<String>) return null;
            final i = _entries.indexWhere((e) => switch (e) {
                  final ChatSummary chat => 'chat-${chat.subject}' == key.value,
                  final String label => 'heading-$label' == key.value,
                  _ => false,
                });
            return i < 0 ? null : i;
          },
          itemBuilder: (context, i) {
            if (i >= count - _chatsPrefetch) _loadMore();
            if (i >= _entries.length) {
              return const Padding(
                key: ValueKey('chats-loading'),
                padding: EdgeInsets.all(16),
                child: Center(
                    child: SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2))),
              );
            }
            return switch (_entries[i]) {
              final ChatSummary chat => KeyedSubtree(
                  key: ValueKey('chat-${chat.subject}'),
                  child: widget.row(chat)),
              final String label => KeyedSubtree(
                  key: ValueKey('heading-$label'),
                  child: _Heading(label, widget.colors)),
              _ => const SizedBox.shrink(),
            };
          },
        ),
      ),
    );
  }
}

class _Heading extends StatelessWidget {
  final String text;
  final AppColors c;

  const _Heading(this.text, this.c);

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
        child: Text(text,
            style: TextStyle(
                color: c.textSecondary,
                fontSize: 13,
                fontWeight: FontWeight.w600)),
      );
}

class _Empty extends StatelessWidget {
  final String text;
  final AppColors c;

  const _Empty(this.text, this.c);

  /// One quiet line under the heading, where the first row would start: a
  /// centred block with 32 px around it made an empty section taller than a
  /// full one.
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
        child: Text(text, style: TextStyle(color: c.textSecondary)),
      );
}

/// [chats] (newest first) under small headings by how long ago they were
/// last active: Today, Yesterday, This week, This month, Earlier. A heading
/// appears only when it has chats; a chat without any activity goes last.
List<(String, List<ChatSummary>)> groupChatsByAge(List<ChatSummary> chats,
    {DateTime? now}) {
  final today = now ?? DateTime.now();
  final start = DateTime(today.year, today.month, today.day);
  String label(ChatSummary chat) {
    if (chat.lastActivity == 0) return 'Earlier';
    final then = DateTime.fromMillisecondsSinceEpoch(chat.lastActivity);
    final day = DateTime(then.year, then.month, then.day);
    final days = start.difference(day).inDays;
    if (days <= 0) return 'Today';
    if (days == 1) return 'Yesterday';
    if (days < 7) return 'This week';
    if (days < 31) return 'This month';
    return 'Earlier';
  }

  const order = ['Today', 'Yesterday', 'This week', 'This month', 'Earlier'];
  final groups = <String, List<ChatSummary>>{};
  for (final chat in chats) {
    groups.putIfAbsent(label(chat), () => []).add(chat);
  }
  return [
    for (final name in order)
      if (groups[name] != null) (name, groups[name]!),
  ];
}

/// "just now", "5 min ago", "3 h ago", "2 d ago", then the date.
String timeAgo(int ms, {DateTime? now}) {
  final then = DateTime.fromMillisecondsSinceEpoch(ms);
  final diff = (now ?? DateTime.now()).difference(then);
  if (diff.inMinutes < 1) return 'just now';
  if (diff.inHours < 1) return '${diff.inMinutes} min ago';
  if (diff.inDays < 1) return '${diff.inHours} h ago';
  if (diff.inDays < 7) return '${diff.inDays} d ago';
  return then.toIso8601String().substring(0, 10);
}
