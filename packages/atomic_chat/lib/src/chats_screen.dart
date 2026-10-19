import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt, HoldFan, HoldFanItem, HoldFanLayout;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'app_top_bar.dart';
import 'home_sections.dart';

import 'models.dart';
import 'slide_back_route.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'resource_row.dart';
import 'resource_view.dart';
import 'native_views.dart';

/// Items per section on the home; the rest is behind "Show all".
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

/// How a section folds and what its heading's hold menu offers.
typedef _Fold = ({
  bool collapsed,
  VoidCallback onToggle,
  List<HoldFanItem<_SectionAction>> menu,
  ValueChanged<_SectionAction> onMenu,
});

typedef _Recent = ({String drive, RecentResource resource});

/// Home screen: one scrollable page of small sections (Drives, Recents, Activity,
/// AI Chats), each with its newest few items and a "Show all" for the rest. A
/// section is one [_Section]; adding another is one more entry in the list.
/// Every section shows as soon as its own data arrives.
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

  /// How long a home list took, in debug builds (`[home]` in logcat).
  Future<T> _timed<T>(String what, Future<T> future) {
    if (!kDebugMode) return future;
    final watch = Stopwatch()..start();
    return future.whenComplete(
        () => debugPrint('[home] $what ${watch.elapsedMilliseconds} ms'));
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
    HomeLayout.load().then((layout) {
      if (mounted) setState(() => _layout = layout);
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
    // The profile button of the shell signs out through the home.
    if (_profile != null) _shell?.onUser = _settings;
  }

  /// A page of the bar (search, a new document, a resource opened from
  /// search) covered the home.
  bool _covered = false;

  /// Back on the home after the bar's pages: they can have opened, made or
  /// changed resources, so the lists are read again (the home's own pages
  /// reload in [_push]).
  void _onShellChanged() {
    final shell = _shell;
    if (shell == null) return;
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
    return drives;
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

  /// The activity feed; its rows do not carry the resources' own icons, so
  /// those are looked up after the list is out (never blocking it).
  Future<List<ActivityEntry>> _loadActivity() async {
    final list = await widget.api.activity(_maxActivity);
    widget.api.resourceIcons([for (final a in list) a.subject]).then((icons) {
      if (mounted && !_sameIcons(icons)) setState(() => _icons = icons);
    }).catchError((Object _) {});
    return list;
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
        _chats = widget.api.chats();
        _recents = _loadRecents();
        _favorites = widget.api.favorites();
        _conversations = widget.api.conversations();
        _activity = _loadActivity();
        _notifications = _loadNotifications();
      });
    });
    // A frame must run for the callback to fire.
    WidgetsBinding.instance.scheduleFrame();
  }

  /// Whether `screen` can have changed what the home lists: a "Show all" list
  /// and a settings page only show things (what is opened from a list
  /// reloads by itself when it is closed).
  static bool _changesData(Widget screen) =>
      !(screen is _ListPage || (screen is ResourceView && screen.path != null));

  Future<void> _push(Widget screen) async {
    await Navigator.of(context)
        .push(SlideBackRoute<void>(builder: (_) => screen));
    if (mounted && _changesData(screen)) _reload();
  }

  WidgetBuilder? get _profile => widget.profile ?? _shell?.profile;

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

  void _openChat(ChatSummary? chat) => _push(ChatScreen(
        api: widget.api,
        subject: chat?.subject,
        title: chat?.name ?? '',
      ));

  void _openResource(String drive, RecentResource r) {
    widget.api.noteOpened(drive, r.subject);
    _push(openResourceView(
        api: widget.api,
        drive: drive,
        subject: r.subject,
        title: r.title,
        className: r.className));
  }

  Widget _driveRow(DriveInfo d) => ResourceRow(
        icon: Icons.folder_outlined,
        emoji: d.emoji,
        title: d.name.isEmpty ? 'Untitled drive' : d.name,
        // The drive itself, drawn by the page: everything in it, read from
        // the store with the same query the web app uses.
        onTap: () => _push(openResourceView(
            api: widget.api,
            drive: d.subject,
            subject: d.subject,
            title: d.name)),
      );

  Widget _chatRow(ChatSummary chat) => ResourceRow(
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
    widget.api.noteOpened(_drive, n.about);
    _push(openResourceView(
        api: widget.api, drive: _drive, subject: n.about, title: ''));
  }

  /// A conversation: who is in it, the newest message and when it was sent.
  Widget _conversationRow(ConversationRow c) {
    final r = c.resource;
    final preview = c.lastMessage.replaceAll(RegExp(r'\s+'), ' ').trim();
    return ResourceRow(
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

  /// `<who> created/changed/deleted · <when>`. A deleted resource is gone, so
  /// its row is not tappable.
  Widget _activityRow(ActivityEntry a) => ResourceRow(
        icon: iconForClass(a.className),
        emoji: _icons[a.subject],
        title: a.name.isEmpty ? a.subject : a.name,
        detail: '${a.actor ?? 'Someone'} ${a.kind} · ${timeAgo(a.at.toInt())}',
        onTap: a.kind == 'deleted'
            ? null
            : () {
                widget.api.noteOpened(a.drive, a.subject);
                _push(openResourceView(
                    api: widget.api,
                    drive: a.drive,
                    subject: a.subject,
                    title: a.name,
                    className: a.className));
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
    final fold = (
      collapsed: _layout.collapsed.contains(id),
      onToggle: () => _setLayout(_layout.toggleCollapsed(id)),
      menu: _menuFor(id),
      onMenu: _applyAction,
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
          onShowAll: (list) => _push(_ListPage(
              title: id.title,
              children: [for (final n in list) _notificationRow(n)])),
        );
      case HomeSection.drives:
        return _Section<DriveInfo>(
          key: key,
          title: id.title,
          fold: fold,
          future: _drives,
          empty: 'No drives yet',
          rows: (list) => [for (final d in list) _driveRow(d)],
          onShowAll: (list) => _push(_ListPage(
              title: id.title, children: [for (final d in list) _driveRow(d)])),
        );
      case HomeSection.recents:
        return _Section<_Recent>(
          key: key,
          title: id.title,
          fold: fold,
          future: _recents,
          empty: 'Nothing opened yet',
          rows: (list) => [for (final r in list) _recentRow(r)],
          onShowAll: (list) => _push(_ListPage(title: id.title, children: [
            for (final r in list.take(_maxRecents)) _recentRow(r),
          ])),
        );
      case HomeSection.activity:
        return _Section<ActivityEntry>(
          key: key,
          title: id.title,
          fold: fold,
          future: _activity,
          empty: 'No activity yet',
          rows: (list) => [for (final a in list) _activityRow(a)],
          onShowAll: (list) => _push(_ListPage(title: id.title, children: [
            for (final a in list.take(_maxActivity)) _activityRow(a),
          ])),
        );
      case HomeSection.chats:
        return _Section<ChatSummary>(
          key: key,
          title: id.title,
          fold: fold,
          future: _chats,
          empty: 'No chats yet',
          rows: (list) => [for (final chat in list) _chatRow(chat)],
          onShowAll: (list) => _push(_ListPage(title: id.title, children: [
            for (final (label, group) in groupChatsByAge(list)) ...[
              _Heading(label, c),
              for (final chat in group) _chatRow(chat),
            ],
          ])),
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
          onShowAll: (list) => _push(_ListPage(
              title: id.title, children: [for (final r in list) _homeRow(r)])),
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
          onShowAll: (list) => _push(_ListPage(
              title: id.title,
              children: [for (final r in list) _conversationRow(r)])),
        );
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
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
            child: ListView(
              physics: const ClampingScrollPhysics(),
              children: [
                for (final id in _layout.visible) _sectionFor(id, c),
                if (_layout.visible.isEmpty) _showSectionsButton(),
              ],
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

/// One home section: a header with "Show all" (only when there are more than
/// [_homeItems]), the first few rows, and the loading, error or empty state
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

  /// Show nothing at all (no heading) while there is nothing to list, and
  /// when the data cannot be read.
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

  /// The heading: a tap folds the section, a hold opens the menu to move or
  /// hide sections.
  Widget _foldHeading(BuildContext context) {
    final c = context.appColors;
    final fold = widget.fold;
    return HoldFan<_SectionAction>(
      width: double.infinity,
      size: 40,
      tooltip: widget.title,
      menuLabel: 'Arrange sections',
      layout: HoldFanLayout.list,
      defaultIndex: null,
      onTap: fold.onToggle,
      items: fold.menu,
      onSelected: fold.onMenu,
      child: Padding(
        padding: const EdgeInsets.only(left: 16, top: 8),
        child: Align(
          alignment: Alignment.centerLeft,
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Text(widget.title,
                style: TextStyle(
                    color: c.textSecondary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600)),
            const SizedBox(width: 4),
            Icon(fold.collapsed ? Icons.chevron_right : Icons.expand_more,
                size: 18, color: c.textSecondary),
          ]),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final c = context.appColors;
    final list = _list;
    final error = list == null ? _error : null;
    if (widget.hideEmpty && (error != null || (list?.isEmpty ?? false))) {
      return const SizedBox.shrink();
    }
    final more = list != null && list.length > _homeItems;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(children: [
          Expanded(child: _foldHeading(context)),
          // Same size, weight and padding as the heading, so the two sit on
          // one baseline.
          if (more && !widget.fold.collapsed)
            InkWell(
              onTap: () => widget.onShowAll(list),
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
                child: Text('Show all',
                    style: TextStyle(
                        color: Theme.of(context).colorScheme.primary,
                        fontSize: 13,
                        fontWeight: FontWeight.w600)),
              ),
            ),
        ]),
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

/// A full-height page listing everything of one section.
class _ListPage extends StatelessWidget {
  final String title;
  final List<Widget> children;

  const _ListPage({required this.title, required this.children});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppTopBar(title: title),
      body: ListView(children: children),
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
