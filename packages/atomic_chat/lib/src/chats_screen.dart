import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt, Perf;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart' show RenderAbstractViewport;
import 'package:flutter/services.dart' show HapticFeedback;
import 'package:shared_preferences/shared_preferences.dart';
import 'app_top_bar.dart';
import 'home_sections.dart';
import 'home_sections_dialog.dart';

import 'models.dart';
import 'slide_back_route.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'resource_row.dart';
import 'row_leading.dart';
import 'resource_view.dart';
import 'native_views.dart';
import 'new_document_sheet.dart';

/// Items per section on the home; the rest is behind its "Show all" row.
const _homeItems = 4;

/// Most entries the activity feed holds.
const _maxActivity = 100;

/// How a section folds and what holding its heading does.
typedef _Fold = ({
  bool collapsed,
  VoidCallback onToggle,
  VoidCallback onHold,
  HomeSection section,
  ValueChanged<int> onCount,
});

/// How an activity row says what happened (`kind` as the host names it).
String activityVerb(String kind) => switch (kind) {
      'changed' => 'edited',
      _ => kind,
    };

/// Home screen: one scrollable page of small sections (Drives, Activity,
/// AI Chats), each with its newest few items. A section's heading folds it on
/// a tap and arranges the sections on a hold. Below the first few items a
/// "Show all" row lists all of them (in the detail pane on a tablet, a page of
/// its own on a phone). Search and New are the bar's. A section is one
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

  /// Which sections show, in which order, and which are folded (per device).
  HomeLayout _layout = const HomeLayout();

  @override
  void initState() {
    super.initState();
    RowPictures.loader = widget.api.fileBytes;
    if (!kReleaseMode) _markLoaded();
    // Once the home is drawn: read the search index so the first keystroke is
    // not the first read.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      widget.api.warmSearch().catchError((Object _) {});
    });
    HomeLayout.load().then((layout) {
      if (mounted) setState(() => _layout = layout);
      _publishSections();
    });
    _loadMine();
    widget.api.storeChanges?.addListener(_storeChanged);
  }

  /// The store may have new conversations or messages: read that list again
  /// (only while the home is what is looked at).
  void _storeChanged() {
    if (!mounted || _covered) return;
    if (ModalRoute.of(context)?.isCurrent == false) return;
    setState(() => _conversations = widget.api.conversations());
  }

  /// SharedPreferences key: the activity feed's "Show mine" (per device).
  static const showMineKey = 'activity_show_mine';

  /// The activity feed shows the person's own changes too.
  bool _mine = false;

  /// Tells the full activity page (phone) that the feed, its icons or the
  /// "Show mine" setting changed.
  final _feedChanged = _Notifier();

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
    _feedChanged.notifyListeners();
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
    _publishSections();
  }

  /// Holding a heading: the dialog that turns sections on and off and
  /// arranges them. It applies live; a phone gets a bottom sheet, the tablet
  /// a centred dialog.
  void _customize() {
    HapticFeedback.lightImpact();
    showHomeSectionsDialog(
      context,
      layout: () => _layout,
      onChanged: _setLayout,
      split: ShellScope.layoutOf(context) == ShellLayout.split,
    );
  }

  /// Keys of the sections: to scroll one into view and open its full list.
  final Map<HomeSection, GlobalKey<_SectionState<dynamic>>> _sectionKeys = {};

  /// How many rows each section has (once read), for the Home button's menu.
  final Map<HomeSection, int> _counts = {};

  void _noteCount(HomeSection id, int n) {
    if (_counts[id] == n) return;
    _counts[id] = n;
    _publishSections();
  }

  /// Hands the Home button the sections it can jump to: the visible ones
  /// that have something, in the home's order. Next to the detail pane the
  /// activity is not a section of the home.
  void _publishSections() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final shell = _shell;
      if (!mounted || shell == null) return;
      final split = shell.split;
      final list = [
        for (final s in _layout.visible)
          if (!(split && s == HomeSection.activity) && (_counts[s] ?? 0) > 0) s
      ];
      if (!listEquals(list, shell.homeSections.value)) {
        shell.homeSections.value = list;
      }
    });
  }

  int _handledRequest = 0;

  /// The Home button's menu picked a section: unfold it, scroll it into
  /// view and open its full list.
  void _onSectionRequest() {
    final req = _shell?.sectionRequest.value;
    if (req == null || req.n == _handledRequest) return;
    _handledRequest = req.n;
    final id = req.section;
    if (_layout.collapsed.contains(id)) {
      _setLayout(_layout.toggleCollapsed(id));
    }
    _revealSection(id, thenShowAll: true);
  }

  /// Scrolls the home so the section [id], just unfolded, can be seen: as
  /// little as needed when heading and rows fit in the room above the bottom
  /// bar (none when they already do), and with the heading at the top when
  /// the section is taller than that. Runs after the frame that lays out the
  /// rows. The hold menu and a tap on a heading both use it.
  void _revealSection(HomeSection id, {bool thenShowAll = false}) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      final state = _sectionKeys[id]?.currentState;
      final ctx = _sectionKeys[id]?.currentContext;
      if (ctx != null) _scrollToSection(ctx);
      if (thenShowAll) state?.showAll();
    });
    WidgetsBinding.instance.scheduleFrame();
  }

  void _scrollToSection(BuildContext ctx) {
    final ro = ctx.findRenderObject();
    final scrollable = Scrollable.maybeOf(ctx);
    if (ro is! RenderBox || !ro.attached || scrollable == null) return;
    final position = scrollable.position;
    final viewport = RenderAbstractViewport.maybeOf(ro);
    if (viewport == null) return;
    // The list is padded by the bottom bar, but its viewport runs under it.
    final inset = MediaQuery.paddingOf(ctx).bottom;
    final top = viewport.getOffsetToReveal(ro, 0.0).offset;
    final bottom = viewport.getOffsetToReveal(ro, 1.0).offset + inset;
    // `bottom` shows the section's end, `top` its heading at the very top;
    // a section taller than the room gets `top`.
    final lo = bottom < top ? bottom : top;
    final target = position.pixels
        .clamp(lo, top)
        .clamp(position.minScrollExtent, position.maxScrollExtent)
        .toDouble();
    if ((target - position.pixels).abs() < 0.5) return;
    position.animateTo(target,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOutCubic);
  }

  ShellController? _shell;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final shell = ShellScope.maybeOf(context);
    if (!identical(shell, _shell)) {
      _shell?.removeListener(_onShellChanged);
      _shell?.sectionRequest.removeListener(_onSectionRequest);
      shell?.addListener(_onShellChanged);
      shell?.sectionRequest.addListener(_onSectionRequest);
      _handledRequest = shell?.sectionRequest.value?.n ?? 0;
    }
    _shell = shell;
    _publishActivity();
    _publishSections();
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
    widget.api.storeChanges?.removeListener(_storeChanged);
    _shell?.removeListener(_onShellChanged);
    _shell?.sectionRequest.removeListener(_onSectionRequest);
    _shell?.homeSections.value = const [];
    _shell?.activity.value = null;
    if (_shell?.onUser == _settings) _shell?.onUser = null;
    _feedChanged.dispose();
    super.dispose();
  }

  /// The agent's drives; when there are none (not synced yet) just the one
  /// the app opened on.
  Future<List<DriveInfo>> _loadDrives() async {
    var drives = await widget.api.drives();
    if (drives.isEmpty) {
      drives = [(subject: widget.drive, name: '', emoji: null, picture: null)];
    }
    _drive = drives.any((d) => d.subject == widget.drive)
        ? widget.drive
        : drives.first.subject;
    if (mounted) _shell?.drive.value = _drive;
    // The most recently visited first.
    return sortDrivesByRecent(widget.api, drives);
  }

  /// The activity feed: what other members changed in the person's drives
  /// (the host leaves out the person's own changes; those are in Search). Its
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
        _feedChanged.notifyListeners();
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
        _drives = _loadDrives();
        _chats = widget.api.chats();
        _favorites = widget.api.favorites();
        _conversations = widget.api.conversations();
        _activity = _loadActivity();
        _notifications = _loadNotifications();
      });
      _feedChanged.notifyListeners();
      _publishActivity();
    });
    // A frame must run for the callback to fire.
    WidgetsBinding.instance.scheduleFrame();
  }

  /// Whether `screen` can have changed what the home lists: a section's list
  /// and a settings page only show things (what is opened from a list
  /// reloads by itself when it is closed).
  static bool _changesData(Widget screen) => !(screen is _ListPage ||
      screen is _ActivityPage ||
      (screen is ResourceView && screen.path != null));

  /// Opens [screen]: pushed over the home on a phone, in the detail pane
  /// next to it on a tablet. [subject] is what it shows, to mark its row.
  Future<void> _push(Widget screen,
      {String? subject, VoidCallback? onLeave}) async {
    await openFromList<void>(context, (_) => screen,
        subject: subject, onLeave: onLeave);
    if (mounted && _changesData(screen)) _reload();
  }

  /// Opens [subject] of [drive] and notes the visit once it is left: the
  /// lists (the drives' order) do not move under the finger that
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
        image: ImageSource.of(d.picture),
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
        icon: iconForClass('ai-chat'),
        shape: RowShape.circle,
        title: chat.name.isEmpty ? 'Untitled chat' : chat.name,
        onTap: () => _openChat(chat),
      );

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
      image: ImageSource.of(n.actor),
      shape: n.actor == null ? RowShape.square : RowShape.circle,
      showInitial: n.actor != null,
      label: (n.actor?.name ?? '').isEmpty ? n.title : n.actor!.name,
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
    final lead = leadingOf(r.picture, r.emoji, 'conversation');
    return ResourceRow(
      subject: r.subject,
      icon: lead.icon,
      image: lead.image,
      shape: lead.shape,
      showInitial: lead.initial,
      label: r.picture?.name,
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

  Widget _emptyHome() => Padding(
        padding: const EdgeInsets.all(32),
        child: Column(children: [
          Text('All sections are off',
              style: TextStyle(color: context.appColors.textSecondary)),
          const SizedBox(height: 8),
          TextButton(
            onPressed: _customize,
            child: const Text('Customize'),
          ),
        ]),
      );

  /// One section of the home, with the layout's fold state and hold menu.
  Widget _sectionFor(HomeSection id, AppColors c) {
    final fold = (
      collapsed: _layout.collapsed.contains(id),
      onToggle: () {
        final opening = _layout.collapsed.contains(id);
        _setLayout(_layout.toggleCollapsed(id));
        if (opening) _revealSection(id);
      },
      onHold: _customize,
      section: id,
      onCount: (n) => _noteCount(id, n),
    );
    final key = _sectionKeys[id] ??= GlobalKey<_SectionState<dynamic>>();
    switch (id) {
      case HomeSection.notifications:
        return _Section<NotificationItem>(
          key: key,
          title: id.title,
          fold: fold,
          future: _notifications,
          empty: 'No notifications',
          hideEmpty: true,
          badge: (list) => list.where((n) => !n.read).length,
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
      case HomeSection.activity:
        return _Section<ActivityEntry>(
          key: key,
          title: id.title,
          fold: fold,
          future: _activity,
          empty: _mine ? 'Nothing changed yet' : 'No activity from others yet',
          rows: (list) => [for (final a in list) _activityRow(a)],
          total: (list) => list.length.clamp(0, _maxActivity),
          onShowAll: (_) => _openPage(
              id,
              (_) => _ActivityPage(
                    title: id.title,
                    changed: _feedChanged,
                    mine: () => _mine,
                    onMine: _setMine,
                    feed: () => _activity,
                    row: _activityRow,
                  )),
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
                  if (_layout.visible.isEmpty) _emptyHome(),
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
    {String? driveName}) {
  final lead = leadingOf(r.picture, r.emoji, r.className);
  return ResourceRow(
      subject: r.subject,
      icon: lead.icon,
      image: lead.image,
      shape: lead.shape,
      showInitial: lead.initial,
      label: r.picture?.name,
      title: r.title.isEmpty ? r.subject : r.title,
      detail: [
        if (driveName != null) driveName,
        classLabel(r.className),
        if (r.openedAt > 0) timeAgo(r.openedAt)
      ].where((t) => t.isNotEmpty).join(' · '),
      onTap: () => onOpen(drive, r),
    );
}

/// One home section: a heading, the first [_homeItems] rows, a "Show all"
/// row when there are more, and the loading, error or empty state while
/// there is nothing to list.
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

  /// How many rows the full list holds, when fewer than the section has.
  final int Function(List<T>)? total;

  /// Show nothing at all (no heading) while there is nothing to list, while
  /// it is still being read, and when the data cannot be read.
  final bool hideEmpty;

  /// A count shown as a pill before the chevron (unread notifications);
  /// nothing at 0.
  final int Function(List<T>)? badge;

  const _Section({
    super.key,
    required this.title,
    required this.fold,
    required this.future,
    required this.empty,
    required this.rows,
    required this.onShowAll,
    this.total,
    this.hideEmpty = false,
    this.badge,
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
      widget.fold.onCount(list.length);
    }, onError: (Object e) {
      if (!mounted || widget.future != future) return;
      // Keep what is on screen; an error shows only when there is nothing.
      if (_list == null) setState(() => _error = e);
    });
  }

  /// Opens the section's full list (the "Show all" row), if it has rows.
  void showAll() {
    final list = _list;
    if (list != null && list.isNotEmpty) widget.onShowAll(list);
  }

  /// The heading: one tap target across the whole row (a tap folds the
  /// section, a hold opens the dialog to show, hide and move sections). The
  /// title is at the rows' 16 dp inset, the chevron at the right turns
  /// instead of changing.
  Widget _foldHeading(BuildContext context) {
    final unread = _list == null ? 0 : (widget.badge?.call(_list!) ?? 0);
    final c = context.appColors;
    final fold = widget.fold;
    final label = '${widget.title}${unread > 0 ? ', $unread unread' : ''}, '
        '${fold.collapsed ? 'collapsed' : 'expanded'}';
    return Semantics(
      container: true,
      button: true,
      expanded: !fold.collapsed,
      label: label,
      onTap: fold.onToggle,
      onLongPress: fold.onHold,
      child: ExcludeSemantics(
        child: SizedBox(
          key: ValueKey('section-heading-${fold.section.name}'),
          height: 48,
          width: double.infinity,
          child: Material(
            type: MaterialType.transparency,
            child: InkWell(
              onTap: fold.onToggle,
              onLongPress: fold.onHold,
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Row(children: [
                  Expanded(
                    // A title in proportion to the rows and the bar's 24 dp
                    // icons: 15 sp, nearly the text colour.
                    child: Text(widget.title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                            color: c.textPrimary.withValues(alpha: 0.85),
                            fontSize: 15,
                            fontWeight: FontWeight.w600)),
                  ),
                  if (unread > 0) ...[
                    const SizedBox(width: 8),
                    Container(
                      key: const Key('notifications-badge'),
                      constraints:
                          const BoxConstraints(minWidth: 20, minHeight: 20),
                      padding: const EdgeInsets.symmetric(horizontal: 6),
                      alignment: Alignment.center,
                      decoration: BoxDecoration(
                          color: c.main,
                          borderRadius: BorderRadius.circular(10)),
                      child: Text(unread > 99 ? '99+' : '$unread',
                          style: const TextStyle(
                              color: Colors.white,
                              fontSize: 12,
                              height: 1.1,
                              fontWeight: FontWeight.w600)),
                    ),
                  ],
                  const SizedBox(width: 4),
                  AnimatedRotation(
                    turns: fold.collapsed ? -0.25 : 0,
                    duration: const Duration(milliseconds: 150),
                    child: Icon(Icons.expand_more,
                        size: 22, color: c.textSecondary),
                  ),
                ]),
              ),
            ),
          ),
        ),
      ),
    );
  }

  /// The heading row: 48 dp like the bar's buttons, with room above it
  /// between sections.
  Widget _headingRow(BuildContext context) => Padding(
        padding: const EdgeInsets.only(top: 8),
        child: _foldHeading(context),
      );

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
        _headingRow(context),
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
        if (!widget.fold.collapsed &&
            error == null &&
            list != null &&
            list.length > _homeItems)
          _ShowAllRow(
            key: ValueKey('section-show-all-${widget.fold.section.name}'),
            count: widget.total?.call(list) ?? list.length,
            onTap: () => widget.onShowAll(list),
          ),
      ],
    );
  }
}

/// The last row of a section with more than [_homeItems] rows: "Show all (N)",
/// at the rows' inset and 48 dp high.
class _ShowAllRow extends StatelessWidget {
  final int count;
  final VoidCallback onTap;

  const _ShowAllRow({super.key, required this.count, required this.onTap});

  @override
  Widget build(BuildContext context) => InkWell(
        onTap: onTap,
        child: ConstrainedBox(
          constraints: const BoxConstraints(minHeight: 48),
          child: Align(
            alignment: Alignment.centerLeft,
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Text('Show all ($count)',
                  style: TextStyle(
                      color: context.appColors.main,
                      fontSize: 14,
                      fontWeight: FontWeight.w600)),
            ),
          ),
        ),
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

class _Notifier extends ChangeNotifier {
  @override
  // ignore: unnecessary_overrides
  void notifyListeners() => super.notifyListeners();
}

/// The activity's full list on a phone: the section's rows, all of them, with
/// the "Show mine" chip in the bar. The setting is the home's own.
class _ActivityPage extends StatelessWidget {
  final String title;
  final Listenable changed;
  final bool Function() mine;
  final ValueChanged<bool> onMine;
  final Future<List<ActivityEntry>> Function() feed;
  final Widget Function(ActivityEntry) row;

  const _ActivityPage({
    required this.title,
    required this.changed,
    required this.mine,
    required this.onMine,
    required this.feed,
    required this.row,
  });

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return ListenableBuilder(
      listenable: changed,
      builder: (context, _) => Scaffold(
        backgroundColor: c.bgBody,
        appBar: AppTopBar(title: title, actions: [
          Padding(
              padding: const EdgeInsets.only(right: 8),
              child: Center(
                  child: ShowMineChip(value: mine(), onChanged: onMine))),
        ]),
        body: SafeArea(
          top: false,
          bottom: false,
          child: FutureBuilder<List<ActivityEntry>>(
            future: feed(),
            builder: (context, snap) {
              final list =
                  (snap.data ?? const <ActivityEntry>[]).take(_maxActivity);
              final rows = list.toList();
              if (snap.connectionState != ConnectionState.done &&
                  rows.isEmpty) {
                return const Center(child: CircularProgressIndicator());
              }
              if (rows.isEmpty) {
                return Padding(
                  padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                  child: Text(
                      mine()
                          ? 'Nothing changed yet'
                          : 'No activity from others yet',
                      style: TextStyle(color: c.textSecondary)),
                );
              }
              return ListView.builder(
                  itemCount: rows.length, itemBuilder: (_, i) => row(rows[i]));
            },
          ),
        ),
      ),
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
