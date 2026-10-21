import 'package:atomic_flutter/atomic_flutter.dart' show ErrorText;
import 'dart:async';
import 'dart:math' as math;

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt, AppScrollPhysics, Perf, SectionHeaderStyle;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart' show RenderAbstractViewport;
import 'package:flutter/services.dart' show HapticFeedback;
import 'package:shared_preferences/shared_preferences.dart';
import 'app_sidebar_icons.dart';
import 'app_top_bar.dart';
import 'home_sections.dart';
import 'home_sections_dialog.dart';

import 'models.dart';
import 'slide_back_route.dart';
import 'app_bottom_bar.dart' show ShellActions;
import 'app_shell.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'drive_home.dart';
import 'resource_row.dart';
import 'row_leading.dart';
import 'sidebar_metrics.dart';
import 'resource_view.dart';
import 'native_views.dart';
import 'new_document_sheet.dart';

/// Items per section on the home; the rest is behind its "Show all" row.
const _homeItems = 4;

/// Most entries the activity feed holds.
const _maxActivity = 100;

/// How long a section's rows take to unfold and to fold (quick, so the home
/// never waits on it), and the curves: out when they appear, in when they go.
const _sectionExpand = Duration(milliseconds: 160);
const _sectionCollapse = Duration(milliseconds: 120);
const _sectionExpandCurve = Curves.easeOutCubic;
const _sectionCollapseCurve = Curves.easeInCubic;

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
  HomeLayout _layout = HomeLayout.fresh;

  /// The drive the person picked in the switcher (the store's active drive
  /// once set); [ChatsScreen.drive] until then.
  String? _selected;

  final _tree = GlobalKey<DriveTreeState>();

  /// The drives as last listed, for the header.
  List<DriveInfo> _driveList = const [];

  /// The order panels were opened in (the last is the newest), to keep only
  /// the newest open when the window gets compact.
  final List<HomeSection> _openOrder = [];

  @override
  void initState() {
    super.initState();
    _drive = widget.drive;
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
    final emptied = ((_counts[id] ?? 0) > 0) != (n > 0);
    _counts[id] = n;
    // A panel that appears or goes away changes how the room is shared.
    if (emptied && mounted) setState(() {});
    _publishSections();
  }

  /// Hands the Home button every section, in the home's order (hidden ones
  /// at their saved places), with whether it is hidden and how many rows it
  /// has once known.
  void _publishSections() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final shell = _shell;
      if (!mounted || shell == null) return;
      final list = <HomeSectionEntry>[
        for (final s in _layout.order)
          (
            section: s,
            hidden: _layout.hidden.contains(s),
            count: _counts[s],
          ),
      ];
      if (!listEquals(list, shell.homeSections.value)) {
        shell.homeSections.value = list;
      }
    });
  }

  int _handledRequest = 0;

  /// The Home button's menu picked a section: its full list opens. A section
  /// on the home that has rows is unfolded and scrolled into view first; one
  /// that is empty, hidden from the home or not on it (the activity next to
  /// the detail pane) just opens its page, and stays as it is.
  void _onSectionRequest() {
    final req = _shell?.sectionRequest.value;
    if (req == null || req.n == _handledRequest) return;
    _handledRequest = req.n;
    final id = req.section;
    final onHome = _layout.visible.contains(id) &&
        !(_shell?.split == true && id == HomeSection.activity);
    final state = _sectionKeys[id]?.currentState;
    if (onHome && state != null && state.hasRows) {
      if (_layout.collapsed.contains(id)) {
        _setLayout(_layout.toggleCollapsed(id));
      }
      _revealSection(id, thenShowAll: true);
    } else {
      _openSectionPage(id);
    }
  }

  /// The section's full list, read from the home's own lists (they load
  /// whether or not the section shows), opened as "Show all" opens it.
  Future<void> _openSectionPage(HomeSection id) async {
    final c = context.appColors;
    try {
      switch (id) {
        case HomeSection.drives:
          final list = await _drives;
          _openAll(id, list.length, (i) => _driveRow(list[i]),
              empty: 'No drives yet');
        case HomeSection.notifications:
          final list = await _notifications;
          _openAll(id, list.length, (i) => _notificationRow(list[i]),
              empty: 'No notifications');
        case HomeSection.favorites:
          final list = await _favorites;
          _openAll(id, list.length, (i) => _homeRow(list[i]),
              empty: 'No favorites yet');
        case HomeSection.messages:
          final list = await _conversations;
          _openAll(id, list.length, (i) => _conversationRow(list[i]),
              empty: 'No messages yet');
        case HomeSection.chats:
          _openAllChats(id, await _chats, c);
        case HomeSection.activity:
          _openActivityPage(id);
      }
    } catch (e) {
      // A list that cannot be read opens as an empty one.
      debugPrint('Home section $id not opened with its rows: $e');
      if (mounted) _openAll(id, 0, (_) => const SizedBox.shrink());
    }
  }

  /// Scrolls the home so the section [id], just unfolded, can be seen: as
  /// little as needed when heading and rows fit in the room above the bottom
  /// bar (none when they already do), and with the heading at the top when
  /// the section is taller than that. Runs after the frame that lays out the
  /// rows. The hold menu and a tap on a heading both use it. The rows are
  /// still growing then, so the scroll aims at the section's full height
  /// ([growth] more than it has now) and takes as long as the unfolding
  /// ([duration]), so both end together.
  void _revealSection(HomeSection id, {bool thenShowAll = false}) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      final state = _sectionKeys[id]?.currentState;
      final ctx = _sectionKeys[id]?.currentContext;
      if (ctx != null) {
        _scrollToSection(ctx,
            growth: state?.growth ?? 0,
            duration: state?.expandDuration ?? _sectionExpand);
      }
      if (thenShowAll) state?.showAll();
    });
    WidgetsBinding.instance.scheduleFrame();
  }

  void _scrollToSection(BuildContext ctx,
      {double growth = 0, Duration duration = _sectionExpand}) {
    final ro = ctx.findRenderObject();
    final scrollable = Scrollable.maybeOf(ctx);
    if (ro is! RenderBox || !ro.attached || scrollable == null) return;
    final position = scrollable.position;
    final viewport = RenderAbstractViewport.maybeOf(ro);
    if (viewport == null) return;
    // The list is padded by the bottom bar, but its viewport runs under it.
    final inset = MediaQuery.paddingOf(ctx).bottom;
    final top = viewport.getOffsetToReveal(ro, 0.0).offset;
    final bottom = viewport.getOffsetToReveal(ro, 1.0).offset + inset + growth;
    // `bottom` shows the section's end, `top` its heading at the very top;
    // a section taller than the room gets `top`.
    final lo = bottom < top ? bottom : top;
    final target = position.pixels
        .clamp(lo, top)
        .clamp(position.minScrollExtent, position.maxScrollExtent + growth)
        .toDouble();
    if ((target - position.pixels).abs() < 0.5) return;
    position.animateTo(target, duration: duration, curve: _sectionExpandCurve);
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
    _ownSwitcher.dispose();
    super.dispose();
  }

  /// The agent's drives; when there are none (not synced yet) just the one
  /// the app opened on.
  Future<List<DriveInfo>> _loadDrives() async {
    var drives = await widget.api.drives();
    if (drives.isEmpty) {
      drives = [(subject: widget.drive, name: '', emoji: null, picture: null)];
    }
    final want = _selected ?? widget.drive;
    _drive = drives.any((d) => d.subject == want) ? want : drives.first.subject;
    if (mounted) _shell?.drive.value = _drive;
    // The most recently visited first.
    final sorted = await sortDrivesByRecent(widget.api, drives);
    if (mounted) {
      setState(() => _driveList = sorted);
      _noteCount(HomeSection.drives, sorted.length);
    }
    return sorted;
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
      _tree.currentState?.reload();
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
  void _openAll(HomeSection id, int count, Widget Function(int) item,
          {String empty = 'Nothing here yet'}) =>
      _openPage(
          id,
          (_) => _ListPage(
              title: id.title, count: count, item: item, empty: empty));

  /// The activity's full page.
  void _openActivityPage(HomeSection id) => _openPage(
      id,
      (_) => _ActivityPage(
            title: id.title,
            changed: _feedChanged,
            mine: () => _mine,
            onMine: _setMine,
            api: widget.api,
            row: _activityRow,
          ));

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

  /// The drive's own page, without making it the current drive.
  void _openDrivePage(DriveInfo d) => _push(
      openResourceView(
          api: widget.api, drive: d.subject, subject: d.subject, title: d.name),
      subject: d.subject,
      onLeave: () => noteDriveVisited(d.subject));

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
        emoji: chat.emoji,
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

  /// An activity row as the web's Drive Activity: the resource's icon and
  /// title, and who did it with their avatar and when ("Polle · 16h ago"),
  /// under a feed across drives also which drive. On a wide pane the who and
  /// when sit at the right; on a phone they are the caption. A deleted
  /// resource is gone, so its row is not tappable.
  Widget _activityRow(ActivityEntry a) => Builder(builder: (context) {
        final showDrive = ActivityDriveFilter.of(context) == null;
        final wide = MediaQuery.sizeOf(context).width >= 600;
        final c = context.appColors;
        final verb = switch (a.kind) {
          'created' => 'created ',
          'deleted' => 'deleted ',
          _ => '',
        };
        final who = a.actor ?? 'Unknown member';
        final when = shortTimeAgo(a.at.toInt());
        final lead = leadingOf(a.picture, _icons[a.subject], a.className);
        final style = TextStyle(color: c.textSecondary, fontSize: 13);
        Widget avatar(double size) => RowLeading(
              key: const Key('activity-actor-avatar'),
              size: size,
              shape: RowShape.circle,
              showInitial: true,
              fallbackLabel: who,
              fallbackIcon: Icons.person_outline,
              image: ImageSource.of(a.actorPicture),
            );
        final driveName = a.driveName ?? '';
        final driveCaption = showDrive && driveName.isNotEmpty
            ? Row(key: const Key('activity-drive'), children: [
                SizedBox(
                    width: 14,
                    height: 14,
                    child: RowLeading(
                        size: 14,
                        fallbackIcon: Icons.folder_outlined,
                        fallbackLabel: driveName,
                        image: ImageSource.of(a.drivePicture))),
                const SizedBox(width: 6),
                Flexible(
                    child: Text(driveName,
                        maxLines: 1, overflow: TextOverflow.ellipsis)),
              ])
            : null;
        return ResourceRow(
          subject: a.subject,
          icon: lead.icon,
          image: lead.image,
          shape: lead.shape,
          showInitial: lead.initial,
          title: a.name.isEmpty ? a.subject : a.name,
          detailWidget: wide
              ? driveCaption
              : Row(children: [
                  avatar(16),
                  const SizedBox(width: 6),
                  Flexible(
                      child: Text('$who $verb· $when'.replaceAll('  ', ' '),
                          maxLines: 1, overflow: TextOverflow.ellipsis)),
                  if (driveCaption != null) ...[
                    const Text(' · '),
                    Flexible(child: driveCaption),
                  ],
                ]),
          trailing: wide
              ? Row(mainAxisSize: MainAxisSize.min, children: [
                  avatar(22),
                  const SizedBox(width: 8),
                  Text('$who $verb· $when'.replaceAll('  ', ' '), style: style),
                ])
              : null,
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
      });

  /// One panel of the home, with the layout's fold state and hold menu.
  Widget _sectionFor(HomeSection id, AppColors c, {bool divider = false}) {
    final fold = (
      collapsed: _layout.collapsed.contains(id),
      onToggle: () {
        final opening = _layout.collapsed.contains(id);
        if (opening) {
          _openOrder
            ..remove(id)
            ..add(id);
        }
        // On a compact window one panel is open at a time.
        _setLayout(opening && _accordion
            ? _layout.openOnly(id)
            : _layout.toggleCollapsed(id));
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
          divider: divider,
          bodyMax: _bodyMaxes[id] ?? 200,
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
          divider: divider,
          bodyMax: _bodyMaxes[id] ?? 200,
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
          divider: divider,
          bodyMax: _bodyMaxes[id] ?? 200,
          title: id.title,
          fold: fold,
          future: _activity,
          empty: _mine ? 'Nothing changed yet' : 'No activity from others yet',
          rows: (list) => [for (final a in list) _activityRow(a)],
          total: (list) => list.length.clamp(0, _maxActivity),
          onShowAll: (_) => _openActivityPage(id),
        );
      case HomeSection.chats:
        return _Section<ChatSummary>(
          key: key,
          divider: divider,
          bodyMax: _bodyMaxes[id] ?? 200,
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
          divider: divider,
          bodyMax: _bodyMaxes[id] ?? 200,
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
          divider: divider,
          bodyMax: _bodyMaxes[id] ?? 200,
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

  /// Whether the panel is on screen: these three are left out while empty.
  bool _takesRoom(HomeSection id) =>
      !const {
        HomeSection.notifications,
        HomeSection.favorites,
        HomeSection.messages
      }.contains(id) ||
      (_counts[id] ?? 0) > 0;

  /// The sections the home lists, a hairline above each but the first.
  List<HomeSection> _panelIds(bool split) => [
        for (final id in _layout.visible)
          if (id != HomeSection.drives &&
              !(split && id == HomeSection.activity))
            id
      ];

  List<Widget> _shownSections(bool split) {
    final c = context.appColors;
    final ids = _panelIds(split);
    return [
      for (var i = 0; i < ids.length; i++)
        _sectionFor(ids[i], c, divider: i > 0),
    ];
  }

  /// Whether the panels behave as an accordion: on a compact window (phone)
  /// one is open at a time. Follows the window live.
  bool get _accordion {
    final forced = HomeLayout.accordionOverride;
    if (forced != null) return forced;
    final size = MediaQuery.sizeOf(context);
    return size.width < 600 || size.height < 700;
  }

  /// How tall a panel's rows may get before they scroll inside it.
  final Map<HomeSection, double> _bodyMaxes = {};

  /// Compact window: of several open panels only the one opened last stays.
  void _enforceAccordion() {
    if (!_accordion) return;
    final open = [
      for (final s in homePanelSections)
        if (!_layout.collapsed.contains(s)) s
    ];
    if (open.length < 2) return;
    final keep = _openOrder.lastWhere(open.contains, orElse: () => open.last);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && _accordion) _setLayout(_layout.openOnly(keep));
    });
  }

  /// The current drive's own list: its tree of children and "New".
  Widget _driveTree() => DriveTree(
        key: _tree,
        api: widget.api,
        drive: _drive,
        onNew: _newInDrive,
        onOpen: (child) => _visit(
            openResourceView(
                api: widget.api,
                drive: _drive,
                subject: child.subject,
                title: child.title,
                className: child.className),
            drive: _drive,
            subject: child.subject),
      );

  /// The "New" row: the new-document sheet with the current drive selected;
  /// what it makes opens.
  Future<void> _newInDrive() async {
    final created = await showNewDocumentSheet(context,
        api: widget.api, fallbackDrive: _drive, preferredDrive: _drive);
    if (created == null || !mounted) return;
    widget.api.noteOpened(created.drive, created.subject);
    await _visit(
        openResourceView(
            api: widget.api,
            drive: created.drive,
            subject: created.subject,
            title: created.name),
        drive: created.drive,
        subject: created.subject);
    if (mounted) _tree.currentState?.reload();
  }

  /// A drive picked in the switcher: it becomes the store's active drive and
  /// everything that follows the drive (the tree, the search scope, where New
  /// goes) moves to it.
  Future<void> _selectDrive(DriveInfo d) async {
    if (driveKey(d.subject) == driveKey(_drive)) return;
    try {
      await widget.api.setActiveDrive(d.subject);
    } catch (e) {
      debugPrint('Active drive not set: $e');
    }
    if (!mounted) return;
    setState(() {
      _selected = d.subject;
      _drive = d.subject;
    });
    _shell?.drive.value = d.subject;
    noteDriveVisited(d.subject);
    _reload();
  }

  DriveInfo? get _currentDrive {
    for (final d in _driveList) {
      if (driveKey(d.subject) == driveKey(_drive)) return d;
    }
    return null;
  }

  /// Whether the sidebar shows the drive list in place of its content. The
  /// shell holds it (so Home can close it); without a shell it is ours.
  final ValueNotifier<bool> _ownSwitcher = ValueNotifier(false);
  ValueNotifier<bool> get _switcher => _shell?.driveSwitcher ?? _ownSwitcher;

  void _toggleSwitcher() => _switcher.value = !_switcher.value;

  /// The drive list, filling the sidebar. Whatever it does closes it first.
  Widget _switcherBody() {
    final shell = _shell;
    void closing(VoidCallback f) {
      _switcher.value = false;
      f();
    }

    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) _switcher.value = false;
      },
      child: DriveSwitcherContent(
        fill: true,
        drives: _driveList,
        current: _drive,
        onSelect: (d) => closing(() => _selectDrive(d)),
        onOpen: (d) => closing(() => _openDrivePage(d)),
        onManage: () => closing(() => _openSectionPage(HomeSection.drives)),
        onNew: shell == null
            ? null
            : () => closing(ShellActions(widget.api, shell).newDrive),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final split = ShellScope.layoutOf(context) == ShellLayout.split;
    // "Show icons in the sidebar" off: the rows below are text only.
    _enforceAccordion();
    return SidebarMetricsScope(
        child: SidebarIconsScope(
            child: FutureBuilder<List<DriveInfo>>(
      future: _drives,
      builder: (context, snapshot) {
        return Scaffold(
          backgroundColor: c.bgBody,
          appBar: AppTopBar(
            compact: SidebarMetrics.of(context).compact,
            titleWidget: Builder(
              builder: (headerContext) => Align(
                alignment: Alignment.centerLeft,
                child: CurrentDriveHeader(
                  drive: _currentDrive,
                  onTap: _toggleSwitcher,
                ),
              ),
            ),
          ),
          // The app's overscroll stretch.
          body: ValueListenableBuilder<bool>(
            valueListenable: _switcher,
            builder: (context, switching, _) => switching
                ? _switcherBody()
                : ScrollConfiguration(
            behavior: ScrollConfiguration.of(context)
                .copyWith(physics: const AppScrollPhysics()),
            // Sideways the camera cutout is at a side: the rows (ListTiles)
            // keep out of it, and so do the headings.
            child: SafeArea(
              top: false,
              bottom: false,
              child: LayoutBuilder(builder: (context, box) {
                final shown = _panelIds(split);
                final open = [
                  for (final s in shown)
                    if (!_layout.collapsed.contains(s)) s
                ];
                final room = box.maxHeight.isFinite ? box.maxHeight : 600.0;
                final m = SidebarMetrics.of(context);
                final scale =
                    math.max(1.0, MediaQuery.textScalerOf(context).scale(1));
                // Upper bounds of what a panel needs: its heading, up to
                // _homeItems rows (two lines with a caption on touch) and a
                // "Show all" row. A panel this tall never scrolls.
                final headerH = (m.compact ? m.headerHeight : 48.0) * scale + 1;
                final rowH = (m.compact ? m.rowHeight : 72.0) * scale;
                final showAllH = (m.compact ? m.rowHeight : 48.0) * scale;
                final natural = rowH * _homeItems + showAllH;
                final headers = headerH * shown.where(_takesRoom).length;
                // The panels come first; the tree keeps at least three rows.
                final minTree = (m.compact ? m.rowHeight : 56.0) * 3;
                final bottomPad = MediaQuery.paddingOf(context).bottom;
                final cap = math.max(0.0, room - minTree);
                final avail = math.max(0.0, cap - headers - bottomPad);
                _bodyMaxes.clear();
                final taking = open.where(_takesRoom).toList();
                for (final s in open) {
                  _bodyMaxes[s] = natural;
                }
                if (taking.isNotEmpty) {
                  if (natural * taking.length <= avail) {
                    // Everything fits: each panel is as tall as its rows.
                  } else {
                    // Short window: the panel opened last keeps its whole
                    // content, the others share what is left (and scroll).
                    final last = _openOrder.lastWhere(taking.contains,
                        orElse: () => taking.last);
                    final others = taking.length - 1;
                    final lastMax = others == 0
                        ? math.min(natural, avail)
                        : math.min(
                            natural, math.max(0.0, avail - others * rowH));
                    _bodyMaxes[last] = lastMax;
                    for (final s in taking) {
                      if (s != last) {
                        _bodyMaxes[s] =
                            math.max(0.0, (avail - lastMax) / others);
                      }
                    }
                  }
                }
                return Column(children: [
                  // The tree takes what the panels leave; it scrolls itself.
                  Expanded(child: _driveTree()),
                  // Bottom-anchored panels, just above the bottom bar.
                  Container(
                    key: const Key('home-panels'),
                    constraints: BoxConstraints(maxHeight: cap),
                    padding: EdgeInsets.only(
                        bottom: MediaQuery.paddingOf(context).bottom),
                    child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: _shownSections(split)),
                  ),
                ]);
              }),
            ),
          ),
        ),
        );
      },
    )));
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

  /// How tall the open rows get before they scroll inside the panel.
  final double bodyMax;

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
    this.bodyMax = double.infinity,
    this.badge,
    this.divider = false,
  });

  /// A hairline above the heading (every section but the first shown).
  final bool divider;

  @override
  State<_Section<T>> createState() => _SectionState<T>();
}

class _SectionState<T> extends State<_Section<T>>
    with AutomaticKeepAliveClientMixin, SingleTickerProviderStateMixin {
  List<T>? _list;

  /// 0 folded, 1 unfolded; [_shape] is it with the expand/collapse curves.
  /// The rows live in one clipped, faded box of this height factor (one
  /// animated thing, not one per row) and are not built at all once folded.
  late final AnimationController _open;
  late final Animation<double> _shape;
  final GlobalKey _bodyKey = GlobalKey();

  /// How long unfolding takes now (none with reduced motion).
  Duration get expandDuration => _reduced ? Duration.zero : _sectionExpand;

  bool get _reduced => MediaQuery.maybeDisableAnimationsOf(context) ?? false;

  /// How much taller the rows will get before the unfolding is done.
  double get growth {
    final box = _bodyKey.currentContext?.findRenderObject();
    if (box is! RenderBox || !box.hasSize) return 0;
    return box.size.height * (1 - _shape.value);
  }

  @override
  void dispose() {
    _open.dispose();
    super.dispose();
  }

  @override
  bool get wantKeepAlive => true;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _open =
        AnimationController(vsync: this, value: widget.fold.collapsed ? 0 : 1);
    _shape = CurvedAnimation(
        parent: _open,
        curve: _sectionExpandCurve,
        reverseCurve: _sectionCollapseCurve);
    _follow(widget.future);
  }

  @override
  void didUpdateWidget(_Section<T> old) {
    super.didUpdateWidget(old);
    if (old.future != widget.future) _follow(widget.future);
    if (old.fold.collapsed != widget.fold.collapsed) {
      final reduced = _reduced;
      if (widget.fold.collapsed) {
        _open.animateBack(0,
            duration: reduced ? Duration.zero : _sectionCollapse,
            curve: Curves.linear);
      } else {
        _open.animateTo(1,
            duration: reduced ? Duration.zero : _sectionExpand,
            curve: Curves.linear);
      }
    }
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

  /// Whether the section has rows to list.
  bool get hasRows => _list?.isNotEmpty ?? false;

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
    final m = SidebarMetrics.of(context);
    final compact = m.compact;
    final titleStyle = compact
        ? c.sectionHeaderText.copyWith(fontSize: m.headerTextSize, height: 1.2)
        : c.sectionHeaderText;
    final chevron = RotationTransition(
      turns: Tween<double>(begin: -0.25, end: 0).animate(_shape),
      child: Icon(Icons.expand_more,
          size: compact ? m.chevronSize : 22, color: c.textSecondary),
    );
    final content = Row(children: [
      Expanded(
        // The app's section-header style: full-strength text on
        // the band, so headers read apart from the rows.
        child: Text(widget.title,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            strutStyle: compact ? SidebarRow.strut(m.headerTextSize) : null,
            style: titleStyle),
      ),
      if (unread > 0) ...[
        const SizedBox(width: 8),
        Container(
          key: const Key('notifications-badge'),
          constraints: BoxConstraints(
              minWidth: compact ? 16 : 20, minHeight: compact ? 16 : 20),
          padding: EdgeInsets.symmetric(horizontal: compact ? 5 : 6),
          alignment: Alignment.center,
          decoration: BoxDecoration(
              color: c.main,
              borderRadius: BorderRadius.circular(compact ? 8 : 10)),
          child: Text(unread > 99 ? '99+' : '$unread',
              style: const TextStyle(
                  color: Colors.white,
                  fontSize: 12,
                  height: 1.1,
                  fontWeight: FontWeight.w600)),
        ),
      ],
      SizedBox(width: compact ? 4 : 4),
      if (compact)
        SizedBox(
            key: const Key('panel-chevron'),
            width: m.chevronSlot,
            height: m.chevronSlot,
            child: Center(child: chevron))
      else
        chevron,
    ]);
    final band = Material(
      color: c.sectionBand,
      child: InkWell(
        mouseCursor: WidgetStateMouseCursor.clickable,
        onTap: fold.onToggle,
        onLongPress: fold.onHold,
        child: Padding(
          padding: EdgeInsets.symmetric(
              horizontal: compact ? m.hPad : 16, vertical: compact ? 2 : 0),
          child: content,
        ),
      ),
    );
    final key = ValueKey('home-panel-${fold.section.name}');
    return Semantics(
      container: true,
      button: true,
      expanded: !fold.collapsed,
      label: label,
      onTap: fold.onToggle,
      onLongPress: fold.onHold,
      child: ExcludeSemantics(
        child: compact
            ? ConstrainedBox(
                key: key,
                constraints: BoxConstraints(minHeight: m.headerHeight),
                child: band)
            : SizedBox(
                key: key, height: 48, width: double.infinity, child: band),
      ),
    );
  }

  /// The heading row: 48 dp like the bar's buttons, on the header band, with
  /// a hairline above it between sections (not before the first).
  Widget _headingRow(BuildContext context) => Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (widget.divider)
            Container(
                key: ValueKey('section-divider-${widget.fold.section.name}'),
                height: 1,
                color: context.appColors.sectionDivider),
          _foldHeading(context),
        ],
      );

  @override
  Widget build(BuildContext context) {
    super.build(context);
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
        AnimatedBuilder(
          animation: _open,
          // Folded away: nothing is built, so the section costs its heading.
          builder: (context, _) => _open.isDismissed
              ? const SizedBox.shrink()
              // Fully open: the rows alone. The clip, the height factor and
              // the fade only exist while folding, so a section at rest has
              // no opacity layer (a repaint boundary with an alpha layer
              // even at 1.0) over its rows while the list scrolls.
              : _open.isCompleted
                  ? RepaintBoundary(
                      key: _bodyKey,
                      child: _body(context, list, error),
                    )
                  : ClipRect(
                      child: Align(
                        alignment: Alignment.topCenter,
                        heightFactor: _shape.value,
                        child: FadeTransition(
                          opacity: _shape,
                          child: RepaintBoundary(
                            key: _bodyKey,
                            child: _body(context, list, error),
                          ),
                        ),
                      ),
                    ),
        ),
      ],
    );
  }

  /// The rows below the heading (what folds).
  Widget _body(BuildContext context, List<T>? list, Object? error) {
    final c = context.appColors;
    final body = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (error != null)
          Padding(
            padding: const EdgeInsets.all(16),
            child: ErrorText('$error', color: c.alert),
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
        if (error == null && list != null && list.length > _homeItems)
          _ShowAllRow(
            key: ValueKey('section-show-all-${widget.fold.section.name}'),
            count: widget.total?.call(list) ?? list.length,
            onTap: () => widget.onShowAll(list),
          ),
      ],
    );
    if (!widget.bodyMax.isFinite) return body;
    // A bottom panel: its rows scroll inside the room it has.
    return ConstrainedBox(
      constraints: BoxConstraints(maxHeight: widget.bodyMax),
      child: SingleChildScrollView(
          key: ValueKey('home-panel-body-${widget.fold.section.name}'),
          child: body),
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
  Widget build(BuildContext context) {
    final m = SidebarMetrics.of(context);
    final c = context.appColors;
    if (m.compact) {
      return SidebarRow(
        title: 'Show all ($count)',
        slot: SidebarIconsScope.of(context),
        titleStyle:
            SidebarRow.text(c.main, m.textSize, weight: FontWeight.w600),
        onTap: onTap,
      );
    }
    return InkWell(
      mouseCursor: WidgetStateMouseCursor.clickable,
      onTap: onTap,
      child: ConstrainedBox(
        constraints: const BoxConstraints(minHeight: 48),
        child: Align(
          alignment: Alignment.centerLeft,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Text('Show all ($count)',
                style: TextStyle(
                    color: c.main, fontSize: 14, fontWeight: FontWeight.w600)),
          ),
        ),
      ),
    );
  }
}

/// A full-height page listing everything of one section: [count] rows, each
/// built by [item] only when it scrolls into view.
class _ListPage extends StatelessWidget {
  final String title;
  final int count;
  final Widget Function(int index) item;

  /// What an empty list says.
  final String empty;

  const _ListPage(
      {required this.title,
      required this.count,
      required this.item,
      this.empty = 'Nothing here yet'});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppTopBar(title: title),
      body: SafeArea(
          top: false,
          bottom: false,
          child: count == 0
              ? Align(
                  alignment: Alignment.topLeft,
                  child: _Empty(empty, c, key: const Key('list-empty')))
              : ListView.builder(
                  itemCount: count, itemBuilder: (_, i) => item(i))),
    );
  }
}

class _Notifier extends ChangeNotifier {
  @override
  // ignore: unnecessary_overrides
  void notifyListeners() => super.notifyListeners();
}

/// The activity's full list on a phone: the feed paged back in time (newest
/// first, [AssistantApi.activityPageSize] at a time as the end comes near,
/// under a spinner row, then a "You're all caught up" footer), with the "Show
/// mine" chip in the bar. The setting is the home's own.
class _ActivityPage extends StatefulWidget {
  final String title;
  final AssistantApi api;
  final Listenable changed;
  final bool Function() mine;
  final ValueChanged<bool> onMine;
  final Widget Function(ActivityEntry) row;

  const _ActivityPage({
    required this.title,
    required this.api,
    required this.changed,
    required this.mine,
    required this.onMine,
    required this.row,
  });

  @override
  State<_ActivityPage> createState() => _ActivityPageState();
}

class _ActivityPageState extends State<_ActivityPage> {
  List<ActivityEntry> _all = [];

  /// The entries of the chosen drive (every drive when none is chosen).
  List<ActivityEntry> get _entries => _drive == null
      ? _all
      : [
          for (final a in _all)
            if (driveKey(a.drive) == _drive) a
        ];
  set _entries(List<ActivityEntry> v) => _all = v;

  /// The chosen drive's [driveKey]; null for every drive.
  String? _drive;
  List<DriveInfo> _driveList = const [];
  bool _done = false;
  bool _loading = false;
  bool _failed = false;

  /// Bumped when the feed starts over, so a page read for the old one is
  /// dropped.
  int _generation = 0;

  @override
  void initState() {
    super.initState();
    widget.changed.addListener(_restart);
    widget.api.drives().then((ds) {
      if (mounted) setState(() => _driveList = visibleDrives(ds));
    }).catchError((Object _) {});
    _loadMore();
  }

  @override
  void dispose() {
    widget.changed.removeListener(_restart);
    super.dispose();
  }

  void _restart() {
    _generation++;
    setState(() {
      _entries = [];
      _done = false;
      _loading = false;
      _failed = false;
    });
    _loadMore();
  }

  Future<void> _loadMore() async {
    if (_loading || _done) return;
    _loading = true;
    final generation = _generation;
    try {
      final page = await widget.api.activityPage(
          before: _all.isEmpty ? null : _all.last, includeOwn: widget.mine());
      if (!mounted || generation != _generation) return;
      final known = {for (final a in _all) '${a.subject}@${a.at}'};
      setState(() {
        _all = [
          ..._all,
          for (final a in page)
            if (known.add('${a.subject}@${a.at}')) a
        ];
        if (page.length < AssistantApi.activityPageSize) _done = true;
      });
    } catch (_) {
      // Keep what is shown; do not ask again in a loop.
      if (mounted && generation == _generation) {
        setState(() {
          _done = true;
          _failed = true;
        });
      }
    } finally {
      if (generation == _generation) _loading = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final entries = _entries;
    final empty = entries.isEmpty && _done;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppTopBar(title: widget.title, actions: [
        Padding(
            padding: const EdgeInsets.only(right: 8),
            child: Center(
                child: ShowMineChip(
                    value: widget.mine(), onChanged: widget.onMine))),
      ]),
      body: SafeArea(
        top: false,
        bottom: false,
        child: empty
            ? Padding(
                padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                child: Text(
                    _failed
                        ? 'Could not read the activity'
                        : widget.mine()
                            ? 'Nothing changed yet'
                            : 'No activity from others yet',
                    style: TextStyle(color: c.textSecondary)),
              )
            : ActivityDriveFilter(
                drive: _drive,
                child: Column(children: [
                  if (_driveList.length > 1) _driveChips(c),
                  Expanded(
                      child: entries.isEmpty && _all.isEmpty
                          ? const Center(child: CircularProgressIndicator())
                          : ListView.builder(
                              key: const Key('activity-all-list'),
                              // The rows, then a spinner while more may come
                              // or the end marker.
                              itemCount: entries.length + 1,
                              itemBuilder: (context, i) {
                                if (i >= entries.length - _chatsPrefetch) {
                                  _loadMore();
                                }
                                if (i < entries.length) {
                                  return widget.row(entries[i]);
                                }
                                if (!_done) {
                                  return const Padding(
                                    key: ValueKey('activity-loading'),
                                    padding: EdgeInsets.all(16),
                                    child: Center(
                                        child: SizedBox(
                                            width: 20,
                                            height: 20,
                                            child: CircularProgressIndicator(
                                                strokeWidth: 2))),
                                  );
                                }
                                return Padding(
                                  key: const ValueKey('activity-end'),
                                  padding: const EdgeInsets.all(24),
                                  child: Center(
                                      child: Text(
                                          entries.isEmpty
                                              ? 'Nothing in this drive yet'
                                              : "You're all caught up",
                                          style: TextStyle(
                                              color: c.textSecondary))),
                                );
                              })),
                ]),
              ),
      ),
    );
  }

  /// "All" and one chip per drive, filtering the feed.
  Widget _driveChips(AppColors c) => SizedBox(
        height: 48,
        child: ListView(
          key: const Key('activity-drive-chips'),
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          children: [
            for (final (key, label) in [
              (null, 'All drives'),
              for (final d in _driveList)
                (driveKey(d.subject), d.name.isEmpty ? d.subject : d.name),
            ])
              Padding(
                padding: const EdgeInsets.only(right: 8),
                child: ChoiceChip(
                  mouseCursor: WidgetStateMouseCursor.clickable,
                  key: Key('activity-drive-${key ?? 'all'}'),
                  label: Text(label),
                  selected: _drive == key,
                  onSelected: (_) => setState(() => _drive = key),
                ),
              ),
          ],
        ),
      );
}

/// The drive an activity list is limited to (its [driveKey]); null for a feed
/// across drives, whose rows then say which drive each change is in.
class ActivityDriveFilter extends InheritedWidget {
  final String? drive;

  const ActivityDriveFilter(
      {super.key, required this.drive, required super.child});

  static String? of(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<ActivityDriveFilter>()?.drive;

  @override
  bool updateShouldNotify(ActivityDriveFilter old) => old.drive != drive;
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
        child: _entries.isEmpty && _done
            ? Align(
                alignment: Alignment.topLeft,
                child: _Empty('No chats yet', widget.colors,
                    key: const Key('list-empty')))
            : ListView.builder(
                key: const Key('chats-all-list'),
                itemCount: count,
                findChildIndexCallback: (key) {
                  if (key is! ValueKey<String>) return null;
                  final i = _entries.indexWhere((e) => switch (e) {
                        final ChatSummary chat =>
                          'chat-${chat.subject}' == key.value,
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
                              child:
                                  CircularProgressIndicator(strokeWidth: 2))),
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

  const _Empty(this.text, this.c, {super.key});

  /// One quiet line under the heading, where the first row would start: a
  /// centred block with 32 px around it made an empty section taller than a
  /// full one.
  @override
  Widget build(BuildContext context) {
    final m = SidebarMetrics.of(context);
    if (m.compact) {
      return Padding(
        padding: EdgeInsets.fromLTRB(m.hPad, 4, m.hPad, 8),
        child: Text(text, style: SidebarRow.text(c.textSecondary, m.textSize)),
      );
    }
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
      child: Text(text, style: TextStyle(color: c.textSecondary)),
    );
  }
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

/// The web's short relative time: "just now", "5m ago", "16h ago", "1d ago",
/// "3w ago", then the date after eight weeks.
String shortTimeAgo(int ms, {DateTime? now}) {
  final then = DateTime.fromMillisecondsSinceEpoch(ms);
  final diff = (now ?? DateTime.now()).difference(then);
  if (diff.inMinutes < 1) return 'just now';
  if (diff.inHours < 1) return '${diff.inMinutes}m ago';
  if (diff.inDays < 1) return '${diff.inHours}h ago';
  if (diff.inDays < 7) return '${diff.inDays}d ago';
  if (diff.inDays < 56) return '${diff.inDays ~/ 7}w ago';
  return then.toIso8601String().substring(0, 10);
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
