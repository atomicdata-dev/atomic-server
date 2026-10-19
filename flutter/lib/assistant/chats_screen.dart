import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../screens/sync_screen.dart';
import '../theme.dart';
import '../widgets/slide_back_route.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'resource_row.dart';
import 'native_views.dart';

/// Items per section on the home; the rest is behind "Show all".
const _homeItems = 4;

/// Most items the merged recents list holds.
const _maxRecents = 100;

/// Most entries the activity feed holds.
const _maxActivity = 100;

typedef _Recent = ({String drive, RecentResource resource});

/// Home screen: one scrollable page of small sections (Drives, Recents, Activity,
/// AI Chats), each with its newest few items and a "Show all" for the rest. A
/// section is one [_Section]; adding another is one more entry in the list.
/// Every section shows as soon as its own data arrives.
class ChatsScreen extends StatefulWidget {
  final AssistantApi api;

  /// The drive the home opens on; the search looks in it.
  final String drive;
  final VoidCallback onOpenGallery;
  final VoidCallback? onSignOut;

  const ChatsScreen({
    super.key,
    required this.drive,
    this.api = const AssistantApi(),
    required this.onOpenGallery,
    this.onSignOut,
  });

  @override
  State<ChatsScreen> createState() => _ChatsScreenState();
}

class _ChatsScreenState extends State<ChatsScreen> {
  late Future<List<DriveInfo>> _drives = _loadDrives();
  late Future<List<ChatSummary>> _chats = widget.api.chats();
  late Future<List<_Recent>> _recents = _loadRecents();
  late Future<List<RecentResource>> _favorites = widget.api.favorites();
  late Future<List<RecentResource>> _conversations = widget.api.conversations();
  late Future<List<ActivityEntry>> _activity =
      widget.api.activity(_maxActivity);

  /// The most recent drive: the one the home opened on, else the first.
  String _drive = '';
  ShellController? _shell;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _shell = ShellScope.maybeOf(context);
    // The profile button of the shell signs out through the home.
    _shell?.onUser = _settings;
  }

  @override
  void dispose() {
    if (_shell?.onUser == _settings) _shell?.onUser = null;
    super.dispose();
  }

  /// The agent's drives; when there are none (not synced yet) just the one
  /// the app opened on.
  Future<List<DriveInfo>> _loadDrives() async {
    var drives = await widget.api.drives();
    if (drives.isEmpty) drives = [(subject: widget.drive, name: '')];
    _drive = drives.any((d) => d.subject == widget.drive)
        ? widget.drive
        : drives.first.subject;
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

  void _reload() => setState(() {
        _chats = widget.api.chats();
        _recents = _loadRecents();
        _favorites = widget.api.favorites();
        _conversations = widget.api.conversations();
        _activity = widget.api.activity(_maxActivity);
      });

  Future<void> _push(Widget screen) async {
    await Navigator.of(context)
        .push(SlideBackRoute<void>(builder: (_) => screen));
    if (mounted) _reload();
  }

  Future<void> _settings() async {
    final signedOut =
        await Navigator.of(context, rootNavigator: true).push<bool>(
              MaterialPageRoute<bool>(builder: (_) => const SyncScreen()),
            ) ??
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

  Widget _recentRow(_Recent r) =>
      _resourceRow(r.resource, _openResource, r.drive);

  /// Favorites and conversations are not tied to one drive: they open in the
  /// current one.
  Widget _homeRow(RecentResource r) => _resourceRow(r, _openResource, _drive);

  /// "<who> created/changed/deleted · <when>". A deleted resource is gone, so
  /// its row is not tappable.
  Widget _activityRow(ActivityEntry a) => ResourceRow(
        icon: Icons.description_outlined,
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

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return FutureBuilder<List<DriveInfo>>(
      future: _drives,
      builder: (context, snapshot) {
        return Scaffold(
          backgroundColor: c.bgBody,
          appBar: AppBar(
            backgroundColor: c.bgBody,
            title: const Text('Home'),
            actions: [
              IconButton(
                tooltip: 'Canvases',
                icon: const Icon(Icons.draw_outlined),
                onPressed: widget.onOpenGallery,
              ),
            ],
          ),
          body: ListView(
            children: [
              _Section<DriveInfo>(
                title: 'Drives',
                future: _drives,
                empty: 'No drives yet',
                rows: (list) => [for (final d in list) _driveRow(d)],
                onShowAll: (list) => _push(_ListPage(
                    title: 'Drives',
                    children: [for (final d in list) _driveRow(d)])),
              ),
              _Section<_Recent>(
                title: 'Recents',
                future: _recents,
                empty: 'Nothing opened yet',
                rows: (list) => [for (final r in list) _recentRow(r)],
                onShowAll: (list) =>
                    _push(_ListPage(title: 'Recents', children: [
                  for (final r in list.take(_maxRecents)) _recentRow(r),
                ])),
              ),
              _Section<ActivityEntry>(
                title: 'Activity',
                future: _activity,
                empty: 'No activity yet',
                rows: (list) => [for (final a in list) _activityRow(a)],
                onShowAll: (list) =>
                    _push(_ListPage(title: 'Activity', children: [
                  for (final a in list.take(_maxActivity)) _activityRow(a),
                ])),
              ),
              _Section<ChatSummary>(
                title: 'AI Chats',
                future: _chats,
                empty: 'No chats yet',
                rows: (list) => [for (final chat in list) _chatRow(chat)],
                onShowAll: (list) =>
                    _push(_ListPage(title: 'AI Chats', children: [
                  for (final (label, group) in groupChatsByAge(list)) ...[
                    _Heading(label, c),
                    for (final chat in group) _chatRow(chat),
                  ],
                ])),
              ),
              _Section<RecentResource>(
                title: 'Favorites',
                future: _favorites,
                empty: 'No favorites yet',
                hideEmpty: true,
                rows: (list) => [for (final r in list) _homeRow(r)],
                onShowAll: (list) => _push(_ListPage(
                    title: 'Favorites',
                    children: [for (final r in list) _homeRow(r)])),
              ),
              _Section<RecentResource>(
                title: 'Messages',
                future: _conversations,
                empty: 'No messages yet',
                hideEmpty: true,
                rows: (list) => [for (final r in list) _homeRow(r)],
                onShowAll: (list) => _push(_ListPage(
                    title: 'Messages',
                    children: [for (final r in list) _homeRow(r)])),
              ),
            ],
          ),
        );
      },
    );
  }
}

/// The current drive; tapping it lets you pick another.

ResourceRow _resourceRow(RecentResource r,
        void Function(String drive, RecentResource) onOpen, String drive) =>
    ResourceRow(
      icon: Icons.description_outlined,
      title: r.title.isEmpty ? r.subject : r.title,
      detail: [r.className, if (r.openedAt > 0) timeAgo(r.openedAt)]
          .where((t) => t.isNotEmpty)
          .join(' · '),
      onTap: () => onOpen(drive, r),
    );

/// One home section: a header with "Show all" (only when there are more than
/// [_homeItems]), the first few rows, and the loading, error or empty state
/// while there is nothing to list.
class _Section<T> extends StatelessWidget {
  final String title;
  final Future<List<T>> future;
  final String empty;
  final List<Widget> Function(List<T>) rows;
  final void Function(List<T>) onShowAll;

  /// Show nothing at all (no heading) while there is nothing to list, and
  /// when the data cannot be read.
  final bool hideEmpty;

  const _Section({
    required this.title,
    required this.future,
    required this.empty,
    required this.rows,
    required this.onShowAll,
    this.hideEmpty = false,
  });

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return FutureBuilder<List<T>>(
      future: future,
      builder: (context, snapshot) {
        final list = snapshot.data;
        if (hideEmpty && (snapshot.hasError || (list?.isEmpty ?? false))) {
          return const SizedBox.shrink();
        }
        final more = list != null && list.length > _homeItems;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Expanded(child: _Heading(title, c)),
              // Same size, weight and padding as the heading, so the two sit on
              // one baseline.
              if (more)
                InkWell(
                  onTap: () => onShowAll(list),
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
            if (snapshot.hasError)
              Padding(
                padding: const EdgeInsets.all(16),
                child:
                    Text('${snapshot.error}', style: TextStyle(color: c.alert)),
              )
            else if (list == null)
              const Padding(
                padding: EdgeInsets.all(16),
                child: Center(child: CircularProgressIndicator()),
              )
            else if (list.isEmpty)
              _Empty(empty, c)
            else
              ...rows(list.take(_homeItems).toList()),
          ],
        );
      },
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
      appBar: AppBar(backgroundColor: c.bgBody, title: Text(title)),
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

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.all(32),
        child:
            Center(child: Text(text, style: TextStyle(color: c.textSecondary))),
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
