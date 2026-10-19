import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../screens/sync_screen.dart';
import '../theme.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'resource_row.dart';
import 'resource_web_view.dart';
import 'search_screen.dart';

/// Chats shown on the home; the rest is one tap away in a chat list later.
const _homeChats = 8;

/// Home screen. AI chats belong to the person, so the search field and the
/// newest chats sit on top whatever drive is showing. Below, one page per
/// drive, swiped sideways, lists the resources opened lately; the search
/// field looks in the drive of the visible page. The neighbouring pages are
/// built ahead so a swipe lands on a filled page.
class ChatsScreen extends StatefulWidget {
  final AssistantApi api;

  /// The drive the home opens on.
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
  late Future<String?> _agentName = widget.api.agentName();
  PageController? _pages;
  int _page = 0;

  /// Bumped when the user comes back from another screen, so the pages read
  /// again.
  int _generation = 0;

  /// The agent's drives; when there are none (not synced yet) just the one
  /// the app opened on.
  Future<List<DriveInfo>> _loadDrives() async {
    var drives = await widget.api.drives();
    if (drives.isEmpty) drives = [(subject: widget.drive, name: '')];
    // A page per drive that has something to show: swiping to an empty one
    // only reads as broken. The drive it opened on always stays.
    final used = await Future.wait([
      for (final d in drives)
        widget.api
            .recentResources(d.subject)
            .then((r) => r.isNotEmpty)
            .catchError((Object _) => false),
    ]);
    drives = [
      for (var i = 0; i < drives.length; i++)
        if (used[i] || drives[i].subject == widget.drive) drives[i],
    ];
    final first = drives.indexWhere((d) => d.subject == widget.drive);
    if (_pages == null) {
      _page = first < 0 ? 0 : first;
      _pages = PageController(initialPage: _page);
    }
    return drives;
  }

  @override
  void dispose() {
    _pages?.dispose();
    super.dispose();
  }

  void _reload() => setState(() {
        _generation++;
        _chats = widget.api.chats();
      });

  Future<void> _push(Widget screen) async {
    await Navigator.of(context)
        .push(MaterialPageRoute<void>(builder: (_) => screen));
    if (mounted) _reload();
  }

  Future<void> _settings() async {
    final signedOut = await Navigator.of(context).push<bool>(
          MaterialPageRoute<bool>(builder: (_) => const SyncScreen()),
        ) ??
        false;
    if (signedOut) {
      widget.onSignOut?.call();
    } else {
      setState(() {
        _drives = _loadDrives();
        _agentName = widget.api.agentName();
      });
      _reload();
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return FutureBuilder<List<DriveInfo>>(
      future: _drives,
      builder: (context, snapshot) {
        final drives = snapshot.data;
        final drive = drives == null || drives.isEmpty
            ? null
            : drives[_page.clamp(0, drives.length - 1)];
        return Scaffold(
          backgroundColor: c.bgBody,
          appBar: AppBar(
            backgroundColor: c.bgBody,
            title: const Text('Chats'),
            actions: [
              IconButton(
                tooltip: 'Canvases',
                icon: const Icon(Icons.draw_outlined),
                onPressed: widget.onOpenGallery,
              ),
              IconButton(
                tooltip: 'Your agent and sync',
                icon: FutureBuilder<String?>(
                  future: _agentName,
                  builder: (_, s) => AgentAvatar(name: s.data),
                ),
                onPressed: _settings,
              ),
            ],
          ),
          body: snapshot.hasError
              ? Center(
                  child: Text('${snapshot.error}',
                      style: TextStyle(color: c.alert)),
                )
              : drives == null || drive == null
                  ? const Center(child: CircularProgressIndicator())
                  : Column(
                      children: [
                        Padding(
                          padding: const EdgeInsets.fromLTRB(16, 4, 16, 8),
                          child: TextField(
                            readOnly: true,
                            decoration: InputDecoration(
                              hintText: drives.length > 1
                                  ? 'Search in ${drive.name}'
                                  : 'Search',
                              prefixIcon: const Icon(Icons.search),
                              filled: true,
                              fillColor: c.bg1,
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(9),
                                borderSide: BorderSide.none,
                              ),
                            ),
                            onTap: () => _push(SearchScreen(
                                drive: drive.subject, api: widget.api)),
                          ),
                        ),
                        // The chats scroll away above the drive pages, so
                        // the pages always get the screen's height to swipe
                        // and scroll in, however many chats there are.
                        Expanded(
                          child: NestedScrollView(
                            headerSliverBuilder: (_, __) => [
                              SliverToBoxAdapter(
                                child: Column(children: [
                                  _ChatsSection(
                                    chats: _chats,
                                    onOpen: (chat) => _push(ChatScreen(
                                      api: widget.api,
                                      subject: chat?.subject,
                                      title: chat?.name ?? '',
                                    )),
                                  ),
                                ]),
                              ),
                            ],
                            body: PageView.builder(
                              controller: _pages,
                              allowImplicitScrolling: true,
                              itemCount: drives.length,
                              onPageChanged: (i) => setState(() => _page = i),
                              itemBuilder: (_, i) => _OpenedPage(
                                key: ValueKey(drives[i].subject),
                                api: widget.api,
                                drive: drives[i].subject,
                                driveName: drives[i].name,
                                index: i,
                                count: drives.length,
                                generation: _generation,
                                onOpen: _push,
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
        );
      },
    );
  }
}

/// The person's newest chats, whatever drive they were started in.
class _ChatsSection extends StatelessWidget {
  final Future<List<ChatSummary>> chats;
  final void Function(ChatSummary?) onOpen;

  const _ChatsSection({required this.chats, required this.onOpen});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return FutureBuilder<List<ChatSummary>>(
      future: chats,
      builder: (context, snapshot) {
        final list = snapshot.data;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            ResourceRow(
              icon: Icons.add,
              title: 'New chat',
              onTap: () => onOpen(null),
            ),
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
              _Empty('No chats yet', c)
            else
              for (final (label, group)
                  in groupChatsByAge(list.take(_homeChats).toList())) ...[
                _Heading(label, c),
                for (final chat in group)
                  ResourceRow(
                    title: chat.name.isEmpty ? 'Untitled chat' : chat.name,
                    onTap: () => onOpen(chat),
                  ),
              ],
          ],
        );
      },
    );
  }
}

class _Dots extends StatelessWidget {
  final int count;
  final int current;

  const _Dots({required this.count, required this.current});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    // Dots only while they fit; with many drives, a count.
    if (count > 8) {
      return Padding(
        padding: const EdgeInsets.only(top: 4),
        child: Center(
          child: Text('${current + 1} / $count',
              style: TextStyle(color: c.textSecondary, fontSize: 12)),
        ),
      );
    }
    return Padding(
      padding: const EdgeInsets.only(top: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          for (var i = 0; i < count; i++)
            Container(
              width: 6,
              height: 6,
              margin: const EdgeInsets.symmetric(horizontal: 2),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: i == current ? c.main : c.border,
              ),
            ),
        ],
      ),
    );
  }
}

/// One drive: the resources opened lately. Kept alive so a page swiped away
/// and back is not read again.
class _OpenedPage extends StatefulWidget {
  final AssistantApi api;
  final String drive;

  /// Which page of how many this is: the heading says which drive, and with
  /// several, shows where in the swipe it is.
  final String driveName;
  final int index;
  final int count;
  final int generation;
  final Future<void> Function(Widget) onOpen;

  const _OpenedPage({
    super.key,
    required this.api,
    required this.drive,
    required this.driveName,
    required this.index,
    required this.count,
    required this.generation,
    required this.onOpen,
  });

  @override
  State<_OpenedPage> createState() => _OpenedPageState();
}

class _OpenedPageState extends State<_OpenedPage>
    with AutomaticKeepAliveClientMixin {
  late Future<List<RecentResource>> _recent =
      widget.api.recentResources(widget.drive);

  @override
  bool get wantKeepAlive => true;

  @override
  void didUpdateWidget(_OpenedPage old) {
    super.didUpdateWidget(old);
    if (old.generation != widget.generation) {
      _recent = widget.api.recentResources(widget.drive);
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final c = context.appColors;
    return FutureBuilder<List<RecentResource>>(
      future: _recent,
      builder: (context, snapshot) {
        if (snapshot.hasError) {
          return Center(
            child: Text('${snapshot.error}', style: TextStyle(color: c.alert)),
          );
        }
        final recent = snapshot.data;
        if (recent == null) {
          return const Center(child: CircularProgressIndicator());
        }
        return ListView(
          children: [
            Row(children: [
              Expanded(
                child: _Heading(
                    widget.count > 1 && widget.driveName.isNotEmpty
                        ? 'Recently opened · ${widget.driveName}'
                        : 'Recently opened',
                    c),
              ),
              if (widget.count > 1)
                Padding(
                  padding: const EdgeInsets.only(right: 16, top: 12),
                  child: _Dots(count: widget.count, current: widget.index),
                ),
            ]),
            if (recent.isEmpty) _Empty('Nothing opened yet', c),
            for (final r in recent)
              ResourceRow(
                icon: Icons.description_outlined,
                title: r.title.isEmpty ? r.subject : r.title,
                detail: [r.className, timeAgo(r.openedAt)]
                    .where((t) => t.isNotEmpty)
                    .join(' · '),
                onTap: () {
                  widget.api.noteOpened(widget.drive, r.subject);
                  widget.onOpen(ResourceWebView(
                    api: widget.api,
                    subject: r.subject,
                    title: r.title,
                  ));
                },
              ),
          ],
        );
      },
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
