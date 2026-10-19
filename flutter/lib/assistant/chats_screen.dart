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
const _homeChats = 5;

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
    await Navigator.of(
      context,
    ).push(MaterialPageRoute<void>(builder: (_) => screen));
    if (mounted) _reload();
  }

  Future<void> _settings() async {
    final signedOut =
        await Navigator.of(context).push<bool>(
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
                  child: Text(
                    '${snapshot.error}',
                    style: TextStyle(color: c.alert),
                  ),
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
                        onTap: () => _push(
                          SearchScreen(drive: drive.subject, api: widget.api),
                        ),
                      ),
                    ),
                    _ChatsSection(
                      chats: _chats,
                      onOpen: (chat) => _push(
                        ChatScreen(
                          api: widget.api,
                          subject: chat?.subject,
                          title: chat?.name ?? '',
                        ),
                      ),
                    ),
                    if (drives.length > 1)
                      _Dots(count: drives.length, current: _page),
                    Expanded(
                      child: PageView.builder(
                        controller: _pages,
                        allowImplicitScrolling: true,
                        itemCount: drives.length,
                        onPageChanged: (i) => setState(() => _page = i),
                        itemBuilder: (_, i) => _OpenedPage(
                          key: ValueKey(drives[i].subject),
                          api: widget.api,
                          drive: drives[i].subject,
                          generation: _generation,
                          onOpen: _push,
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
            _Heading('Recent chats', c),
            ResourceRow(
              icon: Icons.add,
              title: 'New chat',
              onTap: () => onOpen(null),
            ),
            if (snapshot.hasError)
              Padding(
                padding: const EdgeInsets.all(16),
                child: Text(
                  '${snapshot.error}',
                  style: TextStyle(color: c.alert),
                ),
              )
            else if (list == null)
              const Padding(
                padding: EdgeInsets.all(16),
                child: Center(child: CircularProgressIndicator()),
              )
            else if (list.isEmpty)
              _Empty('No chats yet', c)
            else
              for (final (i, chat) in list.take(_homeChats).indexed) ...[
                // A group's label goes above its first chat only, so a group
                // without chats has no label.
                if (i == 0 ||
                    chatGroup(chat.lastActivity) !=
                        chatGroup(list[i - 1].lastActivity))
                  _GroupLabel(chatGroup(chat.lastActivity), c),
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
        child: Text(
          '${current + 1} / $count',
          style: TextStyle(color: c.textSecondary, fontSize: 12),
        ),
      );
    }
    return Padding(
      padding: const EdgeInsets.only(top: 4),
      child: Row(
        mainAxisSize: MainAxisSize.min,
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
  final int generation;
  final Future<void> Function(Widget) onOpen;

  const _OpenedPage({
    super.key,
    required this.api,
    required this.drive,
    required this.generation,
    required this.onOpen,
  });

  @override
  State<_OpenedPage> createState() => _OpenedPageState();
}

class _OpenedPageState extends State<_OpenedPage>
    with AutomaticKeepAliveClientMixin {
  late Future<List<RecentResource>> _recent = widget.api.recentResources(
    widget.drive,
  );

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
            _Heading('Recently opened', c),
            if (recent.isEmpty) _Empty('Nothing opened yet', c),
            for (final r in recent)
              ResourceRow(
                icon: Icons.description_outlined,
                title: r.title.isEmpty ? r.subject : r.title,
                detail: [
                  r.className,
                  timeAgo(r.openedAt),
                ].where((t) => t.isNotEmpty).join(' · '),
                onTap: () {
                  widget.api.noteOpened(widget.drive, r.subject);
                  widget.onOpen(
                    ResourceWebView(
                      api: widget.api,
                      subject: r.subject,
                      title: r.title,
                    ),
                  );
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
    child: Text(
      text,
      style: TextStyle(
        color: c.textSecondary,
        fontSize: 13,
        fontWeight: FontWeight.w600,
      ),
    ),
  );
}

/// The small label over a group of chats: "Today", "This week", ...
class _GroupLabel extends StatelessWidget {
  final String text;
  final AppColors c;

  const _GroupLabel(this.text, this.c);

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
    child: Text(text, style: TextStyle(color: c.textSecondary, fontSize: 11)),
  );
}

class _Empty extends StatelessWidget {
  final String text;
  final AppColors c;

  const _Empty(this.text, this.c);

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.all(32),
    child: Center(
      child: Text(text, style: TextStyle(color: c.textSecondary)),
    ),
  );
}

/// The group a chat last active at [ms] falls in, by the local calendar day:
/// "Today", "Yesterday", "This week" (the last seven days), "This month",
/// "Earlier".
String chatGroup(int ms, {DateTime? now}) {
  if (ms <= 0) return 'Earlier';
  // Compared as UTC dates, so a daylight-saving change cannot make a day 23 h.
  DateTime civil(DateTime t) => DateTime.utc(t.year, t.month, t.day);
  final days = civil(
    now ?? DateTime.now(),
  ).difference(civil(DateTime.fromMillisecondsSinceEpoch(ms))).inDays;
  if (days <= 0) return 'Today';
  if (days == 1) return 'Yesterday';
  if (days < 7) return 'This week';
  if (days < 30) return 'This month';
  return 'Earlier';
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
