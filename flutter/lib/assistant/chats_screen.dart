import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../atomic/widgets/agent_settings_dialog.dart';
import '../theme.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'resource_row.dart';
import 'resource_web_view.dart';
import 'search_screen.dart';

/// Home screen: one page per drive, swiped sideways. Each page is a search
/// field, the drive's recent AI chats and the resources opened lately. The
/// neighbouring pages are built ahead so a swipe lands on a filled page.
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
  PageController? _pages;
  int _page = 0;

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

  Future<void> _settings() async {
    final signedOut = await AgentSettingsDialog.show(context);
    if (signedOut) {
      widget.onSignOut?.call();
    } else {
      setState(() {
        _drives = _loadDrives();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return FutureBuilder<List<DriveInfo>>(
      future: _drives,
      builder: (context, snapshot) {
        final drives = snapshot.data;
        final title = drives == null || drives.isEmpty
            ? 'Chats'
            : drives[_page.clamp(0, drives.length - 1)].name;
        return Scaffold(
          backgroundColor: c.bgBody,
          appBar: AppBar(
            backgroundColor: c.bgBody,
            title: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(title.isEmpty ? 'Chats' : title),
                if (drives != null && drives.length > 1)
                  _Dots(count: drives.length, current: _page),
              ],
            ),
            actions: [
              IconButton(
                tooltip: 'Canvases',
                icon: const Icon(Icons.draw_outlined),
                onPressed: widget.onOpenGallery,
              ),
              IconButton(
                tooltip: 'Settings',
                icon: const Icon(Icons.settings_outlined),
                onPressed: _settings,
              ),
            ],
          ),
          body: snapshot.hasError
              ? Center(
                  child: Text('${snapshot.error}',
                      style: TextStyle(color: c.alert)),
                )
              : drives == null
                  ? const Center(child: CircularProgressIndicator())
                  : PageView.builder(
                      controller: _pages,
                      allowImplicitScrolling: true,
                      itemCount: drives.length,
                      onPageChanged: (i) => setState(() => _page = i),
                      itemBuilder: (_, i) => _DrivePage(
                        key: ValueKey(drives[i].subject),
                        api: widget.api,
                        drive: drives[i].subject,
                      ),
                    ),
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

typedef _Lists = (List<ChatSummary>, List<RecentResource>);

/// One drive: search, recent chats, recently opened resources. Kept alive so
/// a page swiped away and back is not read again.
class _DrivePage extends StatefulWidget {
  final AssistantApi api;
  final String drive;

  const _DrivePage({super.key, required this.api, required this.drive});

  @override
  State<_DrivePage> createState() => _DrivePageState();
}

class _DrivePageState extends State<_DrivePage>
    with AutomaticKeepAliveClientMixin {
  late Future<_Lists> _lists = _load();

  @override
  bool get wantKeepAlive => true;

  Future<_Lists> _load() async {
    final (chats, recent) = await (
      widget.api.chats(widget.drive),
      widget.api.recentResources(widget.drive),
    ).wait;
    return (chats, recent);
  }

  Future<void> _reload() async {
    final next = _load();
    setState(() => _lists = next);
    await next.catchError((_) => (<ChatSummary>[], <RecentResource>[]));
  }

  Future<void> _push(Widget screen) async {
    await Navigator.of(context)
        .push(MaterialPageRoute<void>(builder: (_) => screen));
    if (mounted) await _reload();
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final c = context.appColors;
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 4, 16, 8),
          child: TextField(
            readOnly: true,
            decoration: InputDecoration(
              hintText: 'Search',
              prefixIcon: const Icon(Icons.search),
              filled: true,
              fillColor: c.bg1,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(9),
                borderSide: BorderSide.none,
              ),
            ),
            onTap: () =>
                _push(SearchScreen(drive: widget.drive, api: widget.api)),
          ),
        ),
        Expanded(
          child: FutureBuilder<_Lists>(
            future: _lists,
            builder: (context, snapshot) {
              if (snapshot.hasError) {
                return Center(
                  child: Text('${snapshot.error}',
                      style: TextStyle(color: c.alert)),
                );
              }
              final lists = snapshot.data;
              if (lists == null) {
                return const Center(child: CircularProgressIndicator());
              }
              final (chats, recent) = lists;
              return RefreshIndicator(
                onRefresh: _reload,
                child: ListView(
                  children: [
                    _Heading('Recent chats', c),
                    if (chats.isEmpty) _Empty('No chats yet', c),
                    for (final chat in chats)
                      ResourceRow(
                        icon: Icons.chat_bubble_outline,
                        title: chat.name.isEmpty ? 'Untitled chat' : chat.name,
                        detail: chat.lastActivity == 0
                            ? null
                            : timeAgo(chat.lastActivity),
                        onTap: () => _push(ChatScreen(
                          api: widget.api,
                          subject: chat.subject,
                          title: chat.name,
                        )),
                      ),
                    if (recent.isNotEmpty) _Heading('Recently opened', c),
                    for (final r in recent)
                      ResourceRow(
                        icon: Icons.description_outlined,
                        title: r.title.isEmpty ? r.subject : r.title,
                        detail: [r.className, timeAgo(r.openedAt)]
                            .where((t) => t.isNotEmpty)
                            .join(' · '),
                        onTap: () {
                          widget.api.noteOpened(widget.drive, r.subject);
                          _push(ResourceWebView(
                            api: widget.api,
                            subject: r.subject,
                            title: r.title,
                          ));
                        },
                      ),
                  ],
                ),
              );
            },
          ),
        ),
      ],
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
