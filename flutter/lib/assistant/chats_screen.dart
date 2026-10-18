import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../atomic/widgets/agent_settings_dialog.dart';
import '../theme.dart';
import 'assistant_api.dart';
import 'chat_screen.dart';
import 'search_screen.dart';

/// Home screen: the drive's AI chats, a search field and the way to the canvas
/// gallery.
class ChatsScreen extends StatefulWidget {
  final AssistantApi api;
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
  late Future<List<ChatSummary>> _chats = widget.api.chats(widget.drive);

  Future<void> _reload() async {
    final next = widget.api.chats(widget.drive);
    setState(() => _chats = next);
    await next.catchError((_) => <ChatSummary>[]);
  }

  void _push(Widget screen) => Navigator.of(context)
      .push(MaterialPageRoute<void>(builder: (_) => screen));

  Future<void> _settings() async {
    final signedOut = await AgentSettingsDialog.show(context);
    if (signedOut) {
      widget.onSignOut?.call();
    } else {
      await _reload();
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
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
            tooltip: 'Settings',
            icon: const Icon(Icons.settings_outlined),
            onPressed: _settings,
          ),
        ],
      ),
      body: Column(
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
            child: FutureBuilder<List<ChatSummary>>(
              future: _chats,
              builder: (context, snapshot) {
                if (snapshot.hasError) {
                  return Center(
                    child: Text('${snapshot.error}',
                        style: TextStyle(color: c.alert)),
                  );
                }
                final chats = snapshot.data;
                if (chats == null) {
                  return const Center(child: CircularProgressIndicator());
                }
                return RefreshIndicator(
                  onRefresh: _reload,
                  child: chats.isEmpty
                      ? ListView(children: [
                          Padding(
                            padding: const EdgeInsets.all(32),
                            child: Center(
                              child: Text('No chats yet',
                                  style: TextStyle(color: c.textSecondary)),
                            ),
                          ),
                        ])
                      : ListView.builder(
                          itemCount: chats.length,
                          itemBuilder: (context, i) {
                            final chat = chats[i];
                            return ListTile(
                              leading: Icon(Icons.chat_bubble_outline,
                                  color: c.main),
                              title: Text(
                                chat.name.isEmpty ? 'Untitled chat' : chat.name,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
                              subtitle: chat.lastActivity == 0
                                  ? null
                                  : Text(timeAgo(chat.lastActivity)),
                              onTap: () => _push(ChatScreen(
                                api: widget.api,
                                subject: chat.subject,
                                title: chat.name,
                              )),
                            );
                          },
                        ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
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
