import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../theme.dart';
import 'assistant_api.dart';
import 'fading_text.dart';
import 'hosted_ai.dart';
import 'resource_row.dart';

/// A resource the person attached to a new chat as context.
typedef _Attached = ({String subject, String title, String className});

/// Most characters of one attached resource, and of all of them, sent to the AI.
const _maxItemChars = 4000;
const _maxContextChars = 12000;

/// Most recently opened resources offered in the picker.
const _maxRecent = 6;

/// A chat: the text of each message, newest at the bottom, and, when an AI is
/// available, a field to write to it. A chat without a [subject] is new: it is
/// created with the first message.
class ChatScreen extends StatefulWidget {
  final AssistantApi api;
  final String? subject;
  final String title;

  const ChatScreen({
    super.key,
    required this.api,
    this.subject,
    this.title = '',
  });

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _input = TextEditingController();
  final _focus = FocusNode();
  String? _chat;
  List<ChatMessage> _messages = const [];
  Object? _loadError;
  bool _loaded = false;

  /// The AI of the linked account, once looked up; null when there is none.
  HostedAi? _ai;
  bool _aiLooked = false;

  /// The answer as it streams in, in the pieces it came in.
  List<(String, DateTime)>? _partial;
  bool _sending = false;
  String? _error;

  /// What the person attached, in the order they picked it; sent to the AI
  /// with every message of this screen, never stored in the chat.
  final List<_Attached> _attached = [];
  final Map<String, String> _attachedText = {};

  /// What the picker offers, once read.
  List<DriveInfo>? _drives;
  List<(String drive, RecentResource)>? _recent;
  bool _pickerRead = false;

  @override
  void initState() {
    super.initState();
    _chat = widget.subject;
    _readMessages();
    _lookUpAi();
    if (_chat == null) _readPicker();
  }

  @override
  void dispose() {
    _focus.dispose();
    _input.dispose();
    super.dispose();
  }

  Future<void> _readMessages() async {
    final chat = _chat;
    if (chat == null) {
      setState(() => _loaded = true);
      return;
    }
    try {
      final messages = await widget.api.messages(chat);
      if (mounted) {
        setState(() {
          _messages = messages;
          _loaded = true;
          _loadError = null;
        });
        if (messages.isEmpty) _readPicker();
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _loadError = e;
          _loaded = true;
        });
      }
    }
  }

  /// A new chat is for writing: the field gets the cursor as soon as it can.
  void _focusInput() {
    if (widget.subject != null) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && _ai != null && _ai!.available && _ai!.consent) {
        _focus.requestFocus();
      }
    });
  }

  /// The drives and the recently opened resources of all of them, newest
  /// first, for the picker.
  Future<void> _readPicker() async {
    if (_pickerRead) return;
    _pickerRead = true;
    List<DriveInfo> drives;
    try {
      drives = await widget.api.drives();
    } catch (_) {
      drives = const [];
    }
    final lists = await Future.wait([
      for (final d in drives)
        widget.api.recentResources(d.subject).then(
              (list) => [for (final r in list) (d.subject, r)],
              onError: (Object _) => <(String, RecentResource)>[],
            ),
    ]);
    final recent = [for (final l in lists) ...l]
      ..sort((a, b) => b.$2.openedAt.compareTo(a.$2.openedAt));
    if (mounted) {
      setState(() {
        _drives = drives;
        _recent = recent.take(_maxRecent).toList();
      });
    }
  }

  void _toggle(_Attached item) {
    setState(() {
      final at = _attached.indexWhere((a) => a.subject == item.subject);
      if (at >= 0) {
        _attached.removeAt(at);
      } else {
        _attached.add(item);
      }
    });
  }

  /// The text of what was attached, to go ahead of the history; null when
  /// nothing was.
  Future<String?> _contextText() async {
    if (_attached.isEmpty) return null;
    final parts = <String>[];
    for (final a in List.of(_attached)) {
      var text = _attachedText[a.subject];
      if (text == null) {
        try {
          text =
              await widget.api.resourceText(a.subject, maxChars: _maxItemChars);
        } catch (_) {
          continue;
        }
        _attachedText[a.subject] = text;
      }
      if (text.length > _maxItemChars) text = text.substring(0, _maxItemChars);
      parts.add('${a.title} (${a.className})\n$text');
    }
    if (parts.isEmpty) return null;
    final all = 'The user attached these resources as context:\n\n'
        '${parts.join('\n\n')}';
    return all.length > _maxContextChars
        ? all.substring(0, _maxContextChars)
        : all;
  }

  Future<void> _lookUpAi() async {
    try {
      final ai = await widget.api.hostedAi();
      if (mounted) {
        setState(() {
          _ai = ai;
          _aiLooked = true;
        });
        _focusInput();
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _aiLooked = true;
          _error = '$e';
        });
      }
    }
  }

  Future<void> _enableAi() async {
    try {
      await _ai!.enable();
      if (mounted) {
        setState(() => _error = null);
        _focusInput();
      }
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    }
  }

  Future<void> _send() async {
    final text = _input.text.trim();
    final ai = _ai;
    if (text.isEmpty || ai == null || _sending) return;
    _input.clear();
    final asked = [
      ..._messages,
      (id: 'new', role: 'user', text: text, createdAt: 0),
    ];
    setState(() {
      _sending = true;
      _error = null;
      _messages = asked;
      _partial = [];
    });
    try {
      // The chat exists from the first message on, named after it.
      final chat = _chat ??= await widget.api.newChat(
        text.length > 40 ? '${text.substring(0, 40)}…' : text,
      );
      await widget.api.addMessage(chat, 'user', text);
      var answer = '';
      final context = await _contextText();
      await for (final delta in ai.answer(asked, context: context)) {
        answer += delta;
        if (mounted) {
          setState(() => _partial = [..._partial!, (delta, DateTime.now())]);
        }
      }
      if (answer.trim().isNotEmpty) {
        await widget.api.addMessage(chat, 'assistant', answer);
      }
      await _readMessages();
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) {
        setState(() {
          _sending = false;
          _partial = null;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppBar(
        backgroundColor: c.bgBody,
        title: Text(
          widget.title.isEmpty
              ? (_chat == null ? 'New chat' : 'Untitled chat')
              : widget.title,
        ),
      ),
      body: Column(
        children: [
          Expanded(child: _list(c)),
          _composer(c),
        ],
      ),
    );
  }

  Widget _list(AppColors c) {
    if (_loadError != null) {
      return Center(
        child: Text('$_loadError', style: TextStyle(color: c.alert)),
      );
    }
    if (!_loaded) return const Center(child: CircularProgressIndicator());
    final shown = [
      ..._messages,
      if (_partial != null)
        (id: 'partial', role: 'assistant', text: '', createdAt: 0),
    ];
    if (shown.isEmpty) return _picker(c);
    return ListView.builder(
      reverse: true,
      padding: const EdgeInsets.all(16),
      itemCount: shown.length,
      itemBuilder: (context, i) {
        final m = shown[shown.length - 1 - i];
        final mine = m.role == 'user';
        return Align(
          alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
          child: Container(
            margin: const EdgeInsets.symmetric(vertical: 4),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            constraints: BoxConstraints(
              maxWidth: MediaQuery.of(context).size.width * 0.85,
            ),
            decoration: BoxDecoration(
              color: mine ? c.mainSelectedBg : c.bg1,
              borderRadius: BorderRadius.circular(9),
            ),
            child: m.id == 'partial'
                ? (_partial!.isEmpty
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : FadingText(
                        chunks: _partial!,
                        style: TextStyle(color: c.textPrimary),
                      ))
                : SelectableText(
                    m.text,
                    style: TextStyle(
                      color: mine ? c.mainSelectedFg : c.textPrimary,
                    ),
                  ),
          ),
        );
      },
    );
  }

  Widget _heading(AppColors c, String text) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
        child: Text(
          text,
          style: TextStyle(
            color: c.textSecondary,
            fontSize: 13,
            fontWeight: FontWeight.w600,
          ),
        ),
      );

  Widget _pickRow(
    AppColors c, {
    required IconData icon,
    required String title,
    required String className,
    required String subject,
    String? detail,
  }) {
    final item = (subject: subject, title: title, className: className);
    final on = _attached.any((a) => a.subject == subject);
    return ResourceRow(
      icon: icon,
      title: title,
      detail: detail,
      trailing: on ? Icon(Icons.check, color: c.main) : null,
      onTap: () => _toggle(item),
    );
  }

  /// What a new chat shows instead of messages: resources to give the AI as
  /// context. Optional; the chat starts without if nothing is picked.
  Widget _picker(AppColors c) {
    final drives = _drives ?? const <DriveInfo>[];
    final recent = _recent ?? const <(String, RecentResource)>[];
    return ListView(
      children: [
        _heading(c, 'Add context'),
        if (drives.isNotEmpty) ...[
          _heading(c, 'Drives'),
          for (final d in drives)
            _pickRow(
              c,
              icon: Icons.folder_outlined,
              title: d.name.isEmpty ? 'Untitled drive' : d.name,
              className: 'Drive',
              subject: d.subject,
            ),
        ],
        if (recent.isNotEmpty) ...[
          _heading(c, 'Recent'),
          for (final (_, r) in recent)
            _pickRow(
              c,
              icon: Icons.history,
              title: r.title.isEmpty ? 'Untitled' : r.title,
              className: r.className,
              subject: r.subject,
              detail: r.className,
            ),
        ],
      ],
    );
  }

  /// The attached resources, each removable.
  Widget _chips() => Align(
        alignment: Alignment.centerLeft,
        child: Padding(
          padding: const EdgeInsets.only(bottom: 6),
          child: Wrap(
            spacing: 6,
            runSpacing: 4,
            children: [
              for (final a in _attached)
                Chip(
                  label: Text(a.title, overflow: TextOverflow.ellipsis),
                  visualDensity: VisualDensity.compact,
                  onDeleted: () => _toggle(a),
                  deleteButtonTooltipMessage: 'Remove ${a.title}',
                ),
            ],
          ),
        ),
      );

  /// The way to write, when there is an AI to write to; otherwise one line
  /// saying so.
  Widget _composer(AppColors c) {
    final ai = _ai;
    Widget hint(String text) => Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
          child: Text(
            text,
            style: TextStyle(color: c.textSecondary, fontSize: 13),
            textAlign: TextAlign.center,
          ),
        );
    // While the AI is looked up, the field is there already, switched off:
    // the messages above stay where they are when the answer lands.
    if (_aiLooked && ai == null) {
      return SafeArea(child: hint(_error ?? 'No AI is set up on this device.'));
    }
    if (ai != null && !ai.available) {
      return SafeArea(child: hint('Included AI is not available.'));
    }
    if (ai != null && !ai.consent) {
      return SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Messages you send here are processed by your account '
                "provider's AI, and use your account's credits.",
                style: TextStyle(color: c.textSecondary, fontSize: 13),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              FilledButton(
                onPressed: _enableAi,
                child: const Text('Turn on AI'),
              ),
              if (_error != null)
                Text(_error!, style: TextStyle(color: c.alert, fontSize: 12)),
            ],
          ),
        ),
      );
    }
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 4, 12, 12),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Text(
                  _error!,
                  style: TextStyle(color: c.alert, fontSize: 12),
                ),
              ),
            if (_attached.isNotEmpty) _chips(),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _input,
                    focusNode: _focus,
                    minLines: 1,
                    maxLines: 5,
                    textInputAction: TextInputAction.send,
                    // Stays enabled while a reply streams (`_send` ignores a
                    // second send), and submitting keeps focus: the keyboard
                    // stays open for the next message.
                    enabled: ai != null,
                    onEditingComplete: () {},
                    onSubmitted: (_) => _send(),
                    decoration: InputDecoration(
                      hintText: 'Message',
                      filled: true,
                      fillColor: c.bg1,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(9),
                        borderSide: BorderSide.none,
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  tooltip: 'Send',
                  onPressed: _sending || ai == null ? null : _send,
                  icon: const Icon(Icons.arrow_upward),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
