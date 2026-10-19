import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../theme.dart';
import 'assistant_api.dart';
import 'hosted_ai.dart';

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
  String? _chat;
  List<ChatMessage> _messages = const [];
  Object? _loadError;
  bool _loaded = false;

  /// The AI of the linked account, once looked up; null when there is none.
  HostedAi? _ai;
  bool _aiLooked = false;

  /// The answer as it streams in.
  String? _partial;
  bool _sending = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _chat = widget.subject;
    _readMessages();
    _lookUpAi();
  }

  @override
  void dispose() {
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

  Future<void> _lookUpAi() async {
    try {
      final ai = await widget.api.hostedAi();
      if (mounted) {
        setState(() {
          _ai = ai;
          _aiLooked = true;
        });
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
      if (mounted) setState(() => _error = null);
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
      _partial = '';
    });
    try {
      // The chat exists from the first message on, named after it.
      final chat = _chat ??= await widget.api.newChat(
        text.length > 40 ? '${text.substring(0, 40)}…' : text,
      );
      await widget.api.addMessage(chat, 'user', text);
      var answer = '';
      await for (final delta in ai.answer(asked)) {
        answer += delta;
        if (mounted) setState(() => _partial = answer);
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
        (id: 'partial', role: 'assistant', text: _partial!, createdAt: 0),
    ];
    if (shown.isEmpty) {
      return Center(
        child: Text('No messages', style: TextStyle(color: c.textSecondary)),
      );
    }
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
            child: m.text.isEmpty
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
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
    if (!_aiLooked) return const SizedBox(height: 8);
    if (ai == null) {
      return SafeArea(child: hint(_error ?? 'No AI is set up on this device.'));
    }
    if (!ai.available) {
      return SafeArea(child: hint('Included AI is not available.'));
    }
    if (!ai.consent) {
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
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _input,
                    minLines: 1,
                    maxLines: 5,
                    textInputAction: TextInputAction.send,
                    enabled: !_sending,
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
                  onPressed: _sending ? null : _send,
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
