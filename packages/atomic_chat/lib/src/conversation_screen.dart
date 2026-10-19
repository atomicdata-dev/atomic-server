import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'app_top_bar.dart';

import 'models.dart';
import 'assistant_api.dart';

/// How often the open conversation is read again for messages that arrived
/// through sync. The read is local (opened messages are cached), so it is cheap.
const conversationRefresh = Duration(seconds: 3);

/// Messages of one author closer together than this are one group: the author
/// is named once above it and the time shown once below it.
const _groupGap = Duration(minutes: 5);

/// A conversation (DM or group chat): the messages as bubbles, mine on the
/// right and the others' on the left, newest at the bottom, and a field to
/// write one. Messages are end-to-end encrypted; they are opened on this
/// device. New ones show up on their own while this screen is on top.
class ConversationScreen extends StatefulWidget {
  final AssistantApi api;
  final String subject;

  /// The other members' names, from the Messages row.
  final String title;

  const ConversationScreen({
    super.key,
    required this.api,
    required this.subject,
    this.title = '',
  });

  @override
  State<ConversationScreen> createState() => _ConversationScreenState();
}

class _ConversationScreenState extends State<ConversationScreen>
    with WidgetsBindingObserver {
  final _input = TextEditingController();
  final _focus = FocusNode();
  List<ConversationMessage> _messages = const [];
  Object? _loadError;
  bool _loaded = false;
  bool _hadText = false;
  bool _foreground = true;
  bool _reading = false;
  Timer? _timer;

  /// Messages being sent, shown at the bottom until they are read back.
  final List<ConversationMessage> _pending = [];
  int _pendingCount = 0;

  /// Sends run one after the other, so messages keep their order.
  Future<void> _sends = Future.value();
  String? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _input.addListener(_inputChanged);
    // Fetch the conversation when this device lacks it, and follow it; with no
    // sync session this fails, and what is local is shown anyway.
    unawaited(widget.api.followConversation(widget.subject).then((_) {
      if (mounted) _read();
    }, onError: (Object _) {}));
    _read();
    _timer = Timer.periodic(conversationRefresh, (_) => _tick());
  }

  @override
  void dispose() {
    _timer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    _input.removeListener(_inputChanged);
    _focus.dispose();
    _input.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _foreground = state == AppLifecycleState.resumed;
    if (_foreground) _read();
  }

  void _inputChanged() {
    final has = _input.text.trim().isNotEmpty;
    if (has != _hadText) setState(() => _hadText = has);
  }

  /// Read again, but only while this is the screen being looked at.
  void _tick() {
    if (!mounted || !_foreground) return;
    if (ModalRoute.of(context)?.isCurrent == false) return;
    _read();
  }

  Future<void> _read() async {
    if (_reading) return;
    _reading = true;
    try {
      final messages = await widget.api.conversationMessages(widget.subject);
      if (!mounted) return;
      final changed = !listEquals(messages, _messages);
      if (changed || !_loaded || _loadError != null) {
        setState(() {
          _messages = messages;
          _loaded = true;
          _loadError = null;
        });
      }
    } catch (e) {
      // A failed refresh keeps what is on screen.
      if (mounted && !_loaded) {
        setState(() {
          _loadError = e;
          _loaded = true;
        });
      }
    } finally {
      _reading = false;
    }
  }

  void _send() {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    _input.clear();
    // Submitting keeps the cursor: the keyboard stays open for the next one.
    _focus.requestFocus();
    final pending = (
      id: 'pending-${_pendingCount++}',
      author: '',
      authorName: '',
      mine: true,
      text: text,
      createdAt: DateTime.now().millisecondsSinceEpoch,
    );
    setState(() {
      _pending.add(pending);
      _error = null;
    });
    _sends = _sends.then((_) async {
      try {
        await widget.api.sendConversationMessage(widget.subject, text);
        await _read();
      } catch (e) {
        if (mounted) {
          setState(() => _error = "Couldn't send: $e");
          if (_input.text.isEmpty) _input.text = text;
        }
      } finally {
        if (mounted) setState(() => _pending.remove(pending));
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppTopBar(
          title: widget.title.isEmpty ? 'Conversation' : widget.title),
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
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text('$_loadError',
              textAlign: TextAlign.center, style: TextStyle(color: c.alert)),
        ),
      );
    }
    if (!_loaded) return const Center(child: CircularProgressIndicator());
    final shown = [..._messages, ..._pending];
    if (shown.isEmpty) {
      return Center(
        child: Text('No messages yet',
            style: TextStyle(color: c.textSecondary, fontSize: 13)),
      );
    }
    // Others' names show when more than one other person has spoken.
    final speakers = {
      for (final m in shown)
        if (!m.mine) m.author,
    };
    final group = speakers.length > 1;
    bool sameGroup(ConversationMessage a, ConversationMessage b) =>
        a.mine == b.mine &&
        a.author == b.author &&
        (b.createdAt - a.createdAt).abs() <= _groupGap.inMilliseconds;
    return ListView.builder(
      reverse: true,
      padding: const EdgeInsets.all(16),
      itemCount: shown.length,
      itemBuilder: (context, i) {
        final index = shown.length - 1 - i;
        final m = shown[index];
        final first = index == 0 || !sameGroup(shown[index - 1], m);
        final last =
            index == shown.length - 1 || !sameGroup(m, shown[index + 1]);
        return _bubble(c, m,
            name: group && !m.mine && first ? _nameOf(m) : null,
            time: last ? messageTime(m.createdAt) : null,
            gapAbove: first);
      },
    );
  }

  String _nameOf(ConversationMessage m) =>
      m.authorName.isEmpty ? 'Unknown member' : m.authorName;

  Widget _bubble(AppColors c, ConversationMessage m,
      {String? name, String? time, required bool gapAbove}) {
    final mine = m.mine;
    final readable = m.text != null;
    return Align(
      alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: EdgeInsets.only(top: gapAbove ? 8 : 2, bottom: 2),
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.85,
        ),
        child: Column(
          crossAxisAlignment:
              mine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: [
            if (name != null)
              Padding(
                padding: const EdgeInsets.only(left: 4, bottom: 2),
                child: Text(name,
                    key: const Key('message-author'),
                    style: TextStyle(color: c.textSecondary, fontSize: 12)),
              ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                color: mine ? c.mainSelectedBg : c.bg1,
                borderRadius: BorderRadius.circular(9),
              ),
              child: readable
                  ? SelectableText(
                      m.text!,
                      style: TextStyle(
                        color: mine ? c.mainSelectedFg : c.textPrimary,
                      ),
                    )
                  : Text(
                      "This message can't be opened",
                      style: TextStyle(
                        color: c.textSecondary,
                        fontStyle: FontStyle.italic,
                      ),
                    ),
            ),
            if (time != null)
              Padding(
                padding: const EdgeInsets.only(top: 2, left: 4, right: 4),
                child: Text(time,
                    key: const Key('message-time'),
                    style: TextStyle(color: c.textSecondary, fontSize: 11)),
              ),
          ],
        ),
      ),
    );
  }

  Widget _composer(AppColors c) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(12, 4, 12, 12),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Text(_error!,
                      style: TextStyle(color: c.alert, fontSize: 12)),
                ),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _input,
                      focusNode: _focus,
                      minLines: 1,
                      maxLines: 5,
                      textInputAction: TextInputAction.send,
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
                  IconButton.filled(
                    tooltip: 'Send',
                    onPressed: _hadText ? _send : null,
                    icon: const Icon(Icons.arrow_upward),
                  ),
                ],
              ),
            ],
          ),
        ),
      );
}

const _months = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
];

/// "14:05" for today, "3 Oct 14:05" for another day this year, with the year
/// for an older one.
String messageTime(int ms, {DateTime? now}) {
  final at = DateTime.fromMillisecondsSinceEpoch(ms);
  final today = now ?? DateTime.now();
  String two(int n) => n.toString().padLeft(2, '0');
  final clock = '${two(at.hour)}:${two(at.minute)}';
  if (at.year == today.year && at.month == today.month && at.day == today.day) {
    return clock;
  }
  final date = '${at.day} ${_months[at.month - 1]}';
  return at.year == today.year ? '$date $clock' : '$date ${at.year} $clock';
}
