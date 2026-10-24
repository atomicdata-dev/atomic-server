import 'package:atomic_flutter/atomic_flutter.dart' show ErrorText;
import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt, Perf;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart' show ScrollCacheExtent;
import 'app_top_bar.dart';
import 'home_sections.dart' show HomeSection;
import 'chat_bubbles.dart';
import 'chat_text_styles.dart';
import 'chat_window.dart';
import 'scroll_to_bottom_button.dart';

import 'models.dart';
import 'assistant_api.dart';
import 'list_and_field.dart';
import 'resource_chrome.dart';

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

  /// The drive the conversation is in, for the breadcrumbs.
  final String drive;

  /// The other members' names, from the Messages row.
  final String title;

  const ConversationScreen({
    super.key,
    required this.api,
    this.drive = '',
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

  /// The window of the conversation on screen: the newest messages, older
  /// ones read as the list scrolls up (see [ChatWindow]).
  late final ChatWindow<ConversationMessage> _window = ChatWindow(
    readPage: (before, limit) => widget.api
        .conversationMessagesPage(widget.subject, before: before, limit: limit),
    readAfter: (after, limit) => widget.api
        .conversationMessagesAfter(widget.subject, after, limit: limit),
    idOf: (m) => m.id,
    onOlderPage: (ms, n) => Perf.span('chat older page $n', ms),
  );
  late final _scroll = ChatScrollKeeper(_window);
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
    _window.addListener(_windowChanged);
    unawaited(_window.open());
    _timer = Timer.periodic(conversationRefresh, (_) => _tick());
    widget.api.storeChanges?.addListener(_tick);
  }

  @override
  void dispose() {
    _timer?.cancel();
    widget.api.storeChanges?.removeListener(_tick);
    _window.removeListener(_windowChanged);
    _window.dispose();
    _scroll.dispose();
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

  void _windowChanged() {
    if (mounted) setState(() {});
  }

  String? _prevNewest;
  String? _enterId;

  /// What arrived since the newest message read; shown at once when at the
  /// bottom, otherwise counted on the "Jump to latest" button.
  Future<void> _read() async {
    if (_reading) return;
    _reading = true;
    try {
      if (!_window.loaded) {
        await _window.open();
      } else {
        await _window.poll(atBottom: _scroll.atBottom);
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
    // Your own message animates to the bottom.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _scroll.nudgeToBottom();
    });
    _sends = _sends.then((_) async {
      try {
        await widget.api.sendConversationMessage(widget.subject, text);
        await _read();
        // Your own message shows where you are writing: at the bottom.
        if (_window.unseen > 0 || _window.detached) {
          await _scroll.jumpToLatest();
        }
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
    return ChatTextScope(
        child: SectionBack(
            section: HomeSection.messages,
            child: ResourceMenuScope(
              api: widget.api,
              subject: widget.subject,
              child: Scaffold(
                backgroundColor: c.bgBody,
                appBar: AppTopBar(
                  compact: true,
                  title: widget.title.isEmpty ? 'Conversation' : widget.title,
                  titleWidget: ChatHeader(
                    title: widget.title.isEmpty ? 'Conversation' : widget.title,
                    subtitle: _subtitle,
                  ),
                  bottom: ResourceBreadcrumbs(
                      api: widget.api,
                      drive: widget.drive,
                      subject: widget.subject),
                  actions: const [ResourceMoreButton()],
                ),
                body: ListAndField(
                    fullWidthField: true, list: _list(c), field: _composer(c)),
              ),
            )));
  }

  /// Who is in it: a direct message, or the people seen in a group so far.
  String get _subtitle {
    final others = {
      for (final m in _window.items)
        if (!m.mine) m.author,
    };
    if (others.length > 1) return '${others.length + 1} members';
    return 'Direct message';
  }

  Widget _list(AppColors c) {
    final loadError = _window.error;
    if (loadError != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: ErrorText('$loadError',
              textAlign: TextAlign.center, color: c.alert),
        ),
      );
    }
    if (!_window.loaded) {
      return const Center(child: CircularProgressIndicator());
    }
    final shown = [..._window.items, ..._pending];
    if (shown.isEmpty) {
      return Center(
        child:
            Text('No messages yet', style: ChatTextStyles.of(context).status),
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
    final ids = [for (final m in shown) m.id];
    final at = {for (var i = 0; i < ids.length; i++) ids[i]: i};
    final newest = ids.last;
    if (_prevNewest != null && newest != _prevNewest) {
      final readBack = _prevNewest!.startsWith('pending-') &&
          !newest.startsWith('pending-') &&
          shown.last.mine;
      _enterId = _scroll.atBottom && !readBack ? newest : null;
    }
    _prevNewest = newest;
    final list = LayoutBuilder(
        builder: (context, box) => ListView.builder(
              controller: _scroll.controller,
              reverse: true,
              physics: chatScrollPhysics,
              scrollCacheExtent: const ScrollCacheExtent.viewport(1.5),
              keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
              padding: readableHorizontalPadding(box.maxWidth,
                      gutter: ChatTextStyles.gutter)
                  .copyWith(top: 8, bottom: 8),
              itemCount: shown.length + (_window.hasOlder ? 1 : 0),
              findChildIndexCallback: (key) => reversedIndexOf(key, ids, at),
              itemBuilder: (context, i) {
                if (i == shown.length) {
                  // The top: older messages are being read.
                  return const Padding(
                    padding: EdgeInsets.all(12),
                    child: Center(
                        child: SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2))),
                  );
                }
                _scroll.built(i);
                final index = shown.length - 1 - i;
                final m = shown[index];
                final first = index == 0 || !sameGroup(shown[index - 1], m);
                final last = index == shown.length - 1 ||
                    !sameGroup(m, shown[index + 1]);
                final newDay = index == 0 && !_window.hasOlder ||
                    index > 0 &&
                        otherDay(shown[index - 1].createdAt, m.createdAt);
                final bubble = MessageRow(
                  mine: m.mine,
                  first: first,
                  last: last,
                  name: group && !m.mine && first ? _nameOf(m) : null,
                  avatarOf: m.mine ? null : m.authorName,
                  time: last ? clockTime(m.createdAt) : null,
                  sending: m.id.startsWith('pending-'),
                  listWidth: box.maxWidth -
                      2 *
                          (ChatTextStyles.gutter +
                              readableSideInset(box.maxWidth)),
                  content: _text(c, m),
                );
                return KeyedSubtree(
                  key: ValueKey(m.id),
                  child: RowEntrance(
                    animate: m.id == _enterId,
                    child: newDay
                        ? Column(children: [
                            DaySeparator(dayLabel(m.createdAt),
                                color: c.textSecondary),
                            bubble,
                          ])
                        : bubble,
                  ),
                );
              },
            ));
    final unseen = _window.unseen;
    return Stack(children: [
      list,
      ScrollToBottomButton(keeper: _scroll, unseen: unseen),
    ]);
  }

  String _nameOf(ConversationMessage m) =>
      m.authorName.isEmpty ? 'Unknown member' : m.authorName;

  Widget _text(AppColors c, ConversationMessage m) {
    final styles = ChatTextStyles.of(context);
    return m.text != null
        ? SelectableText(m.text!, style: m.mine ? styles.bodyMine : styles.body)
        : Text(
            "This message can't be opened",
            style: styles.body.copyWith(
              color: m.mine ? ChatTextStyles.onOwnMuted : c.textSecondary,
              fontStyle: FontStyle.italic,
            ),
          );
  }

  Widget _composer(AppColors c) => ChatComposerFrame(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: ErrorText(_error!,
                    color: c.alert, fontSize: ChatTextStyles.metaSize),
              ),
            Row(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Expanded(
                  child: TextField(
                    controller: _input,
                    focusNode: _focus,
                    minLines: 1,
                    maxLines: 5,
                    textCapitalization: TextCapitalization.sentences,
                    textInputAction: TextInputAction.send,
                    onEditingComplete: () {},
                    onSubmitted: (_) => _send(),
                    style: ChatTextStyles.of(context).composer,
                    decoration: chatFieldDecoration(context),
                  ),
                ),
                const SizedBox(width: 8),
                Padding(
                  padding: const EdgeInsets.only(bottom: 2),
                  child: ChatSendButton(onPressed: _hadText ? _send : null),
                ),
              ],
            ),
          ],
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
