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
import 'assistant_api.dart';
import 'conversation_screen.dart' show conversationRefresh, messageTime;
import 'models.dart';
import 'native_views.dart';
import 'slide_back_route.dart';
import 'list_and_field.dart';
import 'resource_chrome.dart';

/// Messages of one author closer together than this are one group: the author
/// is named once above it.
const _groupGap = Duration(minutes: 5);

/// The chat of a meeting or a chat room: messages as bubbles (mine on the
/// right, the others' on the left with their name and an initial), the meeting's
/// events ("Joep is viewing Roadmap") as compact grey lines that open the
/// resource, newest at the bottom, and a field to write one. What is written
/// here is what the web app's chat shows too. New messages show up on their own
/// while this screen is on top.
class ChatRoomScreen extends StatefulWidget {
  final AssistantApi api;

  /// The drive the room lives in, for the resources its event lines open.
  final String drive;
  final String subject;

  /// The room's or meeting's name.
  final String title;

  const ChatRoomScreen({
    super.key,
    required this.api,
    this.drive = '',
    required this.subject,
    this.title = '',
  });

  @override
  State<ChatRoomScreen> createState() => _ChatRoomScreenState();
}

class _ChatRoomScreenState extends State<ChatRoomScreen>
    with WidgetsBindingObserver {
  final _input = TextEditingController();
  final _focus = FocusNode();

  /// The name given here, shown instead of [ChatRoomScreen.title].
  String? _renamed;

  String get _title => _renamed ?? widget.title;

  /// A chat room has no page of its own on the phone (this screen replaces
  /// it), so its name is changed here: a new room is called "ChatRoom".
  Future<void> _rename() async {
    // All selected: typing replaces the old name ("ChatRoom" on a new room).
    final controller = TextEditingController(text: _title)
      ..selection = TextSelection(baseOffset: 0, extentOffset: _title.length);
    final name = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Rename chat'),
        content: TextField(
          key: const Key('chat-room-name'),
          controller: controller,
          autofocus: true,
          textCapitalization: TextCapitalization.sentences,
          onSubmitted: (v) => Navigator.of(context).pop(v),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel')),
          TextButton(
              onPressed: () => Navigator.of(context).pop(controller.text),
              child: const Text('Save')),
        ],
      ),
    );
    // Not disposed here: the dialog still animates out with it.
    final trimmed = name?.trim() ?? '';
    if (trimmed.isEmpty || trimmed == _title || !mounted) return;
    final before = _renamed;
    setState(() => _renamed = trimmed);
    try {
      await widget.api.renameResource(widget.subject, trimmed);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _renamed = before;
        _error = "Couldn't rename: $e";
      });
    }
  }

  /// The window of the room on screen: the newest lines, older ones read
  /// as the list scrolls up (see [ChatWindow]).
  late final ChatWindow<ChatRoomMessage> _window = ChatWindow(
    readPage: (before, limit) => widget.api
        .chatRoomMessagesPage(widget.subject, before: before, limit: limit),
    readAfter: (after, limit) =>
        widget.api.chatRoomMessagesAfter(widget.subject, after, limit: limit),
    idOf: (m) => m.id,
    onOlderPage: (ms, n) => Perf.span('chat older page $n', ms),
  );
  late final _keeper = ChatScrollKeeper(_window);
  ScrollController get _scroll => _keeper.controller;
  String? _prevNewest;
  String? _enterId;
  bool _hadText = false;
  bool _foreground = true;
  bool _reading = false;
  Timer? _timer;

  /// Messages being sent, shown at the bottom until they are read back.
  final List<ChatRoomMessage> _pending = [];
  int _pendingCount = 0;

  /// Sends run one after the other, so messages keep their order.
  Future<void> _sends = Future.value();
  String? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _input.addListener(_inputChanged);
    _window.addListener(_windowChanged);
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
    _window.removeListener(_windowChanged);
    _window.dispose();
    _keeper.dispose();
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

  /// What arrived since the newest line read; shown at once when at the
  /// bottom, otherwise counted on the "Jump to latest" button.
  Future<void> _read() async {
    if (_reading) return;
    _reading = true;
    try {
      if (!_window.loaded) {
        await _window.open();
      } else {
        await _window.poll(atBottom: _keeper.atBottom);
      }
    } finally {
      _reading = false;
    }
  }

  /// The list is upside down (newest at offset 0): the bottom is the start.
  void _toBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _keeper.nudgeToBottom();
    });
  }

  void _send() {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    _input.clear();
    // Submitting keeps the cursor: the keyboard stays open for the next one.
    _focus.requestFocus();
    final pending = (
      id: 'pending-${_pendingCount++}',
      kind: ChatRoomKind.text,
      author: '',
      authorName: '',
      mine: true,
      text: text,
      createdAt: DateTime.now().millisecondsSinceEpoch,
      about: null,
      aboutTitle: '',
    );
    setState(() {
      _pending.add(pending);
      _error = null;
    });
    _toBottom();
    _sends = _sends.then((_) async {
      try {
        await widget.api.sendChatRoomMessage(widget.subject, text);
        await _read();
        // Your own message shows where you are writing: at the bottom.
        if (_window.unseen > 0 || _window.detached) {
          await _keeper.jumpToLatest();
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

  /// Opens the resource an event line is about.
  void _openAbout(ChatRoomMessage m) {
    final subject = m.about;
    if (subject == null) return;
    widget.api.noteOpened(widget.drive, subject);
    Navigator.of(context).push(SlideBackRoute<void>(
      builder: (_) => openResourceView(
          api: widget.api,
          drive: widget.drive,
          subject: subject,
          title: m.aboutTitle),
    ));
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
                onRename: _rename,
                child: Scaffold(
                  backgroundColor: c.bgBody,
                  appBar: AppTopBar(
                    compact: true,
                    title: _title.isEmpty ? 'Chat' : _title,
                    titleWidget: ChatHeader(
                      title: _title.isEmpty ? 'Chat' : _title,
                      subtitle: _subtitle,
                      icon: Icons.forum_outlined,
                    ),
                    bottom: ResourceBreadcrumbs(
                        api: widget.api,
                        drive: widget.drive,
                        subject: widget.subject),
                    actions: const [ResourceMoreButton()],
                  ),
                  body: ListAndField(
                      fullWidthField: true,
                      list: _list(c),
                      field: _composer(c)),
                ))));
  }

  /// The room, and how many people have spoken in it.
  String get _subtitle {
    final people = {
      for (final m in _window.items)
        if (m.kind == ChatRoomKind.text) m.mine ? 'me' : m.author,
    };
    return people.length > 1 ? '${people.length} members' : 'Chat room';
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
    // Bubbles of one author in a row (events and gaps end it) share a header.
    bool sameGroup(ChatRoomMessage a, ChatRoomMessage b) =>
        a.kind == ChatRoomKind.text &&
        b.kind == ChatRoomKind.text &&
        a.mine == b.mine &&
        a.author == b.author &&
        (b.createdAt - a.createdAt).abs() <= _groupGap.inMilliseconds;
    final ids = [for (final m in shown) m.id];
    final at = {for (var i = 0; i < ids.length; i++) ids[i]: i};
    // The newest row slides in, unless it is your own message read back.
    final newest = ids.last;
    if (_prevNewest != null && newest != _prevNewest) {
      final readBack = _prevNewest!.startsWith('pending-') &&
          !newest.startsWith('pending-') &&
          shown.last.mine;
      _enterId = _keeper.atBottom && !readBack ? newest : null;
    }
    _prevNewest = newest;
    final list = LayoutBuilder(
        builder: (context, box) => ListView.builder(
              controller: _scroll,
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
                  // The top: older lines are being read.
                  return const Padding(
                    padding: EdgeInsets.all(12),
                    child: Center(
                        child: SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2))),
                  );
                }
                _keeper.built(i);
                final index = shown.length - 1 - i;
                final m = shown[index];
                final Widget row;
                if (m.kind == ChatRoomKind.event) {
                  row = _eventRow(c, m);
                } else {
                  final first = index == 0 || !sameGroup(shown[index - 1], m);
                  final last = index == shown.length - 1 ||
                      !sameGroup(m, shown[index + 1]);
                  row = MessageRow(
                    mine: m.mine,
                    first: first,
                    last: last,
                    name: !m.mine && first ? _nameOf(m) : null,
                    avatarOf: m.mine ? null : m.authorName,
                    time: last ? clockTime(m.createdAt) : null,
                    sending: m.id.startsWith('pending-'),
                    listWidth: box.maxWidth -
                        2 *
                            (ChatTextStyles.gutter +
                                readableSideInset(box.maxWidth)),
                    content: SelectableText(m.text,
                        style: m.mine
                            ? ChatTextStyles.of(context).bodyMine
                            : ChatTextStyles.of(context).body),
                  );
                }
                final newDay = index == 0 && !_window.hasOlder ||
                    index > 0 &&
                        otherDay(shown[index - 1].createdAt, m.createdAt);
                return KeyedSubtree(
                  key: ValueKey(m.id),
                  child: RowEntrance(
                    animate: m.id == _enterId,
                    child: newDay
                        ? Column(children: [
                            DaySeparator(dayLabel(m.createdAt),
                                color: c.textSecondary),
                            row,
                          ])
                        : row,
                  ),
                );
              },
            ));
    final unseen = _window.unseen;
    return Stack(children: [
      list,
      ScrollToBottomButton(keeper: _keeper, unseen: unseen),
    ]);
  }

  String _nameOf(ChatRoomMessage m) =>
      m.authorName.isEmpty ? 'Unknown member' : m.authorName;

  /// "Joep is viewing Roadmap", or "Joep · Started the meeting." for a marker.
  String _eventText(ChatRoomMessage m) {
    final name = m.authorName;
    if (m.about != null) {
      final title = m.aboutTitle.isEmpty ? m.about! : m.aboutTitle;
      return name.isEmpty ? 'Viewing $title' : '$name is viewing $title';
    }
    return name.isEmpty ? m.text : '$name · ${m.text}';
  }

  Widget _eventRow(AppColors c, ChatRoomMessage m) {
    final tappable = m.about != null;
    final row = Padding(
      padding: const EdgeInsets.symmetric(vertical: 4, horizontal: 4),
      child: Row(
        children: [
          Icon(Icons.near_me_outlined, size: 14, color: c.textSecondary),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              _eventText(m),
              key: const Key('event-text'),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: ChatTextStyles.of(context).meta.copyWith(
                    decoration: tappable
                        ? TextDecoration.underline
                        : TextDecoration.none,
                    decorationColor: c.textSecondary,
                  ),
            ),
          ),
          const SizedBox(width: 8),
          Text(messageTime(m.createdAt),
              style: ChatTextStyles.of(context).meta),
        ],
      ),
    );
    return tappable
        ? InkWell(
            mouseCursor: WidgetStateMouseCursor.clickable,
            key: const Key('event-row'),
            onTap: () => _openAbout(m),
            child: row,
          )
        : KeyedSubtree(key: const Key('event-row'), child: row);
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
