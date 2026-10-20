import 'dart:async';

import 'package:flutter/material.dart';

/// One window of a chat as the host reads it: [items] oldest first, [older]
/// the cursor of the window before (null at the start of the chat),
/// [newest] the cursor of the last item (null when there is none; for
/// reading what came after), [more] when a read of newer items was cut by
/// its limit. Cursors are opaque.
@immutable
class ChatPage<T> {
  final List<T> items;
  final String? older;
  final String? newest;
  final bool more;

  const ChatPage(this.items, {this.older, this.newest, this.more = false});

  static ChatPage<T> empty<T>() => ChatPage<T>(const []);
}

/// A window of the newest items before [before] (null: the newest of all).
typedef ChatPageReader<T> = Future<ChatPage<T>> Function(
    String? before, int limit);

/// The items after the cursor [after], oldest first.
typedef ChatAfterReader<T> = Future<ChatPage<T>> Function(
    String after, int limit);

/// Windows of a host-side list, as the [ChatPage] calls of [AssistantApi]
/// give them, over a list of all of them: for a host that reads a chat whole.
/// The cursors are positions in [all].
ChatPage<T> pageOfAll<T>(List<T> all, String? before, int limit) {
  final end = before == null
      ? all.length
      : (int.tryParse(before) ?? all.length).clamp(0, all.length);
  final start = (end - limit).clamp(0, end);
  return ChatPage<T>(all.sublist(start, end),
      older: start > 0 ? '$start' : null, newest: '$end');
}

/// See [pageOfAll]: the items after [after], a position in [all].
ChatPage<T> afterOfAll<T>(List<T> all, String after, int limit) {
  final from = (int.tryParse(after) ?? all.length).clamp(0, all.length);
  final end = (from + limit).clamp(from, all.length);
  return ChatPage<T>(all.sublist(from, end),
      newest: '$end', more: end < all.length);
}

class _Chunk<T> {
  final List<T> items;
  final String? older;
  String? newest;
  _Chunk(this.items, this.older, this.newest);
}

/// What a chat screen holds of a chat that may be very long (a channel of
/// 200 000 messages): a bounded window of it, read in pages of [pageSize]
/// as the person scrolls.
///
/// - [open] reads the newest page.
/// - [loadOlder] adds the page before the first item (scrolled up).
/// - [poll] reads what arrived after the last item: added at once when the
///   person is at the bottom ([atBottom]), else counted in [unseen] and kept
///   until [jumpToLatest].
/// - The window keeps at most [maxItems]: scrolled near the bottom the
///   oldest pages go ([trimOldest]); scrolled far up the newest go
///   ([trimNewest]) and come back through [loadNewer]. [detached] tells that
///   the newest items are not in the window.
/// - [add] puts an item the screen made itself (a sent message) at the end.
///
/// Items are told apart by [idOf], so a page read twice adds nothing twice.
class ChatWindow<T> extends ChangeNotifier {
  final ChatPageReader<T> readPage;
  final ChatAfterReader<T>? readAfter;
  final String Function(T) idOf;
  final int pageSize;
  final int maxItems;

  ChatWindow({
    required this.readPage,
    required this.readAfter,
    required this.idOf,
    this.pageSize = 50,
    this.maxItems = 500,
  });

  final List<_Chunk<T>> _chunks = [];

  /// Items the screen added (sent), after every chunk.
  final List<T> _local = [];

  /// New items read while the person was scrolled up, shown on
  /// [jumpToLatest].
  final List<T> _waiting = [];

  /// The cursor after the newest item the host gave (also while [detached]).
  String? _latest;

  List<T>? _items;
  bool _loaded = false;
  Object? _error;
  bool _loadingOlder = false;
  bool _loadingNewer = false;
  bool _detached = false;
  bool _disposed = false;

  /// Everything in the window, oldest first. Cached until it changes.
  List<T> get items => _items ??= [
        for (final c in _chunks) ...c.items,
        ..._local,
      ];

  bool get loaded => _loaded;
  Object? get error => _error;
  bool get loadingOlder => _loadingOlder;

  /// Whether there is more before the first item.
  bool get hasOlder => _chunks.isNotEmpty && _chunks.first.older != null;

  /// Whether the newest items are out of the window (scrolled far up).
  bool get detached => _detached;

  /// New items that arrived while scrolled up, not shown yet; or, while
  /// [detached], at least one when anything arrived.
  int get unseen => _waiting.length + (_detachedNews ? 1 : 0);
  bool _detachedNews = false;

  void _changed() {
    _items = null;
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }

  Future<void> open() async {
    try {
      final page = await readPage(null, pageSize);
      _chunks
        ..clear()
        ..add(_Chunk(List.of(page.items), page.older, page.newest));
      _local.clear();
      _waiting.clear();
      _latest = page.newest;
      _detached = false;
      _detachedNews = false;
      _loaded = true;
      _error = null;
    } catch (e) {
      // A failed refresh keeps what is shown.
      if (!_loaded) {
        _error = e;
        _loaded = true;
      }
    }
    _changed();
  }

  /// Open a window at [cursor] (an `older` cursor, as a search result will
  /// give): the page before it, detached from the newest.
  Future<void> openAt(String cursor) async {
    final page = await readPage(cursor, pageSize);
    _chunks
      ..clear()
      ..add(_Chunk(List.of(page.items), page.older, page.newest));
    _local.clear();
    _waiting.clear();
    _detached = true;
    _loaded = true;
    _changed();
  }

  Future<void> loadOlder() async {
    if (_loadingOlder || !hasOlder) return;
    _loadingOlder = true;
    _changed();
    try {
      final first = _chunks.first;
      final page = await readPage(first.older, pageSize);
      if (identical(_chunks.firstOrNull, first)) {
        final known = {for (final i in items) idOf(i)};
        _chunks.insert(
            0,
            _Chunk([
              for (final i in page.items)
                if (!known.contains(idOf(i))) i
            ], page.older, page.newest));
      }
    } catch (_) {
      // Tried again on the next scroll.
    } finally {
      _loadingOlder = false;
      _changed();
    }
  }

  /// While [detached]: the page after the last item, back towards the
  /// newest.
  Future<void> loadNewer() async {
    final after = _chunks.lastOrNull?.newest;
    if (!_detached || _loadingNewer || readAfter == null || after == null) {
      return;
    }
    _loadingNewer = true;
    try {
      final page = await readAfter!(after, pageSize);
      final known = {for (final i in items) idOf(i)};
      _chunks.add(_Chunk([
        for (final i in page.items)
          if (!known.contains(idOf(i))) i
      ], null, page.newest ?? after));
      if (!page.more) {
        _detached = false;
        _detachedNews = false;
        _latest = page.newest ?? after;
      }
    } catch (_) {
    } finally {
      _loadingNewer = false;
      _changed();
    }
  }

  /// Read what arrived after the newest item. With [atBottom] it is shown
  /// at once; otherwise it waits in [unseen].
  Future<void> poll({required bool atBottom}) async {
    final after = _latest;
    if (readAfter == null) return;
    if (after == null) {
      // An empty chat: read the newest page again.
      if (items.isEmpty) await open();
      return;
    }
    try {
      var page = await readAfter!(after, pageSize);
      _latest = page.newest ?? after;
      if (page.items.isEmpty) return;
      if (_detached) {
        _detachedNews = true;
        _changed();
        return;
      }
      final known = {for (final i in items) idOf(i)};
      final fresh = [
        for (final i in page.items)
          if (!known.contains(idOf(i))) i
      ];
      // A sent message read back replaces its local stand-in: the screen
      // drops those itself (see [settleLocal]); here they are just known.
      if (atBottom && _waiting.isEmpty) {
        _appendRead(fresh, page.newest);
        // A burst longer than a page: the newest page is enough.
        if (page.more) await open();
      } else {
        _waiting.addAll(fresh);
        if (page.more) _detachedNews = true;
      }
      _changed();
    } catch (_) {
      // A failed poll keeps what is shown.
    }
  }

  void _appendRead(List<T> fresh, String? newest) {
    if (_chunks.isEmpty) _chunks.add(_Chunk([], null, null));
    _chunks.last.items.addAll(fresh);
    _chunks.last.newest = newest ?? _chunks.last.newest;
  }

  /// Show the newest items: the waiting ones, or the newest page again when
  /// the window had left them.
  Future<void> jumpToLatest() async {
    if (_detached || _detachedNews) {
      await open();
      return;
    }
    _appendRead(List.of(_waiting), _latest);
    _waiting.clear();
    _changed();
  }

  /// Add an item the screen made (a message being sent) at the end.
  void add(T item) {
    _local.add(item);
    _changed();
  }

  /// Replace the screen's own items (sent messages: pending ones go once
  /// they are read back).
  void setLocal(List<T> local) {
    _local
      ..clear()
      ..addAll(local);
    _changed();
  }

  List<T> get local => List.unmodifiable(_local);

  /// Scrolled near the bottom: drop the oldest pages beyond [maxItems].
  /// Nothing on screen moves (the list grows from the bottom).
  void trimOldest() {
    var n = items.length;
    var dropped = false;
    while (_chunks.length > 1 && n - _chunks.first.items.length >= maxItems) {
      n -= _chunks.removeAt(0).items.length;
      dropped = true;
    }
    if (dropped) _changed();
  }

  /// Scrolled far up: drop the newest pages beyond [maxItems]; they are
  /// read again by [loadNewer] or [jumpToLatest].
  void trimNewest() {
    if (_local.isNotEmpty || readAfter == null) return;
    var n = items.length;
    var dropped = false;
    while (_chunks.length > 1 &&
        n - _chunks.last.items.length >= maxItems &&
        _chunks[_chunks.length - 2].newest != null) {
      n -= _chunks.removeLast().items.length;
      dropped = true;
    }
    if (dropped) {
      _detached = true;
      _waiting.clear();
      _changed();
    }
  }
}

/// Scroll behaviour of a chat list over a [ChatWindow]: a reversed list
/// (newest at the bottom, offset 0). Loads older pages within [edge] items
/// of the top and newer ones near the bottom while detached, keeps the
/// window bounded, and tells whether the person is at the bottom.
class ChatScrollKeeper {
  final ChatWindow<dynamic> window;
  final ScrollController controller = ScrollController();

  /// About how many items from either end a page is read.
  final int edge;

  ChatScrollKeeper(this.window, {this.edge = 15}) {
    controller.addListener(_scrolled);
  }

  /// Within this many pixels of the bottom counts as at the bottom.
  static const bottomSlack = 80.0;

  bool get atBottom =>
      !controller.hasClients || controller.position.pixels <= bottomSlack;

  /// Scrolled up by more than a screen: show "Jump to latest".
  bool get farFromBottom =>
      controller.hasClients &&
      controller.position.pixels > controller.position.viewportDimension;

  /// The index (from the bottom) the list last built: where the eye is.
  int _lastBuilt = 0;

  /// Called by the item builder with the index from the bottom.
  void built(int fromBottom) {
    final count = window.items.length;
    _lastBuilt = fromBottom;
    if (count - fromBottom <= edge && window.hasOlder) {
      // Not during the build.
      scheduleMicrotask(window.loadOlder);
    }
  }

  void _scrolled() {
    if (!controller.hasClients) return;
    final pos = controller.position;
    if (pos.pixels <= bottomSlack) {
      if (window.detached) {
        unawaited(window.loadNewer());
      } else {
        window.trimOldest();
      }
    } else if (_lastBuilt > window.maxItems ~/ 2 + edge) {
      window.trimNewest();
    }
  }

  Future<void> jumpToLatest() async {
    await window.jumpToLatest();
    if (controller.hasClients) controller.jumpTo(0);
  }

  void dispose() => controller.dispose();
}

/// The "Jump to latest" button over a chat list: shown when scrolled up by
/// more than a screen or when new messages wait, with their count.
class JumpToLatest extends StatelessWidget {
  final int unseen;
  final VoidCallback onPressed;

  const JumpToLatest(
      {super.key, required this.unseen, required this.onPressed});

  @override
  Widget build(BuildContext context) => FloatingActionButton.small(
        key: const Key('jump-to-latest'),
        tooltip: unseen > 0 ? '$unseen new' : 'Jump to latest',
        onPressed: onPressed,
        child: unseen > 0
            ? Badge(
                label: Text(unseen > 99 ? '99+' : '$unseen'),
                child: const Icon(Icons.arrow_downward),
              )
            : const Icon(Icons.arrow_downward),
      );
}

/// 'Today', 'Yesterday' or the date, for a separator above the first
/// message of a day.
String dayLabel(int ms, {DateTime? now}) {
  final at = DateTime.fromMillisecondsSinceEpoch(ms);
  final today = now ?? DateTime.now();
  final day = DateTime(at.year, at.month, at.day);
  final diff = DateTime(today.year, today.month, today.day).difference(day);
  if (diff.inDays == 0) return 'Today';
  if (diff.inDays == 1) return 'Yesterday';
  const months = [
    'January', 'February', 'March', 'April', 'May', 'June', 'July', //
    'August', 'September', 'October', 'November', 'December',
  ];
  final date = '${at.day} ${months[at.month - 1]}';
  return at.year == today.year ? date : '$date ${at.year}';
}

/// Whether two times (ms) are on different days.
bool otherDay(int a, int b) {
  final x = DateTime.fromMillisecondsSinceEpoch(a);
  final y = DateTime.fromMillisecondsSinceEpoch(b);
  return x.year != y.year || x.month != y.month || x.day != y.day;
}

/// A day separator line.
class DaySeparator extends StatelessWidget {
  final String label;
  final Color color;
  const DaySeparator(this.label, {super.key, required this.color});

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 10),
        child: Center(
          child: Text(label,
              key: const Key('day-separator'),
              style: TextStyle(color: color, fontSize: 12)),
        ),
      );
}

/// For a reversed `ListView.builder` over [ids] (oldest first): the
/// builder index of an item's key, so a row keeps its element (and place)
/// when items are added above or below it.
int? reversedIndexOf(Key key, List<String> ids, Map<String, int> index) {
  if (key is! ValueKey<String>) return null;
  final i = index[key.value];
  return i == null ? null : ids.length - 1 - i;
}
