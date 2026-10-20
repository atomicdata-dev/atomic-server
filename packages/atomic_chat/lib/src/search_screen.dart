import 'dart:async';
import 'dart:math' as math;

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt, Perf;
import 'package:flutter/foundation.dart' show kReleaseMode;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'app_top_bar.dart';

import 'models.dart';
import 'covered_insets_freeze.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'resource_row.dart';
import 'native_views.dart';
import 'list_and_field.dart';
import 'new_document_sheet.dart';

/// What a search looks for: anything, or one kind (a home section's search).
enum SearchKind {
  any('', 'Search', 'Recently opened'),
  drives('Drives', 'Search drives', 'Drives'),
  chats('AI chats', 'Search AI chats', 'AI chats'),
  messages('Messages', 'Search messages', 'Messages');

  /// The chip next to the field; empty for [any].
  final String label;
  final String hint;

  /// The heading over what is listed before anything is typed.
  final String heading;

  const SearchKind(this.label, this.hint, this.heading);

  /// The classes the host's search keeps for this kind (see
  /// [AssistantApi.searchClasses]); empty for [any].
  List<String> get classes => switch (this) {
        any => const [],
        drives => const ['drive'],
        chats => const ['aichat'],
        messages => const ['conversation', 'chatroom'],
      };

  /// Whether a resource of [className] (a shortname or class URL) is of this
  /// kind.
  bool matches(String className) {
    final key = className
        .split(RegExp(r'[/#]'))
        .last
        .toLowerCase()
        .replaceAll(RegExp(r'[^a-z0-9]'), '');
    return switch (this) {
      any => true,
      drives => key == 'drive',
      chats => key == 'aichat',
      messages => key == 'conversation' || key == 'chatroom',
    };
  }
}

/// Type-ahead search over every drive; a hit opens in its own drive. [drive]
/// is only the fallback for what has no drive of its own.
///
/// With [scopeDrive] it searches that drive only (and lists only its recently
/// opened resources), said next to the field with a way back to every drive.
/// The scope belongs to this opening of the screen.
///
/// With a [kind] other than [SearchKind.any] only resources of that kind are
/// listed (before anything is typed: all of them), said in a chip next to the
/// field with a way back to everything.
class SearchScreen extends StatefulWidget {
  final AssistantApi api;
  final String drive;
  final String? scopeDrive;
  final SearchKind kind;

  /// What the field starts with (a search that moved to the list pane, or
  /// back, when the window changed size).
  final String initialQuery;

  /// The tablet's search over everything ([showSearchPalette]): the field on
  /// top, the results under it, no page bar.
  final bool palette;

  /// Called as a result is opened (the palette closes then).
  final VoidCallback? onOpened;

  const SearchScreen({
    super.key,
    required this.drive,
    required this.api,
    this.scopeDrive,
    this.kind = SearchKind.any,
    this.initialQuery = '',
    this.palette = false,
    this.onOpened,
  });

  /// A quick fade and short rise instead of the page slide: the keyboard rises
  /// at the same time, and a long slide on top of it feels slow.
  static Route<void> route({
    required String drive,
    required AssistantApi api,
    String? scopeDrive,
    SearchKind kind = SearchKind.any,
    String initialQuery = '',
    RouteSettings? settings,
  }) =>
      PageRouteBuilder<void>(
        settings: settings,
        pageBuilder: (_, __, ___) => CoveredInsetsFreeze(
            child: SearchScreen(
                drive: drive,
                api: api,
                scopeDrive: scopeDrive,
                kind: kind,
                initialQuery: initialQuery)),
        transitionDuration: const Duration(milliseconds: 140),
        reverseTransitionDuration: const Duration(milliseconds: 110),
        transitionsBuilder: (context, animation, _, child) => AnimatedBuilder(
          animation: animation,
          child: child,
          builder: (context, child) {
            final t = (animation.status == AnimationStatus.reverse
                    ? Curves.easeIn
                    : Curves.easeOut)
                .transform(animation.value);
            return Opacity(
              opacity: t,
              child: Transform.translate(
                offset: Offset(0, 24 * (1 - t)),
                child: child,
              ),
            );
          },
        ),
      );

  @override
  State<SearchScreen> createState() => _SearchScreenState();
}

/// The tablet's search: a card over the whole window (sidebar and pages)
/// on a dimmed backdrop, like a browser's ⌘K. A tap next to it, Esc or back
/// closes it and leaves everything as it was; a result opens in the detail
/// pane and closes it. Its route carries the [ShellScope] the card needs.
Future<void> showSearchPalette({
  required ShellController shell,
  required AssistantApi api,
  String? scope,
  SearchKind kind = SearchKind.any,
}) async {
  final context = shell.navigatorKey.currentContext;
  if (context == null || shell.searching.value) return;
  shell.searching.value = true;
  try {
    await showGeneralDialog<void>(
      context: context,
      useRootNavigator: true,
      barrierDismissible: true,
      barrierLabel: 'Close search',
      barrierColor: Colors.black54,
      transitionDuration: const Duration(milliseconds: 120),
      transitionBuilder: (context, animation, _, child) => FadeTransition(
          opacity: CurvedAnimation(parent: animation, curve: Curves.easeOut),
          child: child),
      pageBuilder: (dialog, _, __) => ShellScope(
        controller: shell,
        layout: ShellLayout.split,
        child: SearchPalette(
          child: SearchScreen(
            drive: shell.drive.value,
            api: api,
            scopeDrive: scope,
            kind: kind,
            palette: true,
            onOpened: () => Navigator.of(dialog).pop(),
          ),
        ),
      ),
    );
  } finally {
    shell.searching.value = false;
  }
}

/// The palette's card: at most [maxWidth] wide, in the upper part of the
/// window, as high as fits above the keyboard (up to 70% of the window).
class SearchPalette extends StatelessWidget {
  static const maxWidth = 640.0;

  final Widget child;

  const SearchPalette({super.key, required this.child});

  @override
  Widget build(BuildContext context) {
    final media = MediaQuery.of(context);
    final size = media.size;
    final top = media.padding.top + size.height * 0.08;
    final room = size.height - top - media.viewInsets.bottom - 16;
    final height = math.max(120.0, math.min(size.height * 0.7, room));
    return Padding(
      padding: EdgeInsets.only(top: top, left: 16, right: 16),
      child: Align(
        alignment: Alignment.topCenter,
        child: ConstrainedBox(
          constraints: BoxConstraints(maxWidth: maxWidth, maxHeight: height),
          child: Material(
            key: const Key('search-palette'),
            elevation: 12,
            clipBehavior: Clip.antiAlias,
            borderRadius: BorderRadius.circular(16),
            // The page under the card is not the card's: no insets.
            child: MediaQuery(
              data: media
                  .removePadding(removeTop: true, removeBottom: true)
                  .removeViewPadding(removeTop: true, removeBottom: true)
                  .removeViewInsets(removeBottom: true),
              child: child,
            ),
          ),
        ),
      ),
    );
  }
}

typedef _Item = ({
  String drive,
  String shown,
  String subject,
  String title,
  String className,
  String? emoji
});

/// What the list shows. The screen is built once; only the list listens.
class _SearchModel extends ChangeNotifier {
  List<SearchHit> hits = const [];
  List<DriveInfo> drives = const [];
  List<({String drive, RecentResource resource})> recent = const [];
  Object? error;
  String query = '';

  /// The query [hits] answer (they lag the field while a search runs); empty
  /// before the first answer, and the list shows the recents until then.
  String hitsFor = '';

  /// The kind [hits] were searched for (the host keeps only that kind).
  SearchKind hitsKind = SearchKind.any;

  /// Whether the list shows the recently opened instead of hits: nothing
  /// typed, or no answer yet (no empty frame between the two lists).
  bool get showsRecent => query.isEmpty || hitsFor.isEmpty;

  /// The one drive searched, or null for all of them.
  String? scope;

  /// What is looked for.
  SearchKind kind = SearchKind.any;

  /// Every resource of [kind] (not [SearchKind.any]), listed before anything
  /// is typed; null until read.
  List<_Item>? ofKind;

  void changed() => notifyListeners();
}

class _SearchScreenState extends State<SearchScreen> {
  final _SearchModel _model = _SearchModel();
  ShellController? _shell;
  late final TextEditingController _text =
      TextEditingController(text: widget.initialQuery);
  final FocusNode _focus = FocusNode();
  late final ValueNotifier<SearchKind> _hintKind = ValueNotifier(widget.kind);

  @override
  void initState() {
    super.initState();
    _shell = ShellScope.maybeOf(context);
    _model.scope = widget.scopeDrive;
    _model.kind = widget.kind;
    final cache = _shell?.searchCache;
    if (cache != null) {
      _model.drives = cache.drives;
      _model.recent = _inScope(cache.recent);
    }
    _remember();
    _load();
    _shell?.searchReset.addListener(_startOver);
    // `autofocus` only takes the focus where nothing has it; in the list
    // pane the page next to it (a web page) may have it.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && !_focus.hasFocus) _focus.requestFocus();
    });
    if (widget.initialQuery.trim().isNotEmpty) _changed(widget.initialQuery);
  }

  /// The Search button while this search is the one shown: an empty field
  /// (and the recents), the keyboard up. A field that was empty already also
  /// lets go of its drive.
  void _startOver() {
    if (!mounted || !(ModalRoute.of(context)?.isCurrent ?? true)) return;
    final wasEmpty = _text.text.trim().isEmpty;
    _text.clear();
    _changed('');
    if (wasEmpty && _model.kind != SearchKind.any) {
      _clearKind();
    } else if (wasEmpty && _model.scope != null) {
      _clearScope();
    }
    _showKeyboard();
  }

  /// Focus on the field and the keyboard up, also when the field kept the
  /// focus but the keyboard was put away (Android's back).
  void _showKeyboard() {
    _focus.requestFocus();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && _focus.hasFocus) {
        unawaited(SystemChannels.textInput
            .invokeMethod<void>('TextInput.show')
            .catchError((_) {}));
      }
    });
  }

  /// Whether this search's page was on top when last looked at.
  bool _wasCurrent = true;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // Back to the search (a page opened from it was closed): ready to type.
    final current = ModalRoute.of(context)?.isCurrent ?? true;
    if (current && !_wasCurrent) _showKeyboard();
    _wasCurrent = current;
  }

  /// The shell keeps the text and drive, for a search that moves between a
  /// page and the list pane.
  void _remember() => _shell?.search =
      (query: _text.text, scope: _model.scope, kind: _model.kind);

  /// [recent] limited to the scope's drive, when there is one.
  List<({String drive, RecentResource resource})> _inScope(
      List<({String drive, RecentResource resource})> recent) {
    final scope = _model.scope;
    if (scope == null) return recent;
    return [
      for (final r in recent)
        if (_id(r.drive) == _id(scope)) r
    ];
  }

  /// Back to every drive: the same screen, the query searched again.
  void _clearScope() {
    _model.scope = null;
    _remember();
    final route = ModalRoute.of(context);
    if (route != null) _shell?.setKind(route, ShellPage.search);
    final query = _model.query;
    _model.query = '';
    _model.hits = const [];
    _model.hitsFor = '';
    _model.changed();
    _loadRecent(_model.drives);
    if (query.isNotEmpty) _changed(query);
  }

  /// Back to every kind: the same screen, the query searched again.
  void _clearKind() {
    _model.kind = SearchKind.any;
    _hintKind.value = SearchKind.any;
    _model.ofKind = null;
    _remember();
    final route = ModalRoute.of(context);
    if (route != null) {
      _shell?.setKind(
          route,
          _model.scope == null
              ? ShellPage.search
              : ShellPage.searchIn(_model.scope!));
    }
    _model.changed();
    // The hits so far are of the kind only: everything is searched again.
    if (_model.query.isNotEmpty && !_searching) unawaited(_search());
  }

  bool _isDrive(String subject, String className) =>
      subject.isNotEmpty &&
      (className.split(RegExp(r'[/#]')).last == 'Drive' ||
          _model.drives.any((d) => _id(d.subject) == _id(subject)));

  /// The explicit "search in this drive" of a drive in the results: the
  /// search goes on inside [subject]. Tapping the drive itself opens it.
  void _searchInDrive(String subject) {
    if (subject.isEmpty) return;
    if (_model.scope != null && _id(_model.scope!) == _id(subject)) return;
    _model.scope = subject;
    _remember();
    final route = ModalRoute.of(context);
    if (route != null) _shell?.setKind(route, ShellPage.search);
    final query = _model.query;
    _model.query = '';
    _model.hits = const [];
    _model.hitsFor = '';
    _model.recent = _inScope(_model.recent);
    _model.changed();
    _loadRecent(_model.drives);
    if (query.isNotEmpty) _changed(query);
  }

  /// One drives call for both the names and the recents; it paints the cached
  /// list first and refreshes behind it.
  Future<void> _load() async {
    try {
      final drives = await widget.api.drives();
      if (!mounted) return;
      _model.drives = drives;
      _model.changed();
      await Future.wait([_loadRecent(drives), _loadKind()]);
    } catch (_) {
      // Only names and a convenience: the search itself still works.
    }
  }

  Future<void> _loadRecent(List<DriveInfo> known) async {
    try {
      final scope = _model.scope;
      var drives = scope != null ? [scope] : [for (final d in known) d.subject];
      if (drives.isEmpty) drives = [widget.drive];
      final lists = await Future.wait([
        for (final drive in drives)
          widget.api.recentResources(drive).then(
                (list) => [for (final r in list) (drive: drive, resource: r)],
                onError: (Object _) =>
                    <({String drive, RecentResource resource})>[],
              ),
      ]);
      final merged = [for (final l in lists) ...l]
        ..sort((a, b) => b.resource.openedAt.compareTo(a.resource.openedAt));
      final recent = merged.take(20).toList();
      if (scope == null) _shell?.searchCache = SearchCache(known, recent);
      if (!mounted || scope != _model.scope) return;
      _model.recent = recent;
      _model.changed();
    } catch (_) {
      // Only a convenience: the search itself still works.
    }
  }

  /// Every resource of the kind looked for, for the list before anything is
  /// typed.
  Future<void> _loadKind() async {
    final kind = _model.kind;
    try {
      final List<_Item> items = switch (kind) {
        SearchKind.any => const [],
        SearchKind.drives => [
            for (final d in _model.drives)
              (
                drive: d.subject,
                shown: '',
                subject: d.subject,
                title: d.name.isEmpty ? 'Untitled drive' : d.name,
                className: 'Drive',
                emoji: d.emoji
              )
          ],
        SearchKind.chats => await _loadChats(kind),
        SearchKind.messages => [
            for (final c in await widget.api.conversations())
              (
                drive: widget.drive,
                shown: '',
                subject: c.resource.subject,
                title: c.resource.title,
                className: c.resource.className,
                emoji: c.resource.emoji
              )
          ],
      };
      if (!mounted || kind != _model.kind) return;
      _model.ofKind = items;
      _model.changed();
    } catch (_) {
      // Only a convenience: the search itself still works.
    }
  }

  /// Every AI chat, newest first: the first page shows at once, the rest
  /// joins it as the pages arrive (a thousand chats are twenty pages).
  Future<List<_Item>> _loadChats(SearchKind kind) async {
    final items = <_Item>[];
    final known = <String>{};
    while (true) {
      final page = await widget.api.chatsPage(
          offset: known.length, limit: AssistantApi.chatsPageSize * 4);
      for (final c in page) {
        if (!known.add(c.subject)) continue;
        items.add((
          drive: widget.drive,
          shown: '',
          subject: c.subject,
          title: c.name.isEmpty ? 'Untitled chat' : c.name,
          className: 'ai-chat',
          emoji: null
        ));
      }
      if (!mounted || kind != _model.kind) return items;
      final last = page.length < AssistantApi.chatsPageSize * 4;
      if (last) return items;
      // Show what there is, then go on reading.
      _model.ofKind = List.of(items);
      _model.changed();
    }
  }

  /// The same drive may be spelled `did:ad:x` or `atomic:x`.
  static String _id(String subject) =>
      subject.replaceFirst('did:ad:', '').replaceFirst('atomic:', '');

  /// `<class> · <drive name>`: every result says which drive it is in.
  String _detail(String className, String drive) {
    final id = _id(drive);
    final name = drive.isEmpty
        ? null
        : _model.drives
            .where((d) => _id(d.subject) == id)
            .map((d) => d.name)
            .firstOrNull;
    return [classLabel(className), if (name != null && name.isNotEmpty) name]
        .where((t) => t.isNotEmpty)
        .join(' · ');
  }

  /// Opens a resource, notes it as opened, and refreshes the list after.
  Future<void> _open(
      String drive, String subject, String title, String className) async {
    final opened = openFromList<void>(
      context,
      (_) => openResourceView(
          api: widget.api,
          drive: drive,
          subject: subject,
          title: title,
          className: className),
      subject: subject,
      // Noted once it is left: the lists do not move under the finger.
      onLeave: () {
        widget.api.noteOpened(drive, subject);
        noteDriveVisited(drive);
      },
    );
    widget.onOpened?.call();
    await opened;
    if (mounted) await _loadRecent(_model.drives);
  }

  @override
  void dispose() {
    _shell?.searchReset.removeListener(_startOver);
    _model.dispose();
    _hintKind.dispose();
    _text.dispose();
    _focus.dispose();
    super.dispose();
  }

  /// Whether a search is under way; a keystroke meanwhile only updates
  /// [_model.query], which is searched as soon as that one answers.
  bool _searching = false;

  /// When the field last changed, for the `search keystroke to results` mark.
  final Stopwatch _typed = Stopwatch();

  void _changed(String text) {
    _remember();
    final query = text.trim();
    if (query == _model.query) return;
    _model.query = query;
    if (query.isEmpty) {
      _model.hits = const [];
      _model.hitsFor = '';
      _model.changed();
      return;
    }
    _typed
      ..reset()
      ..start();
    // Searched at once, no debounce: the local store answers in a few ms.
    // One search at a time; what was typed meanwhile is searched next (only
    // the latest text). The list keeps what it shows until hits arrive.
    if (!_searching) unawaited(_search());
  }

  Future<void> _search() async {
    _searching = true;
    try {
      while (mounted && _model.query.isNotEmpty) {
        final query = _model.query;
        final scope = _model.scope;
        final kind = _model.kind;
        if (query == _model.hitsFor &&
            kind == _model.hitsKind &&
            _model.error == null) {
          break;
        }
        final asked = _typed.elapsedMilliseconds;
        try {
          // The kind is chosen in the index, before the result limit.
          final classes = kind.classes;
          final hits = classes.isEmpty
              ? await widget.api.search(query, drive: scope)
              : await widget.api
                  .searchClasses(query, drive: scope, classes: classes);
          if (!mounted) return;
          // Stale: the text, the drive or the kind changed while it ran. The
          // loop searches the new one.
          if (query != _model.query ||
              scope != _model.scope ||
              kind != _model.kind) {
            continue;
          }
          _model.hits = hits;
          _model.hitsFor = query;
          _model.hitsKind = kind;
          _model.error = null;
          _model.changed();
          if (!kReleaseMode) {
            Perf.span('search query', _typed.elapsedMilliseconds - asked);
            final typed = _typed;
            WidgetsBinding.instance.addPostFrameCallback((_) => Perf.span(
                'search keystroke to results', typed.elapsedMilliseconds));
          }
        } catch (e) {
          if (!mounted) return;
          if (query != _model.query ||
              scope != _model.scope ||
              kind != _model.kind) {
            continue;
          }
          _model.error = e;
          _model.hitsFor = query;
          _model.changed();
          break;
        }
      }
    } finally {
      _searching = false;
    }
  }

  /// What is listed, best first: the first one is shown nearest the field.
  List<_Item> get _items => _model.showsRecent && _model.kind != SearchKind.any
      ? (_model.ofKind ?? const [])
      : _model.showsRecent
          ? [
              for (final (:drive, resource: r) in _model.recent)
                (
                  drive: drive,
                  shown: drive,
                  subject: r.subject,
                  title: r.title,
                  className: r.className,
                  emoji: r.emoji
                )
            ]
          : [
              for (final h in _model.hits)
                // Searching in a drive, the drive itself is not a hit.
                if ((_model.scope == null ||
                        _id(h.subject) != _id(_model.scope!)) &&
                    _model.kind.matches(h.className))
                  (
                    drive: h.drive.isEmpty ? widget.drive : h.drive,
                    shown: h.drive,
                    subject: h.subject,
                    title: h.title,
                    className: h.className,
                    emoji: h.emoji
                  )
            ];

  /// Enter / the keyboard's search action opens the best hit.
  void _openBest() {
    final items = _items;
    if (items.isEmpty) return;
    final i = items.first;
    _open(i.drive, i.subject, i.title, i.className);
  }

  /// `In: <drive>` with a way back to every drive, while scoped; the kind
  /// looked for (`Drives`) with a way back to everything.
  Widget _scopeLabel(BuildContext context) {
    final scope = _model.scope;
    final kind = _model.kind;
    if (kind != SearchKind.any) {
      return _chip(context,
          key: const Key('search-kind'),
          text: kind.label,
          clear: 'Search everything',
          onClear: _clearKind);
    }
    if (scope == null) return const SizedBox.shrink();
    final name = _model.drives
            .where((d) => _id(d.subject) == _id(scope))
            .map((d) => d.name)
            .where((n) => n.isNotEmpty)
            .firstOrNull ??
        'this drive';
    return _chip(context,
        key: const Key('search-scope'),
        text: 'In: $name',
        clear: 'Search all drives',
        onClear: _clearScope);
  }

  Widget _chip(BuildContext context,
      {required Key key,
      required String text,
      required String clear,
      required VoidCallback onClear}) {
    final c = context.appColors;
    return Padding(
      padding: const EdgeInsets.only(left: 8),
      child: Container(
        key: key,
        padding: const EdgeInsets.only(left: 10),
        constraints: const BoxConstraints(maxWidth: 140),
        decoration: BoxDecoration(
          color: c.mainSelectedBg,
          borderRadius: BorderRadius.circular(9),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Flexible(
              child: Text(
                text,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: c.mainSelectedFg, fontSize: 12),
              ),
            ),
            IconButton(
              tooltip: clear,
              visualDensity: VisualDensity.compact,
              iconSize: 16,
              color: c.mainSelectedFg,
              onPressed: onClear,
              icon: const Icon(Icons.close),
            ),
          ],
        ),
      ),
    );
  }

  /// Below this height the page shows only the field (sideways with the
  /// keyboard up).
  static const _fieldRoom = 120.0;

  late final Widget _field = RepaintBoundary(
    child: SafeArea(
      top: false,
      child: Padding(
        // The palette: the same 12 dp above and below, 16 at the sides.
        padding: widget.palette
            ? const EdgeInsets.symmetric(horizontal: 16, vertical: 12)
            : const EdgeInsets.fromLTRB(16, 4, 12, 12),
        child: Row(
          children: [
            Expanded(
              child: Builder(builder: (context) {
                final c = context.appColors;
                // Only the hint follows the kind: typing rebuilds no field.
                return ValueListenableBuilder<SearchKind>(
                    valueListenable: _hintKind,
                    builder: (context, kind, _) => TextField(
                          controller: _text,
                          focusNode: _focus,
                          autofocus: true,
                          textInputAction: TextInputAction.search,
                          // Keeps the keyboard (and focus) after Enter.
                          onEditingComplete: () {},
                          onSubmitted: (_) => _openBest(),
                          onChanged: _changed,
                          decoration: InputDecoration(
                            hintText: kind.hint,
                            filled: true,
                            fillColor: c.bg1,
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(9),
                              borderSide: BorderSide.none,
                            ),
                          ),
                        ));
              }),
            ),
            ListenableBuilder(
              listenable: _model,
              builder: (context, _) => _scopeLabel(context),
            ),
          ],
        ),
      ),
    ),
  );

  Widget _results(BuildContext context) {
    final c = context.appColors;
    if (_model.error != null) {
      return Center(
          child: Text('${_model.error}', style: TextStyle(color: c.alert)));
    }
    final items = _items;
    if (items.isEmpty &&
        _model.query.isNotEmpty &&
        _model.hitsFor == _model.query) {
      return _nothingFound(c);
    }
    final heading = _model.showsRecent && items.isNotEmpty;
    final palette = widget.palette;
    return ListView.builder(
      // Best first, drawn from the bottom up: nearest the thumb. The palette
      // lists from its field on top down.
      reverse: !palette,
      padding: palette ? const EdgeInsets.symmetric(vertical: 8) : null,
      itemCount: items.length + (heading ? 1 : 0),
      itemBuilder: (context, i) {
        final n = palette ? (heading ? i - 1 : i) : i;
        if (n == items.length || n < 0) {
          return Padding(
            padding:
                EdgeInsets.fromLTRB(palette ? 24 : 16, palette ? 4 : 12, 16, 4),
            child: Text(_model.kind.heading,
                style: TextStyle(
                    color: c.textSecondary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600)),
          );
        }
        return _row(c, items[n], top: n == 0);
      },
    );
  }

  /// A query without hits: said where the first hit would be, just above
  /// the field, with the way to every drive while scoped.
  Widget _nothingFound(AppColors c) => Align(
        alignment:
            widget.palette ? Alignment.topCenter : Alignment.bottomCenter,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Nothing found for “${_model.query}”'
                '${_model.kind != SearchKind.any ? ' in ${_model.kind.label}' : _model.scope == null ? '' : ' in this drive'}',
                key: const Key('search-nothing-found'),
                textAlign: TextAlign.center,
                style: TextStyle(color: c.textSecondary),
              ),
              if (_model.scope != null)
                TextButton(
                  onPressed: _clearScope,
                  child: const Text('Search all drives'),
                ),
            ],
          ),
        ),
      );

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    // Built once per theme: typing and loading only rebuild the list.
    if (widget.palette) {
      return Material(
        color: c.bgBody,
        child: Column(children: [
          _field,
          Divider(
              height: 1, color: Theme.of(context).colorScheme.outlineVariant),
          Expanded(
            child: ListenableBuilder(
              listenable: _model,
              builder: (context, _) => _results(context),
            ),
          ),
        ]),
      );
    }
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppTopBar(
        title: 'Search',
        // In the sidebar next to the pages (no route to pop): back to the
        // home's list.
        leading: _shell != null &&
                _shell!.split &&
                !(ModalRoute.of(context)?.canPop ?? false)
            ? BackButton(onPressed: () => _shell!.showList(ShellPage.home))
            : null,
      ),
      body: SafeArea(
        top: false,
        bottom: false,
        child: ListAndField(
          minHeight: _fieldRoom,
          list: RepaintBoundary(
            child: ListenableBuilder(
              listenable: _model,
              builder: (context, _) => _results(context),
            ),
          ),
          field: _field,
        ),
      ),
    );
  }

  Widget _row(
    AppColors c,
    _Item i, {
    required bool top,
  }) {
    final row = ResourceRow(
      subject: i.subject,
      icon: iconForClass(i.className),
      emoji: i.emoji,
      title: i.title.isEmpty ? i.subject : i.title,
      detail: _detail(i.className, i.shown),
      onTap: () => _open(i.drive, i.subject, i.title, i.className),
      trailing: _isDrive(i.subject, i.className)
          ? IconButton(
              key: Key('search-in-drive-${i.subject}'),
              icon: const Icon(Icons.manage_search),
              tooltip: 'Search in ${i.title.isEmpty ? 'this drive' : i.title}',
              constraints: const BoxConstraints(minWidth: 48, minHeight: 48),
              onPressed: () => _searchInDrive(i.subject),
            )
          : null,
    );
    if (widget.palette) {
      // Every row at the same inset; the one Enter opens is filled, not
      // outlined (an outline moved its content).
      return Padding(
        key: top ? const Key('search-top-hit') : null,
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
        child: Material(
          color: top ? c.mainSelectedBg : Colors.transparent,
          borderRadius: BorderRadius.circular(9),
          clipBehavior: Clip.antiAlias,
          child: row,
        ),
      );
    }
    if (!top) return row;
    // The one Enter opens.
    return Container(
      key: const Key('search-top-hit'),
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        border: Border.all(color: c.main, width: 1.5),
        borderRadius: BorderRadius.circular(9),
      ),
      child: row,
    );
  }
}
