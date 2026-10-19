import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt;
import 'package:flutter/material.dart';
import 'app_top_bar.dart';

import 'models.dart';
import 'covered_insets_freeze.dart';
import 'slide_back_route.dart';
import 'app_shell.dart';
import 'assistant_api.dart';
import 'resource_row.dart';
import 'native_views.dart';

/// Type-ahead search over every drive; a hit opens in its own drive. [drive]
/// is only the fallback for what has no drive of its own.
///
/// With [scopeDrive] it searches that drive only (and lists only its recently
/// opened resources), said next to the field with a way back to every drive.
/// The scope belongs to this opening of the screen.
class SearchScreen extends StatefulWidget {
  final AssistantApi api;
  final String drive;
  final String? scopeDrive;

  const SearchScreen({
    super.key,
    required this.drive,
    required this.api,
    this.scopeDrive,
  });

  /// A quick fade and short rise instead of the page slide: the keyboard rises
  /// at the same time, and a long slide on top of it feels slow.
  static Route<void> route({
    required String drive,
    required AssistantApi api,
    String? scopeDrive,
    RouteSettings? settings,
  }) =>
      PageRouteBuilder<void>(
        settings: settings,
        pageBuilder: (_, __, ___) => CoveredInsetsFreeze(
            child:
                SearchScreen(drive: drive, api: api, scopeDrive: scopeDrive)),
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

  /// The one drive searched, or null for all of them.
  String? scope;

  void changed() => notifyListeners();
}

class _SearchScreenState extends State<SearchScreen> {
  final _SearchModel _model = _SearchModel();
  Timer? _debounce;
  ShellController? _shell;

  @override
  void initState() {
    super.initState();
    _shell = ShellScope.maybeOf(context);
    _model.scope = widget.scopeDrive;
    final cache = _shell?.searchCache;
    if (cache != null) {
      _model.drives = cache.drives;
      _model.recent = _inScope(cache.recent);
    }
    _load();
  }

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
    final route = ModalRoute.of(context);
    if (route != null) _shell?.setKind(route, ShellPage.search);
    final query = _model.query;
    _model.query = '';
    _model.hits = const [];
    _model.changed();
    _loadRecent(_model.drives);
    if (query.isNotEmpty) _changed(query);
  }

  /// A drive in the results is a filter, not a page: the search goes on
  /// inside it. True when [subject] was taken as such.
  bool _scopeToDrive(String subject, String className) {
    final isDrive = className.split(RegExp(r'[/#]')).last == 'Drive' ||
        _model.drives.any((d) => _id(d.subject) == _id(subject));
    if (!isDrive || subject.isEmpty) return false;
    if (_model.scope != null && _id(_model.scope!) == _id(subject)) {
      return true;
    }
    _model.scope = subject;
    final route = ModalRoute.of(context);
    if (route != null) _shell?.setKind(route, ShellPage.search);
    final query = _model.query;
    _model.query = '';
    _model.hits = const [];
    _model.recent = _inScope(_model.recent);
    _model.changed();
    _loadRecent(_model.drives);
    if (query.isNotEmpty) _changed(query);
    return true;
  }

  /// One drives call for both the names and the recents; it paints the cached
  /// list first and refreshes behind it.
  Future<void> _load() async {
    try {
      final drives = await widget.api.drives();
      if (!mounted) return;
      _model.drives = drives;
      _model.changed();
      await _loadRecent(drives);
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
    if (_scopeToDrive(subject, className)) return;
    widget.api.noteOpened(drive, subject);
    await Navigator.of(context).push(
      SlideBackRoute<void>(
        builder: (_) => openResourceView(
            api: widget.api,
            drive: drive,
            subject: subject,
            title: title,
            className: className),
      ),
    );
    if (mounted) await _loadRecent(_model.drives);
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _model.dispose();
    super.dispose();
  }

  void _changed(String text) {
    _debounce?.cancel();
    final query = text.trim();
    if (query == _model.query) return;
    _model.query = query;
    if (query.isEmpty) {
      _model.hits = const [];
      _model.changed();
      return;
    }
    // Typing flips the list from recents to hits once; the debounce then only
    // swaps the hits.
    _model.changed();
    _debounce = Timer(const Duration(milliseconds: 120), () async {
      try {
        final scope = _model.scope;
        final hits = await widget.api.search(query, drive: scope);
        if (scope != _model.scope) return;
        if (mounted && query == _model.query) {
          _model.hits = hits;
          _model.error = null;
          _model.changed();
        }
      } catch (e) {
        if (mounted && query == _model.query) {
          _model.error = e;
          _model.changed();
        }
      }
    });
  }

  /// What is listed, best first: the first one is shown nearest the field.
  List<_Item> get _items => _model.query.isEmpty
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

  /// `In: <drive>` with a way back to every drive, while scoped.
  Widget _scopeLabel(BuildContext context) {
    final scope = _model.scope;
    if (scope == null) return const SizedBox.shrink();
    final c = context.appColors;
    final name = _model.drives
            .where((d) => _id(d.subject) == _id(scope))
            .map((d) => d.name)
            .where((n) => n.isNotEmpty)
            .firstOrNull ??
        'this drive';
    return Padding(
      padding: const EdgeInsets.only(left: 8),
      child: Container(
        key: const Key('search-scope'),
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
                'In: $name',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: c.mainSelectedFg, fontSize: 12),
              ),
            ),
            IconButton(
              tooltip: 'Search all drives',
              visualDensity: VisualDensity.compact,
              iconSize: 16,
              color: c.mainSelectedFg,
              onPressed: _clearScope,
              icon: const Icon(Icons.close),
            ),
          ],
        ),
      ),
    );
  }

  late final Widget _field = RepaintBoundary(
    child: SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 4, 12, 12),
        child: Row(
          children: [
            Expanded(
              child: Builder(builder: (context) {
                final c = context.appColors;
                return TextField(
                  autofocus: true,
                  textInputAction: TextInputAction.search,
                  // Keeps the keyboard (and focus) after Enter.
                  onEditingComplete: () {},
                  onSubmitted: (_) => _openBest(),
                  onChanged: _changed,
                  decoration: InputDecoration(
                    hintText: 'Search',
                    filled: true,
                    fillColor: c.bg1,
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(9),
                      borderSide: BorderSide.none,
                    ),
                  ),
                );
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
    final heading = _model.query.isEmpty && _model.recent.isNotEmpty;
    return ListView.builder(
      // Best first, drawn from the bottom up: nearest the thumb.
      reverse: true,
      itemCount: items.length + (heading ? 1 : 0),
      itemBuilder: (context, n) {
        if (n == items.length) {
          return Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
            child: Text('Recently opened',
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

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    // Built once per theme: typing and loading only rebuild the list.
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: const AppTopBar(title: 'Search'),
      body: SafeArea(
        top: false,
        bottom: false,
        child: Column(
          children: [
            Expanded(
              child: RepaintBoundary(
                child: ListenableBuilder(
                  listenable: _model,
                  builder: (context, _) => _results(context),
                ),
              ),
            ),
            _field,
          ],
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
      icon: iconForClass(i.className),
      emoji: i.emoji,
      title: i.title.isEmpty ? i.subject : i.title,
      detail: _detail(i.className, i.shown),
      onTap: () => _open(i.drive, i.subject, i.title, i.className),
    );
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
