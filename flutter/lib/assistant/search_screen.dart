import 'dart:async';

import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../theme.dart';
import '../widgets/slide_back_route.dart';
import 'assistant_api.dart';
import 'resource_row.dart';
import 'native_views.dart';

/// Type-ahead search over every drive; a hit opens in its own drive. [drive]
/// is only the fallback for what has no drive of its own.
class SearchScreen extends StatefulWidget {
  final AssistantApi api;
  final String drive;

  const SearchScreen({
    super.key,
    required this.drive,
    this.api = const AssistantApi(),
  });

  @override
  State<SearchScreen> createState() => _SearchScreenState();
}

class _SearchScreenState extends State<SearchScreen> {
  Timer? _debounce;
  List<SearchHit> _hits = const [];
  List<DriveInfo> _drives = const [];
  Object? _error;
  String _query = '';

  /// What was opened lately: the list while nothing is typed.
  List<({String drive, RecentResource resource})> _recent = const [];

  @override
  void initState() {
    super.initState();
    _loadRecent();
    _loadDrives();
  }

  Future<void> _loadDrives() async {
    try {
      final drives = await widget.api.drives();
      if (mounted) setState(() => _drives = drives);
    } catch (_) {
      // Only names for the rows.
    }
  }

  /// The same drive may be spelled `did:ad:x` or `atomic:x`.
  static String _id(String subject) =>
      subject.replaceFirst('did:ad:', '').replaceFirst('atomic:', '');

  /// "<class> · <drive name>": every result says which drive it is in.
  String _detail(String className, String drive) {
    final id = _id(drive);
    final name = drive.isEmpty
        ? null
        : _drives
            .where((d) => _id(d.subject) == id)
            .map((d) => d.name)
            .firstOrNull;
    return [className, if (name != null && name.isNotEmpty) name]
        .where((t) => t.isNotEmpty)
        .join(' · ');
  }

  Future<void> _loadRecent() async {
    try {
      var drives = [for (final d in await widget.api.drives()) d.subject];
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
      if (mounted) setState(() => _recent = merged.take(20).toList());
    } catch (_) {
      // Only a convenience: the search itself still works.
    }
  }

  /// Opens a resource, notes it as opened, and refreshes the list after.
  Future<void> _open(
      String drive, String subject, String title, String className) async {
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
    if (mounted) await _loadRecent();
  }

  @override
  void dispose() {
    _debounce?.cancel();
    super.dispose();
  }

  void _changed(String text) {
    _debounce?.cancel();
    _query = text.trim();
    if (_query.isEmpty) {
      setState(() => _hits = const []);
      return;
    }
    _debounce = Timer(const Duration(milliseconds: 200), () async {
      final asked = _query;
      try {
        final hits = await widget.api.search(asked);
        if (mounted && asked == _query) {
          setState(() {
            _hits = hits;
            _error = null;
          });
        }
      } catch (e) {
        if (mounted && asked == _query) setState(() => _error = e);
      }
    });
  }

  /// What is listed, best first: the first one is shown nearest the field.
  List<({String drive, String shown, String subject, String title, String className})>
      get _items => _query.isEmpty
          ? [
              for (final (:drive, resource: r) in _recent)
                (
                  drive: drive,
                  shown: drive,
                  subject: r.subject,
                  title: r.title,
                  className: r.className
                )
            ]
          : [
              for (final h in _hits)
                (
                  drive: h.drive.isEmpty ? widget.drive : h.drive,
                  shown: h.drive,
                  subject: h.subject,
                  title: h.title,
                  className: h.className
                )
            ];

  /// Enter / the keyboard's search action opens the best hit.
  void _openBest() {
    final items = _items;
    if (items.isEmpty) return;
    final i = items.first;
    _open(i.drive, i.subject, i.title, i.className);
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final items = _items;
    final results = _error != null
        ? Center(child: Text('$_error', style: TextStyle(color: c.alert)))
        : ListView(
            // Best first, drawn from the bottom up: nearest the thumb.
            reverse: true,
            children: [
              for (var n = 0; n < items.length; n++)
                _row(c, items[n], top: n == 0),
              if (_query.isEmpty && _recent.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
                  child: Text('Recently opened',
                      style: TextStyle(
                          color: c.textSecondary,
                          fontSize: 13,
                          fontWeight: FontWeight.w600)),
                ),
            ],
          );
    return Scaffold(
      backgroundColor: c.bgBody,
      body: SafeArea(
        bottom: false,
        child: Column(
          children: [
            Expanded(child: results),
            SafeArea(
              top: false,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(12, 4, 12, 12),
                child: Row(
                  children: [
                    IconButton(
                      tooltip: 'Back',
                      icon: const Icon(Icons.arrow_back),
                      onPressed: () {
                        // Straight back, even with the keyboard open.
                        FocusManager.instance.primaryFocus?.unfocus();
                        Navigator.of(context).pop();
                      },
                    ),
                    Expanded(
                      child: TextField(
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
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _row(
    AppColors c,
    ({
      String drive,
      String shown,
      String subject,
      String title,
      String className
    }) i, {
    required bool top,
  }) {
    final row = ResourceRow(
      icon: Icons.description_outlined,
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
