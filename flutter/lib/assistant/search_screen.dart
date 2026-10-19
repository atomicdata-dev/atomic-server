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
  List<RecentResource> _recent = const [];

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
      final recent = await widget.api.recentResources(widget.drive);
      if (mounted) setState(() => _recent = recent);
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

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppBar(
        backgroundColor: c.bgBody,
        title: TextField(
          autofocus: true,
          decoration: const InputDecoration(
            hintText: 'Search',
            border: InputBorder.none,
          ),
          onChanged: _changed,
        ),
      ),
      body: _error != null
          ? Center(
              child: Text('$_error', style: TextStyle(color: c.alert)),
            )
          : ListView(
              children: [
                if (_query.isEmpty && _recent.isNotEmpty) ...[
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
                    child: Text('Recently opened',
                        style: TextStyle(
                            color: c.textSecondary,
                            fontSize: 13,
                            fontWeight: FontWeight.w600)),
                  ),
                  for (final r in _recent)
                    ResourceRow(
                      icon: Icons.description_outlined,
                      title: r.title.isEmpty ? r.subject : r.title,
                      detail: r.className,
                      onTap: () =>
                          _open(widget.drive, r.subject, r.title, r.className),
                    ),
                ],
                for (final hit in _hits)
                  ResourceRow(
                    icon: Icons.description_outlined,
                    title: hit.title.isEmpty ? hit.subject : hit.title,
                    detail: _detail(hit.className, hit.drive),
                    onTap: () => _open(
                        hit.drive.isEmpty ? widget.drive : hit.drive,
                        hit.subject,
                        hit.title,
                        hit.className),
                  ),
              ],
            ),
    );
  }
}
