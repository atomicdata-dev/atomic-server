import 'dart:async';

import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../theme.dart';
import '../widgets/slide_back_route.dart';
import 'assistant_api.dart';
import 'resource_row.dart';
import 'resource_view.dart';

/// Type-ahead search over [drive]; a hit opens in the web view.
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
  Object? _error;
  String _query = '';

  /// What was opened lately: the list while nothing is typed.
  List<RecentResource> _recent = const [];

  @override
  void initState() {
    super.initState();
    _loadRecent();
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
  Future<void> _open(String subject, String title) async {
    widget.api.noteOpened(widget.drive, subject);
    await Navigator.of(context).push(
      SlideBackRoute<void>(
        builder: (_) => ResourceView(subject: subject, title: title),
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
        final hits = await widget.api.search(widget.drive, asked);
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
                      onTap: () => _open(r.subject, r.title),
                    ),
                ],
                for (final hit in _hits)
                  ResourceRow(
                    icon: Icons.description_outlined,
                    title: hit.title.isEmpty ? hit.subject : hit.title,
                    detail: hit.className,
                    onTap: () => _open(hit.subject, hit.title),
                  ),
              ],
            ),
    );
  }
}
