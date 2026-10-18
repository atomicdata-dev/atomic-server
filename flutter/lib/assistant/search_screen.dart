import 'dart:async';

import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../theme.dart';
import 'assistant_api.dart';
import 'resource_web_view.dart';

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
              hintText: 'Search', border: InputBorder.none),
          onChanged: _changed,
        ),
      ),
      body: _error != null
          ? Center(child: Text('$_error', style: TextStyle(color: c.alert)))
          : ListView(children: [
              for (final hit in _hits)
                ListTile(
                  leading: Icon(Icons.description_outlined, color: c.main),
                  title: Text(hit.title.isEmpty ? hit.subject : hit.title,
                      maxLines: 1, overflow: TextOverflow.ellipsis),
                  subtitle: hit.className.isEmpty ? null : Text(hit.className),
                  onTap: () {
                    widget.api.noteOpened(widget.drive, hit.subject);
                    Navigator.of(context).push(MaterialPageRoute<void>(
                      builder: (_) => ResourceWebView(
                          api: widget.api,
                          subject: hit.subject,
                          title: hit.title),
                    ));
                  },
                ),
            ]),
    );
  }
}
