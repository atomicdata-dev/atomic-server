import 'dart:convert';

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt;
import 'package:flutter/material.dart';

import 'chat_parts.dart';
import 'chat_text_styles.dart';

String _cut(String s, int max) =>
    s.length <= max ? s : '${s.substring(0, max - 1)}…';

String? _str(Object? input, String key) {
  if (input is! Map) return null;
  final v = input[key];
  return v is String && v.trim().isNotEmpty ? v.trim() : null;
}

/// What a tool call does, in words, as the web app says it: `semantic_search`
/// with the model's own description of the search, `get_atomic_resource`
/// with the titles of what it reads (from [titles], subject to title, when
/// known), and so on. Any other tool: its name.
String toolLabel(ToolPart p, {Map<String, String> titles = const {}}) {
  final input = p.input;
  final running = p.state.running;
  switch (p.toolName) {
    case 'semantic_search':
      final description = _str(input, 'description');
      if (description != null) return description;
      final query = _str(input, 'query');
      return query == null
          ? (running ? 'Searching your drives' : 'Searched your drives')
          : '${running ? 'Searching' : 'Searched'} your drives for '
              '“${_cut(query, 40)}”';
    case 'query':
      return _str(input, 'description') ??
          (running ? 'Querying your data' : 'Queried your data');
    case 'get_atomic_resource':
      final subjects = input is Map && input['subjects'] is List
          ? [for (final s in input['subjects'] as List) '$s']
          : const <String>[];
      final named = [
        for (final s in subjects)
          if (titles[s] != null) _cut(titles[s]!, 20),
      ];
      final verb = running ? 'Reading' : 'Read';
      if (named.length == subjects.length && named.isNotEmpty) {
        return '$verb ${named.join(', ')}';
      }
      return subjects.length > 1
          ? '$verb ${subjects.length} resources'
          : '$verb a resource';
    case 'read_file_resource':
      return running ? 'Reading a file' : 'Read a file';
    case 'web_search_exa':
      return running ? 'Searching online' : 'Searched online';
    case 'edit_atomic_resource':
    case 'edit_document_resource':
      return running ? 'Editing a resource' : 'Edited a resource';
    case 'get_schema':
      return 'Reading schema';
    case 'find_schema':
      return 'Searching schemas';
    case 'ensure_ontology':
      return 'Saving schema';
    case 'create_resource':
      final name = _createdName(input);
      return '${running ? 'Creating' : 'Created'} ${name ?? 'a resource'}';
    case 'create_table':
      final name = _str(input, 'name');
      return '${running ? 'Creating' : 'Created'} table${name == null ? '' : ' $name'}';
    case 'read_skill':
    case 'read_skill_reference':
      final name = _str(input, 'name');
      return 'Loading skill${name == null ? '' : ': $name'}';
    case 'delete_resource':
      return running ? 'Deleting a resource' : 'Deleted a resource';
    case 'favorite_resource':
      return 'Toggling favorite';
    case 'navigate_to_resource':
      return 'Opening a resource';
    case 'open_share_settings':
      return 'Opening share settings';
    case 'show_history':
      return 'Opening history';
  }
  final name = p.toolName.replaceAll('_', ' ');
  return running ? 'Using tool $name' : 'Used tool $name';
}

String? _createdName(Object? input) {
  final raw = _str(input, 'jsonAD');
  if (raw == null) return null;
  try {
    final v = jsonDecode(raw);
    if (v is List) return '${v.length} resources';
    if (v is Map) {
      final name = v['name'] ?? v['shortname'];
      if (name is String && name.isNotEmpty) return name;
    }
  } catch (_) {}
  return null;
}

IconData _toolIcon(String name) => switch (name) {
      'semantic_search' || 'find_schema' => Icons.search,
      'query' => Icons.storage_outlined,
      'get_atomic_resource' ||
      'read_file_resource' =>
        Icons.visibility_outlined,
      'web_search_exa' => Icons.public,
      'edit_atomic_resource' || 'edit_document_resource' => Icons.edit_outlined,
      'get_schema' ||
      'read_skill' ||
      'read_skill_reference' =>
        Icons.menu_book_outlined,
      'create_resource' || 'create_table' || 'ensure_ontology' => Icons.add,
      _ => Icons.build_outlined,
    };

/// What a finished call returned, in a line: the number of hits of a search,
/// what was read, else the start of its result.
String toolResultSummary(ToolPart p, {Map<String, String> titles = const {}}) {
  if (p.state == ToolState.outputError) return p.errorText ?? 'Failed';
  final out = p.output;
  if (p.toolName == 'semantic_search' && out is List) {
    if (out.isEmpty) return 'No results';
    final names = [
      for (final h in out)
        if (h is Map && h['title'] is String) h['title'] as String,
    ];
    return '${out.length} result${out.length == 1 ? '' : 's'}'
        '${names.isEmpty ? '' : ': ${names.take(5).join(', ')}'}'
        '${names.length > 5 ? '…' : ''}';
  }
  if (p.toolName == 'get_atomic_resource' && out is Map) {
    return 'Read ${out.length} resource${out.length == 1 ? '' : 's'}';
  }
  if (out == null) return 'Done';
  if (out is String) return _cut(out, 300);
  return _cut(const JsonEncoder.withIndent('  ').convert(out), 600);
}

/// Titles of resources a message's tool calls found (search hits), by
/// subject: to name what a later call reads.
Map<String, String> toolTitles(Iterable<ChatPart> parts) => {
      for (final p in parts)
        if (p is ToolPart && p.output is List)
          for (final h in p.output as List)
            if (h is Map && h['subject'] is String && h['title'] is String)
              h['subject'] as String: h['title'] as String,
    };

/// One tool call of an answer, as a compact row: what it does, with a
/// spinner while it runs and a check or a cross after. A tap opens what
/// it was given and a short summary of its result.
class ToolStepRow extends StatefulWidget {
  final ToolPart part;
  final Map<String, String> titles;

  const ToolStepRow(this.part, {super.key, this.titles = const {}});

  @override
  State<ToolStepRow> createState() => _ToolStepRowState();
}

class _ToolStepRowState extends State<ToolStepRow> {
  bool _open = false;

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final p = widget.part;
    final running = p.state.running;
    final failed = p.state == ToolState.outputError;
    final label = toolLabel(p, titles: widget.titles);
    final small = ChatTextStyles.of(context).status;
    final Widget status = running
        ? SizedBox(
            width: 14,
            height: 14,
            child: CircularProgressIndicator(
              strokeWidth: 1.6,
              color: c.textSecondary,
            ),
          )
        : Icon(
            failed ? Icons.close_rounded : Icons.check_rounded,
            size: 16,
            color: failed ? c.alert : c.success,
          );
    return Semantics(
      button: true,
      expanded: _open,
      label: '$label, ${running ? 'running' : failed ? 'failed' : 'done'}',
      excludeSemantics: true,
      child: Material(
        type: MaterialType.transparency,
        child: InkWell(
          key: Key('tool-step-${p.toolCallId}'),
          borderRadius: BorderRadius.circular(6),
          onTap: () => setState(() => _open = !_open),
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 4),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Row(
                  children: [
                    Icon(_toolIcon(p.toolName),
                        size: 15, color: c.textSecondary),
                    const SizedBox(width: 8),
                    Flexible(
                      child: Text(
                        running ? '$label…' : label,
                        maxLines: _open ? 4 : 1,
                        overflow: TextOverflow.ellipsis,
                        style: small,
                      ),
                    ),
                    const SizedBox(width: 6),
                    status,
                    Icon(
                      _open ? Icons.expand_less : Icons.expand_more,
                      size: 16,
                      color: c.textSecondary,
                    ),
                  ],
                ),
                if (_open) _details(c, small),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _details(AppColors c, TextStyle small) {
    final p = widget.part;
    final input = p.input;
    final mono = ChatTextStyles.of(context).statusMono;
    String args;
    try {
      args = const JsonEncoder.withIndent('  ').convert(input ?? const {});
    } catch (_) {
      args = '$input';
    }
    return Padding(
      padding: const EdgeInsets.only(left: 23, top: 4, bottom: 2),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: c.surface,
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: c.border),
        ),
        child: SelectionArea(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text('Tool: ${p.toolName}',
                  style: small.copyWith(fontSize: ChatTextStyles.metaSize)),
              const SizedBox(height: 4),
              Text(_cut(args, 800), style: mono),
              if (!p.state.running) ...[
                const SizedBox(height: 6),
                Text(
                  toolResultSummary(p, titles: widget.titles),
                  key: Key('tool-result-${p.toolCallId}'),
                  style: small.copyWith(
                    fontSize: ChatTextStyles.metaSize,
                    color: p.state == ToolState.outputError
                        ? c.alert
                        : c.textSecondary,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
