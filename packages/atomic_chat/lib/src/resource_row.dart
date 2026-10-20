import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/material.dart';

import 'app_shell.dart';

/// The icon of a class, by the class's name as the rows carry it (the class's
/// own name, or the last part of its subject), as the web app's
/// `getIconForClass` does. [Icons.description_outlined] for the rest.
IconData iconForClass(String className) {
  final key = className
      .split('/')
      .last
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9]'), '');
  return switch (key) {
    'folder' || 'drive' => Icons.folder_outlined,
    'table' => Icons.table_chart_outlined,
    'canvas' => Icons.draw_outlined,
    'aichat' || 'conversation' || 'chatroom' => Icons.chat_bubble_outline,
    'meeting' => Icons.videocam_outlined,
    'class' || 'property' || 'ontology' => Icons.data_object,
    'formfield' || 'form' => Icons.input,
    'bookmark' => Icons.bookmark_border,
    'file' => Icons.insert_drive_file_outlined,
    'dashboard' => Icons.show_chart,
    'tag' => Icons.sell_outlined,
    _ => Icons.description_outlined,
  };
}

const _classLabels = {
  'document': 'Document',
  'documentv2': 'Document',
  'table': 'Table',
  'folder': 'Folder',
  'drive': 'Drive',
  'chatroom': 'Chat',
  'conversation': 'Chat',
  'meeting': 'Meeting',
  'aichat': 'AI chat',
  'chatlog': 'AI chat',
  'canvas': 'Canvas',
  'bookmark': 'Bookmark',
  'file': 'File',
  'dashboard': 'Dashboard',
  'tag': 'Tag',
  'class': 'Class',
  'property': 'Property',
  'ontology': 'Ontology',
  'formfield': 'Form field',
  'form': 'Form',
  'message': 'Message',
  'article': 'Article',
  'agent': 'Agent',
};

/// A class as a person reads it: [className] is a shortname (`document-v2`)
/// or a class URL; a known class gets its label (`Document`), any other the
/// shortname without a version suffix, hyphens and underscores as spaces and
/// a capital (`web-page-v3` -> `Web page`).
String classLabel(String className) {
  var name = className
          .trim()
          .split(RegExp(r'[/#]'))
          .where((p) => p.isNotEmpty)
          .lastOrNull ??
      '';
  if (name.isEmpty) return '';
  final known =
      _classLabels[name.toLowerCase().replaceAll(RegExp(r'[^a-z0-9]'), '')];
  if (known != null) return known;
  name = name
      .replaceFirst(RegExp(r'[-_ ]?v\d+$', caseSensitive: false), '')
      .replaceAll(RegExp(r'[-_]+'), ' ')
      .replaceAllMapped(RegExp(r'([a-z0-9])([A-Z])'), (m) => '${m[1]} ${m[2]}')
      .trim()
      .toLowerCase();
  return name.isEmpty ? '' : name[0].toUpperCase() + name.substring(1);
}

/// One line of a list of resources: the resource's own [emoji] or else an icon
/// if it has one, a title, a line of detail.
class ResourceRow extends StatelessWidget {
  final IconData? icon;

  /// The resource's own icon; shown instead of [icon] when set.
  final String? emoji;
  final String title;
  final String? detail;

  /// Null for a row that is only information.
  final VoidCallback? onTap;

  /// Shown at the end of the line, e.g. a check mark for a selected row.
  final Widget? trailing;

  /// What the row opens. Next to the detail pane (the split layout of the
  /// shell) the row is marked while that is the resource shown there.
  final String? subject;

  const ResourceRow({
    super.key,
    this.subject,
    this.icon,
    this.emoji,
    required this.title,
    this.detail,
    this.onTap,
    this.trailing,
  });

  bool get _hasEmoji => emoji != null && emoji!.isNotEmpty;

  /// The icon's box is 24 px either way, so rows line up.
  Widget? _leading(BuildContext context) {
    if (_hasEmoji) {
      return SizedBox(
        width: 24,
        height: 24,
        child: Center(
          child: Text(
            emoji!,
            key: const Key('resource-emoji'),
            style: const TextStyle(fontSize: 20, height: 1),
          ),
        ),
      );
    }
    return icon == null ? null : Icon(icon, color: context.appColors.main);
  }

  Widget _tile(BuildContext context, {bool selected = false}) {
    final c = context.appColors;
    return ListTile(
      leading: _leading(context),
      title: Text(title, maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: detail == null || detail!.isEmpty ? null : Text(detail!),
      // A plain list of titles reads better tight.
      visualDensity: detail == null && icon == null && !_hasEmoji
          ? VisualDensity.compact
          : VisualDensity.standard,
      trailing: trailing,
      selected: selected,
      selectedTileColor: c.mainSelectedBg,
      selectedColor: c.mainSelectedFg,
      onTap: onTap,
    );
  }

  @override
  Widget build(BuildContext context) {
    final subject = this.subject;
    final shell = ShellScope.maybeOf(context);
    final Widget row;
    if (subject == null ||
        shell == null ||
        ShellScope.layoutOf(context) != ShellLayout.split) {
      row = _tile(context);
    } else {
      row = ValueListenableBuilder<String?>(
        valueListenable: shell.selected,
        builder: (context, selected, _) =>
            _tile(context, selected: selected == subject),
      );
    }
    final warm = shell?.warm;
    if (subject == null || onTap == null || warm == null) return row;
    // The page's first read starts as the finger goes down, not after the
    // tap and the page's first frame (a scroll just leaves it unused).
    return Listener(
      onPointerDown: (_) => warm.prefetch(subject),
      child: row,
    );
  }
}
