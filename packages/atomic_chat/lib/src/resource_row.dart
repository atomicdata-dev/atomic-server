import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColorsExt;
import 'package:flutter/material.dart';

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
    'class' || 'property' || 'ontology' => Icons.data_object,
    'formfield' || 'form' => Icons.input,
    'bookmark' => Icons.bookmark_border,
    'file' => Icons.insert_drive_file_outlined,
    'dashboard' => Icons.show_chart,
    'tag' => Icons.sell_outlined,
    _ => Icons.description_outlined,
  };
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

  const ResourceRow({
    super.key,
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

  @override
  Widget build(BuildContext context) => ListTile(
        leading: _leading(context),
        title: Text(title, maxLines: 1, overflow: TextOverflow.ellipsis),
        subtitle: detail == null || detail!.isEmpty ? null : Text(detail!),
        // A plain list of titles reads better tight.
        visualDensity: detail == null && icon == null && !_hasEmoji
            ? VisualDensity.compact
            : VisualDensity.standard,
        trailing: trailing,
        onTap: onTap,
      );
}
