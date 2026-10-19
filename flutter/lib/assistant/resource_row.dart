import 'package:flutter/material.dart';

import '../theme.dart';

/// One line of a list of resources: an icon if it has one, a title, a line of
/// detail.
class ResourceRow extends StatelessWidget {
  final IconData? icon;
  final String title;
  final String? detail;

  /// Null for a row that is only information.
  final VoidCallback? onTap;

  const ResourceRow({
    super.key,
    this.icon,
    required this.title,
    this.detail,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) => ListTile(
        leading:
            icon == null ? null : Icon(icon, color: context.appColors.main),
        title: Text(title, maxLines: 1, overflow: TextOverflow.ellipsis),
        subtitle: detail == null || detail!.isEmpty ? null : Text(detail!),
        // A plain list of titles reads better tight.
        visualDensity: detail == null && icon == null
            ? VisualDensity.compact
            : VisualDensity.standard,
        onTap: onTap,
      );
}
