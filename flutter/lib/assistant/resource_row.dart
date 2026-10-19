import 'package:flutter/material.dart';

import '../theme.dart';

/// One line of a list of resources: icon, title, a line of detail.
class ResourceRow extends StatelessWidget {
  final IconData? icon;
  final String title;
  final String? detail;
  final VoidCallback onTap;

  const ResourceRow({
    super.key,
    this.icon,
    required this.title,
    this.detail,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) => ListTile(
    leading: icon == null ? null : Icon(icon, color: context.appColors.main),
    title: Text(title, maxLines: 1, overflow: TextOverflow.ellipsis),
    subtitle: detail == null || detail!.isEmpty ? null : Text(detail!),
    onTap: onTap,
  );
}
