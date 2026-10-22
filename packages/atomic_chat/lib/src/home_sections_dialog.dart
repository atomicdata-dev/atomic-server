import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt;
import 'package:flutter/material.dart';

import 'home_sections.dart';

/// The icon of a Home section.
IconData homeSectionIcon(HomeSection s) => switch (s) {
      HomeSection.notifications => Icons.notifications_none,
      HomeSection.drives => Icons.folder_outlined,
      HomeSection.activity => Icons.bolt_outlined,
      HomeSection.chats => Icons.chat_bubble_outline,
      HomeSection.favorites => Icons.star_border,
      HomeSection.messages => Icons.forum_outlined,
    };

/// Opens "Home sections": a checkbox per section to show or hide it, and
/// drag handles to arrange them. Every change goes to [onChanged] at once.
/// A bottom sheet on a phone, a centred dialog (at most 420 dp wide) when
/// [split].
Future<void> showHomeSectionsDialog(
  BuildContext context, {
  required HomeLayout Function() layout,
  required ValueChanged<HomeLayout> onChanged,
  required bool split,
}) {
  final body = _HomeSectionsBody(initial: layout(), onChanged: onChanged);
  if (split) {
    return showDialog<void>(
      context: context,
      builder: (_) => Dialog(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: body,
        ),
      ),
    );
  }
  return showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    useSafeArea: true,
    builder: (_) => body,
  );
}

class _HomeSectionsBody extends StatefulWidget {
  final HomeLayout initial;
  final ValueChanged<HomeLayout> onChanged;
  const _HomeSectionsBody({required this.initial, required this.onChanged});

  @override
  State<_HomeSectionsBody> createState() => _HomeSectionsBodyState();
}

class _HomeSectionsBodyState extends State<_HomeSectionsBody> {
  late HomeLayout _layout = widget.initial;

  void _set(HomeLayout l) {
    setState(() => _layout = l);
    widget.onChanged(l);
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return SafeArea(
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        SizedBox(
          height: 56,
          child: Row(children: [
            const SizedBox(width: 16),
            Expanded(
              child: Text('Home sections',
                  style: TextStyle(
                      color: c.textPrimary,
                      fontSize: 18,
                      fontWeight: FontWeight.w600)),
            ),
            TextButton(
              onPressed: () => _set(_layout.reset()),
              child: const Text('Reset to default'),
            ),
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Done'),
            ),
            const SizedBox(width: 8),
          ]),
        ),
        Flexible(
          child: ReorderableListView(
            shrinkWrap: true,
            buildDefaultDragHandles: false,
            onReorderItem: (a, b) => _set(_layout.reorder(a, b)),
            children: [
              for (var i = 0; i < _layout.order.length; i++)
                _row(_layout.order[i], i, c),
            ],
          ),
        ),
      ]),
    );
  }

  Widget _row(HomeSection s, int index, AppColors c) {
    final on = !_layout.hidden.contains(s);
    return ReorderableDelayedDragStartListener(
      key: ValueKey('home-section-${s.name}'),
      index: index,
      child: SizedBox(
        height: 48,
        child: InkWell(
          mouseCursor: WidgetStateMouseCursor.clickable,
          onTap: () => _set(_layout.setHidden(s, on)),
          child: Row(children: [
            const SizedBox(width: 8),
            Checkbox(
              value: on,
              onChanged: (v) => _set(_layout.setHidden(s, !(v ?? false))),
            ),
            Icon(homeSectionIcon(s), size: 22, color: c.textSecondary),
            const SizedBox(width: 12),
            Expanded(
              child: Text(s.title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(color: c.textPrimary, fontSize: 15)),
            ),
            ReorderableDragStartListener(
              index: index,
              child: MouseRegion(
                cursor: SystemMouseCursors.grab,
                child: SizedBox(
                  width: 48,
                  height: 48,
                  child: Icon(Icons.drag_handle, color: c.textSecondary),
                ),
              ),
            ),
            const SizedBox(width: 8),
          ]),
        ),
      ),
    );
  }
}
