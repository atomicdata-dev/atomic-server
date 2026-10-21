import 'dart:async';
import 'dart:math' as math;

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColorsExt, ErrorText, SectionHeaderStyle;
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_api.dart';
import 'models.dart';
import 'app_sidebar_icons.dart';
import 'resource_row.dart';
import 'row_leading.dart';

/// Below this width the drive switcher is a bottom sheet, from it a popover
/// under the header.
const driveSwitcherPopoverWidth = 600.0;

String driveTitle(DriveInfo d) => d.name.isEmpty ? 'Untitled drive' : d.name;

/// A drive's avatar: its picture or emoji, else a folder.
class DriveAvatar extends StatelessWidget {
  final DriveInfo? drive;
  final double size;

  const DriveAvatar({super.key, required this.drive, this.size = 28});

  @override
  Widget build(BuildContext context) {
    final d = drive;
    return SizedBox(
      width: size,
      height: size,
      child: RowLeading(
        size: size,
        image: d == null ? null : ImageSource.of(d.picture, emoji: d.emoji),
        fallbackLabel: d == null ? '' : driveTitle(d),
        fallbackIcon: Icons.folder_outlined,
      ),
    );
  }
}

/// The current drive as the home's heading: avatar, bold name and the small
/// up/down selector of the web sidebar. A tap opens the drive switcher.
class CurrentDriveHeader extends StatelessWidget {
  final DriveInfo? drive;
  final VoidCallback onTap;

  const CurrentDriveHeader(
      {super.key, required this.drive, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final d = drive;
    final name = d == null ? 'Drive' : driveTitle(d);
    return Semantics(
      button: true,
      label: 'Current drive: $name. Switch drive',
      excludeSemantics: true,
      onTap: onTap,
      child: InkWell(
        key: const Key('current-drive-header'),
        mouseCursor: WidgetStateMouseCursor.clickable,
        borderRadius: BorderRadius.circular(8),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 4),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            if (SidebarIconsScope.of(context)) ...[
              DriveAvatar(drive: d),
              const SizedBox(width: 10),
            ],
            Flexible(
              child: Text(name,
                  key: const Key('current-drive-name'),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                      color: c.textPrimary,
                      fontSize: 20,
                      fontWeight: FontWeight.w700)),
            ),
            const SizedBox(width: 4),
            Icon(Icons.unfold_more, size: 20, color: c.textSecondary),
          ]),
        ),
      ),
    );
  }
}

/// The drive switcher: a search field, every listed drive (the current one
/// checked) and "Manage drives…" and "New drive" at the bottom.
class DriveSwitcherContent extends StatefulWidget {
  final List<DriveInfo> drives;
  final String current;
  final ValueChanged<DriveInfo> onSelect;
  final VoidCallback? onManage;
  final VoidCallback? onNew;

  const DriveSwitcherContent({
    super.key,
    required this.drives,
    required this.current,
    required this.onSelect,
    this.onManage,
    this.onNew,
  });

  @override
  State<DriveSwitcherContent> createState() => _DriveSwitcherContentState();
}

class _DriveSwitcherContentState extends State<DriveSwitcherContent> {
  final _query = TextEditingController();

  @override
  void dispose() {
    _query.dispose();
    super.dispose();
  }

  List<DriveInfo> get _shown {
    final q = _query.text.trim().toLowerCase();
    if (q.isEmpty) return widget.drives;
    return [
      for (final d in widget.drives)
        if (driveTitle(d).toLowerCase().contains(q)) d
    ];
  }

  Widget _action(IconData icon, String label, VoidCallback onTap, Key key) {
    final c = context.appColors;
    return InkWell(
      key: key,
      mouseCursor: WidgetStateMouseCursor.clickable,
      onTap: onTap,
      child: ConstrainedBox(
        constraints: const BoxConstraints(minHeight: 48),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Row(children: [
            Icon(icon, size: 22, color: c.textSecondary),
            const SizedBox(width: 16),
            Text(label, style: TextStyle(color: c.textPrimary, fontSize: 15)),
          ]),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final shown = _shown;
    final currentKey = driveKeyOf(widget.current);
    return Column(
      key: const Key('drive-switcher'),
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
          child: TextField(
            key: const Key('drive-switcher-search'),
            controller: _query,
            onChanged: (_) => setState(() {}),
            textInputAction: TextInputAction.search,
            decoration: InputDecoration(
              hintText: 'Search drives',
              prefixIcon: const Icon(Icons.search, size: 20),
              isDense: true,
              filled: true,
              fillColor: c.bg1,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(9),
                borderSide: BorderSide.none,
              ),
            ),
          ),
        ),
        Flexible(
          child: shown.isEmpty
              ? Padding(
                  padding: const EdgeInsets.all(24),
                  child: Center(
                    child: Text('No drives match',
                        key: const Key('drive-switcher-empty'),
                        style: TextStyle(color: c.textSecondary)),
                  ),
                )
              : ListView.builder(
                  shrinkWrap: true,
                  itemCount: shown.length,
                  itemBuilder: (context, i) {
                    final d = shown[i];
                    final current = driveKeyOf(d.subject) == currentKey;
                    return KeyedSubtree(
                      key: ValueKey('drive-switcher-row-${d.subject}'),
                      child: ListTile(
                        mouseCursor: WidgetStateMouseCursor.clickable,
                        leading: DriveAvatar(drive: d, size: 32),
                        title: Text(driveTitle(d),
                            maxLines: 1, overflow: TextOverflow.ellipsis),
                        titleTextStyle: TextStyle(
                            color: c.textPrimary,
                            fontSize: 15,
                            fontWeight:
                                current ? FontWeight.w600 : FontWeight.w400),
                        trailing: current
                            ? Icon(Icons.check,
                                key: const Key('drive-switcher-current'),
                                size: 20,
                                color: c.main)
                            : null,
                        onTap: () => widget.onSelect(d),
                      ),
                    );
                  },
                ),
        ),
        Divider(height: 1, color: c.sectionDivider),
        if (widget.onManage != null)
          _action(Icons.folder_copy_outlined, 'Manage drives…',
              widget.onManage!, const Key('drive-switcher-manage')),
        if (widget.onNew != null)
          _action(Icons.add, 'New drive', widget.onNew!,
              const Key('drive-switcher-new')),
      ],
    );
  }
}

/// The identifier without its scheme (`did:ad:X` and `atomic:X` are one).
String driveKeyOf(String subject) =>
    subject.replaceFirst(RegExp(r'^(did:ad:|atomic:)'), '').split('?').first;

/// Opens the drive switcher from the header whose [context] is given: a
/// popover under it from [driveSwitcherPopoverWidth] on, else a bottom sheet.
/// Picking a drive closes it first, then calls [onSelect].
Future<void> showDriveSwitcher(
  BuildContext context, {
  required List<DriveInfo> drives,
  required String current,
  required ValueChanged<DriveInfo> onSelect,
  VoidCallback? onManage,
  VoidCallback? onNew,
}) {
  final media = MediaQuery.of(context);
  final wide = media.size.width >= driveSwitcherPopoverWidth;
  Widget content(BuildContext inner) => DriveSwitcherContent(
        drives: drives,
        current: current,
        onSelect: (d) {
          Navigator.of(inner).pop();
          onSelect(d);
        },
        onManage: onManage == null
            ? null
            : () {
                Navigator.of(inner).pop();
                onManage();
              },
        onNew: onNew == null
            ? null
            : () {
                Navigator.of(inner).pop();
                onNew();
              },
      );
  if (!wide) {
    return showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      constraints: BoxConstraints(maxHeight: media.size.height * 0.85),
      builder: (inner) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(inner).bottom),
        child: SafeArea(child: content(inner)),
      ),
    );
  }
  final box = context.findRenderObject() as RenderBox;
  final origin = box.localToGlobal(Offset.zero);
  final top = origin.dy + box.size.height + 4;
  const width = 340.0;
  final left = origin.dx
      .clamp(8.0, math.max(8.0, media.size.width - width - 8))
      .toDouble();
  return showGeneralDialog<void>(
    context: context,
    barrierDismissible: true,
    barrierLabel: 'Close drives',
    barrierColor: Colors.transparent,
    transitionDuration: const Duration(milliseconds: 90),
    pageBuilder: (inner, _, __) {
      final c = inner.appColors;
      return Stack(children: [
        Positioned(
          left: left,
          top: top,
          width: width,
          child: Material(
            key: const Key('drive-switcher-popover'),
            color: c.bgBody,
            elevation: 8,
            borderRadius: BorderRadius.circular(12),
            clipBehavior: Clip.antiAlias,
            child: ConstrainedBox(
              constraints: BoxConstraints(
                  maxHeight: math.max(160, media.size.height - top - 16)),
              child: content(inner),
            ),
          ),
        ),
      ]);
    },
  );
}

/// SharedPreferences key: the folders open in the tree of [drive].
String driveTreeOpenKey(String drive) => 'drive_tree_open_${driveKeyOf(drive)}';

/// The current drive's children as a tree, in the web sidebar's order:
/// folders unfold and fold, what is open is remembered per drive, and the
/// rows are built as they scroll into view (a flat list of the visible
/// rows). "New" is the last row.
class DriveTree extends StatefulWidget {
  final AssistantApi api;
  final String drive;

  /// A row was tapped (not its chevron): open the resource.
  final ValueChanged<DriveChild> onOpen;

  /// The "New" row was tapped.
  final VoidCallback onNew;

  const DriveTree({
    super.key,
    required this.api,
    required this.drive,
    required this.onOpen,
    required this.onNew,
  });

  @override
  State<DriveTree> createState() => DriveTreeState();
}

class _Level {
  DriveChildren? data;
  Object? error;
  bool loading = false;
}

sealed class _Item {}

class _ChildItem extends _Item {
  final DriveChild child;
  final int depth;
  _ChildItem(this.child, this.depth);
}

class _StatusItem extends _Item {
  final int depth;
  final String parent;
  final Object? error;
  _StatusItem(this.depth, this.parent, this.error);
}

class DriveTreeState extends State<DriveTree> {
  static const _maxDepth = 10;
  final Map<String, _Level> _levels = {};
  Set<String> _open = {};
  Timer? _debounce;

  @override
  void initState() {
    super.initState();
    _load(widget.drive);
    _restoreOpen();
    widget.api.storeChanges?.addListener(_storeChanged);
  }

  @override
  void didUpdateWidget(DriveTree oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.drive != widget.drive) {
      // Another drive: its own children and its own open folders.
      _levels.clear();
      _open = {};
      _load(widget.drive);
      _restoreOpen();
    }
    if (oldWidget.api.storeChanges != widget.api.storeChanges) {
      oldWidget.api.storeChanges?.removeListener(_storeChanged);
      widget.api.storeChanges?.addListener(_storeChanged);
    }
  }

  @override
  void dispose() {
    _debounce?.cancel();
    widget.api.storeChanges?.removeListener(_storeChanged);
    super.dispose();
  }

  void _storeChanged() {
    _debounce?.cancel();
    _debounce = Timer(const Duration(milliseconds: 600), reload);
  }

  Future<void> _restoreOpen() async {
    try {
      final p = await SharedPreferences.getInstance();
      final saved = p.getStringList(driveTreeOpenKey(widget.drive));
      if (!mounted || saved == null) return;
      setState(() => _open = {...saved, ..._open});
      for (final s in saved) {
        _load(s);
      }
    } catch (_) {}
  }

  Future<void> _saveOpen() async {
    try {
      final p = await SharedPreferences.getInstance();
      await p.setStringList(driveTreeOpenKey(widget.drive), _open.toList());
    } catch (_) {}
  }

  /// Reads the children of [parent] (the old ones stay until the new arrive).
  Future<void> _load(String parent) async {
    final level = _levels[parent] ??= _Level();
    if (level.loading) return;
    level.loading = true;
    try {
      final data = await widget.api.driveChildren(parent);
      level
        ..data = data
        ..error = null;
    } catch (e) {
      level.error = e;
    } finally {
      level.loading = false;
    }
    if (mounted) setState(() {});
  }

  /// Reads the root and every open folder again.
  void reload() {
    if (!mounted) return;
    _load(widget.drive);
    for (final s in _open) {
      _load(s);
    }
  }

  void _toggle(String subject) {
    setState(() {
      if (!_open.remove(subject)) {
        _open.add(subject);
        if (_levels[subject]?.data == null) _load(subject);
      }
    });
    _saveOpen();
  }

  /// The rows that show now, depth first.
  List<_Item> _flatten() {
    final out = <_Item>[];
    void walk(String parent, int depth, Set<String> path) {
      final level = _levels[parent];
      final data = level?.data;
      if (data == null) {
        out.add(_StatusItem(depth, parent, level?.error));
        return;
      }
      for (final child in data.children) {
        if (path.contains(child.subject)) continue;
        out.add(_ChildItem(child, depth));
        if (child.expandable &&
            depth < _maxDepth &&
            _open.contains(child.subject)) {
          walk(child.subject, depth + 1, {...path, child.subject});
        }
      }
    }

    walk(widget.drive, 0, {widget.drive});
    return out;
  }

  Widget _row(_ChildItem item) {
    final c = context.appColors;
    final child = item.child;
    final lead = leadingOf(child.picture, child.emoji, child.className);
    final open = _open.contains(child.subject);
    return Padding(
      key: ValueKey('drive-tree-row-${child.subject}'),
      padding: EdgeInsets.only(left: 16.0 * item.depth),
      child: ResourceRow(
        subject: child.subject,
        icon: lead.icon,
        image: lead.image,
        shape: lead.shape,
        showInitial: lead.initial,
        title: child.title.isEmpty ? 'Untitled' : child.title,
        trailing: child.expandable && _canHaveChildren(child)
            ? IconButton(
                key: ValueKey('drive-tree-toggle-${child.subject}'),
                mouseCursor: WidgetStateMouseCursor.clickable,
                tooltip: open ? 'Collapse' : 'Expand',
                visualDensity: VisualDensity.compact,
                icon: AnimatedRotation(
                  turns: open ? 0 : -0.25,
                  duration: const Duration(milliseconds: 120),
                  child:
                      Icon(Icons.expand_more, size: 22, color: c.textSecondary),
                ),
                onPressed: () => _toggle(child.subject),
              )
            : null,
        onTap: () => widget.onOpen(child),
      ),
    );
  }

  /// Only folders and the like unfold (the host marks what keeps its children
  /// in a page of its own as not expandable); a document has none.
  bool _canHaveChildren(DriveChild child) {
    final level = _levels[child.subject]?.data;
    if (level != null) {
      return level.children.isNotEmpty || _open.contains(child.subject);
    }
    final key = child.className.split('/').last.toLowerCase();
    return key == 'folder' || key == 'drive' || key.isEmpty;
  }

  Widget _status(_StatusItem s) {
    final c = context.appColors;
    final pad = EdgeInsets.only(left: 16.0 + 16.0 * s.depth, right: 16);
    if (s.error != null) {
      return Padding(
        key: ValueKey('drive-tree-error-${s.parent}'),
        padding: pad.add(const EdgeInsets.symmetric(vertical: 8)),
        child: Row(children: [
          Expanded(child: ErrorText('${s.error}', color: c.alert)),
          TextButton(
              key: ValueKey('drive-tree-retry-${s.parent}'),
              onPressed: () => _load(s.parent),
              child: const Text('Retry')),
        ]),
      );
    }
    return Padding(
      key: ValueKey('drive-tree-loading-${s.parent}'),
      padding: pad.add(const EdgeInsets.symmetric(vertical: 12)),
      child: const Align(
        alignment: Alignment.centerLeft,
        child: SizedBox(
            width: 18,
            height: 18,
            child: CircularProgressIndicator(strokeWidth: 2)),
      ),
    );
  }

  Widget _newRow() {
    final c = context.appColors;
    return InkWell(
      key: const Key('drive-new-row'),
      mouseCursor: WidgetStateMouseCursor.clickable,
      onTap: widget.onNew,
      child: ConstrainedBox(
        constraints: const BoxConstraints(minHeight: 48),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Row(children: [
            const SizedBox(width: 6),
            Icon(Icons.add, size: 22, color: c.textSecondary),
            const SizedBox(width: 24),
            Text('New', style: TextStyle(color: c.textSecondary, fontSize: 15)),
          ]),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final root = _levels[widget.drive];
    final items = _flatten();
    final rootEmpty = root?.data != null && root!.data!.children.isEmpty;
    return KeyedSubtree(
      key: const Key('drive-tree'),
      child: ListView.builder(
        padding: EdgeInsets.zero,
        itemCount: items.length + (rootEmpty ? 1 : 0) + 1,
        itemBuilder: (context, i) {
          if (i < items.length) {
            final item = items[i];
            return switch (item) {
              _ChildItem() => _row(item),
              _StatusItem() => _status(item),
            };
          }
          if (rootEmpty && i == items.length) {
            return Padding(
              padding: const EdgeInsets.all(24),
              child: Center(
                child: Text('Nothing here yet',
                    key: const Key('drive-tree-empty'),
                    style: TextStyle(color: c.textSecondary)),
              ),
            );
          }
          return _newRow();
        },
      ),
    );
  }
}
