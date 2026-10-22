import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColorsExt, ErrorText, SectionHeaderStyle;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show LogicalKeyboardKey;
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_api.dart';
import 'models.dart';
import 'app_sidebar_icons.dart';
import 'resource_row.dart';
import 'row_leading.dart';
import 'sidebar_metrics.dart';

String driveTitle(DriveInfo d) => d.name.isEmpty ? 'Untitled drive' : d.name;

/// A drive's avatar: its picture or emoji, else a folder.
class DriveAvatar extends StatelessWidget {
  final DriveInfo? drive;
  final double size;

  /// Draw the folder fallback at the slot's left edge (see
  /// [RowLeading.alignGlyphStart]).
  final bool alignGlyphStart;

  const DriveAvatar(
      {super.key,
      required this.drive,
      this.size = 28,
      this.alignGlyphStart = false});

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
        alignGlyphStart: alignGlyphStart,
      ),
    );
  }
}

/// The current drive as the home's heading: avatar, bold name and the small
/// up/down selector of the web sidebar. A tap opens the drive switcher.
class CurrentDriveHeader extends StatelessWidget {
  final DriveInfo? drive;
  final VoidCallback onTap;

  /// A resource of the tree was dropped on the header: move it to the drive's
  /// root. Null: the header accepts no drops.
  final ValueChanged<DriveDrag>? onDrop;

  const CurrentDriveHeader(
      {super.key, required this.drive, required this.onTap, this.onDrop});

  @override
  Widget build(BuildContext context) {
    final header = _header(context);
    final drop = onDrop;
    if (drop == null) return header;
    final c = context.appColors;
    return DragTarget<DriveDrag>(
      key: const Key('current-drive-drop'),
      // Already at the root: the rows' own drop lines reorder it.
      onWillAcceptWithDetails: (d) => d.data.parent != d.data.drive,
      onAcceptWithDetails: (d) => drop(d.data),
      builder: (context, candidate, rejected) => DecoratedBox(
        decoration: BoxDecoration(
          color: candidate.isEmpty ? Colors.transparent : c.rowHighlight,
          borderRadius: BorderRadius.circular(8),
        ),
        child: header,
      ),
    );
  }

  Widget _header(BuildContext context) {
    final c = context.appColors;
    final d = drive;
    final name = d == null ? 'Drive' : driveTitle(d);
    final m = SidebarMetrics.of(context);
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
        child: ConstrainedBox(
          constraints:
              BoxConstraints(minHeight: m.compact ? m.driveHeaderHeight : 0),
          child: Padding(
            // Compact: the avatar sits at the rows' icon column (the bar's
            // title spacing is 4). Touch: the bar's title spacing is already
            // the rows' 16, so no side padding of our own.
            padding: m.compact
                ? EdgeInsets.symmetric(vertical: 4, horizontal: m.hPad - 4)
                : const EdgeInsets.symmetric(vertical: 6),
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              if (SidebarIconsScope.of(context)) ...[
                DriveAvatar(
                    drive: d,
                    size: m.compact ? m.driveAvatar : 28,
                    alignGlyphStart: !m.compact),
                SizedBox(width: m.compact ? m.gap : 10),
              ],
              Flexible(
                child: Text(name,
                    key: const Key('current-drive-name'),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    strutStyle:
                        m.compact ? SidebarRow.strut(m.driveNameSize) : null,
                    style: TextStyle(
                        color: c.textPrimary,
                        fontSize: m.compact ? m.driveNameSize : 20,
                        height: m.compact ? 1.2 : null,
                        fontWeight: FontWeight.w700)),
              ),
              const SizedBox(width: 4),
              Icon(Icons.unfold_more,
                  size: m.compact ? m.chevronSize : 20, color: c.textSecondary),
            ]),
          ),
        ),
      ),
    );
  }
}

/// The drive switcher: a search field, every listed drive as a full-width
/// row (the left part opens the drive's page, a "Switch" button on the right
/// makes it the current drive, the current one shows a "Current" chip) and
/// "Manage drives…" and "New drive" at the bottom.
///
/// It is a state of the sidebar, not a layer over it: with [fill] it takes
/// all the room it is given (the list scrolls, the actions stay at the
/// bottom).
class DriveSwitcherContent extends StatefulWidget {
  final List<DriveInfo> drives;
  final String current;
  final ValueChanged<DriveInfo> onSelect;

  /// The row's left part: open the drive's page, the active drive unchanged.
  final ValueChanged<DriveInfo> onOpen;
  final VoidCallback? onManage;
  final VoidCallback? onNew;

  /// Take all the height there is instead of only what the rows need.
  final bool fill;

  const DriveSwitcherContent({
    super.key,
    this.fill = false,
    required this.drives,
    required this.current,
    required this.onSelect,
    required this.onOpen,
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
      mainAxisSize: widget.fill ? MainAxisSize.max : MainAxisSize.min,
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
          fit: widget.fill ? FlexFit.tight : FlexFit.loose,
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
                  shrinkWrap: !widget.fill,
                  itemCount: shown.length,
                  itemBuilder: (context, i) {
                    final d = shown[i];
                    final current = driveKeyOf(d.subject) == currentKey;
                    return _DriveSwitcherRow(
                      key: ValueKey('drive-switcher-row-${d.subject}'),
                      drive: d,
                      current: current,
                      onOpen: () => widget.onOpen(d),
                      onSwitch: () => widget.onSelect(d),
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

/// One drive in the switcher, edge to edge: the left part (avatar and name)
/// opens the drive's page, the right a compact "Switch" button, or for the
/// current drive a "Current" chip. Ctrl/Cmd+Enter on the row switches.
class _DriveSwitcherRow extends StatefulWidget {
  final DriveInfo drive;
  final bool current;
  final VoidCallback onOpen;
  final VoidCallback onSwitch;

  const _DriveSwitcherRow({
    super.key,
    required this.drive,
    required this.current,
    required this.onOpen,
    required this.onSwitch,
  });

  @override
  State<_DriveSwitcherRow> createState() => _DriveSwitcherRowState();
}

class _DriveSwitcherRowState extends State<_DriveSwitcherRow> {
  bool _hovered = false;

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final d = widget.drive;
    final name = driveTitle(d);
    final switchable = !widget.current;
    Widget trailing;
    if (switchable) {
      trailing = Semantics(
        button: true,
        label: 'Switch to $name',
        excludeSemantics: true,
        onTap: widget.onSwitch,
        child: SizedBox(
          height: 34,
          child: FilledButton.tonal(
            key: ValueKey('drive-switcher-switch-${d.subject}'),
            onPressed: widget.onSwitch,
            style: FilledButton.styleFrom(
              minimumSize: const Size(0, 34),
              padding: const EdgeInsets.symmetric(horizontal: 14),
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              backgroundColor: c.mainSelectedBg,
              foregroundColor: c.mainSelectedFg,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(17)),
              textStyle:
                  const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
            ),
            child: const Text('Switch'),
          ),
        ),
      );
    } else {
      trailing = Container(
        key: const Key('drive-switcher-current'),
        height: 28,
        padding: const EdgeInsets.symmetric(horizontal: 10),
        decoration: BoxDecoration(
          color: c.bg1,
          borderRadius: BorderRadius.circular(14),
        ),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Icon(Icons.check, size: 16, color: c.textSecondary),
          const SizedBox(width: 4),
          Text('Current',
              key: const Key('drive-switcher-current-label'),
              style: TextStyle(
                  color: c.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600)),
        ]),
      );
    }
    return CallbackShortcuts(
      bindings: {
        if (switchable) ...{
          const SingleActivator(LogicalKeyboardKey.enter, control: true):
              widget.onSwitch,
          const SingleActivator(LogicalKeyboardKey.enter, meta: true):
              widget.onSwitch,
        },
      },
      child: MouseRegion(
        onEnter: (_) => setState(() => _hovered = true),
        onExit: (_) => setState(() => _hovered = false),
        child: DecoratedBox(
          decoration: BoxDecoration(
            color: _hovered ? c.rowHighlight : Colors.transparent,
            border: Border(bottom: BorderSide(color: c.sectionDivider)),
          ),
          child: ConstrainedBox(
            constraints: const BoxConstraints(minHeight: 56),
            child: Row(children: [
              Expanded(
                child: Semantics(
                  button: true,
                  label: 'Open $name',
                  excludeSemantics: true,
                  onTap: widget.onOpen,
                  child: InkWell(
                    key: ValueKey('drive-switcher-open-${d.subject}'),
                    mouseCursor: WidgetStateMouseCursor.clickable,
                    onTap: widget.onOpen,
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(minHeight: 56),
                      child: Padding(
                        padding: const EdgeInsets.only(left: 16, right: 8),
                        child: Row(children: [
                          DriveAvatar(drive: d, size: 32),
                          const SizedBox(width: 14),
                          Expanded(
                            child: Text(name,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(
                                    color: c.textPrimary,
                                    fontSize: 15,
                                    fontWeight: widget.current
                                        ? FontWeight.w600
                                        : FontWeight.w400)),
                          ),
                        ]),
                      ),
                    ),
                  ),
                ),
              ),
              Padding(
                padding: const EdgeInsets.only(right: 12),
                child: trailing,
              ),
            ]),
          ),
        ),
      ),
    );
  }
}

/// The identifier without its scheme (`did:ad:X` and `atomic:X` are one).
String driveKeyOf(String subject) =>
    subject.replaceFirst(RegExp(r'^(did:ad:|atomic:)'), '').split('?').first;

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

/// What a dragged tree row carries: the resource, the parent it sits under
/// and the drive the tree shows.
class DriveDrag {
  final String subject;
  final String parent;
  final String drive;
  const DriveDrag(this.subject, this.parent, this.drive);
}

/// Where on a row a drop lands: above it, below it, or into it.
enum DropZone { before, after, into }

/// A resolved drop: the new parent and the position among its children
/// without the dragged one.
class DriveMove {
  final String parent;
  final int index;
  const DriveMove(this.parent, this.index);

  @override
  bool operator ==(Object other) =>
      other is DriveMove && other.parent == parent && other.index == index;

  @override
  int get hashCode => Object.hash(parent, index);

  @override
  String toString() => 'DriveMove($parent, $index)';
}

/// Past every child: the host clamps it, so "the end" needs no count.
const driveMoveToEnd = 1 << 30;

/// Where dropping [dragged] on [zone] of a row lands, or null when that is
/// refused or changes nothing. As the web sidebar: a drop above or below a row
/// puts the item next to it under the row's parent; a drop into a row appends
/// to that row's children (only when [canHoldChildren]); never into the item
/// itself or one of its own descendants ([path] is the row's ancestors, its
/// parent included).
///
/// [siblings] are the subjects under the row's parent in tree order.
DriveMove? resolveDrop({
  required String dragged,
  required String row,
  required String parent,
  required Set<String> path,
  required List<String> siblings,
  required DropZone zone,
  required bool canHoldChildren,
}) {
  if (dragged == row || path.contains(dragged)) return null;
  if (zone == DropZone.into) {
    return canHoldChildren ? DriveMove(row, driveMoveToEnd) : null;
  }
  final others = [
    for (final s in siblings)
      if (s != dragged) s
  ];
  final at = others.indexOf(row);
  if (at < 0) return null;
  final index = zone == DropZone.before ? at : at + 1;
  // Back where it already is.
  if (siblings.indexOf(dragged) == index) return null;
  return DriveMove(parent, index);
}

class _Level {
  DriveChildren? data;
  Object? error;
  bool loading = false;

  /// Asked again while a read was running: read once more when it ends.
  bool again = false;
}

sealed class _Item {}

class _ChildItem extends _Item {
  final DriveChild child;
  final int depth;

  /// The folder (or the drive) this row is listed under.
  final String parent;

  /// The subjects listed under [parent], in order.
  final List<String> siblings;

  /// The row's ancestors: [parent] and everything above it.
  final Set<String> path;
  _ChildItem(this.child, this.depth, this.parent, this.siblings, this.path);
}

class _Hint {
  final String subject;
  final DropZone zone;
  const _Hint(this.subject, this.zone);

  @override
  bool operator ==(Object other) =>
      other is _Hint && other.subject == subject && other.zone == zone;

  @override
  int get hashCode => Object.hash(subject, zone);
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
  Future<void> _load(String parent, {bool again = false}) async {
    final level = _levels[parent] ??= _Level();
    if (level.loading) {
      if (again) level.again = true;
      return;
    }
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
    if (level.again) {
      level.again = false;
      if (mounted) _load(parent);
    }
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
      final siblings = [for (final c in data.children) c.subject];
      for (final child in data.children) {
        if (path.contains(child.subject)) continue;
        out.add(_ChildItem(child, depth, parent, siblings, path));
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

  /// The fold chevron at the row's end. Its icon ends where a panel
  /// heading's chevron does: centred in a [SidebarMetrics.chevronSlot] box
  /// that ends [SidebarMetrics.hPad] from the edge on desktop, and pushed out
  /// to the edge on touch, where the ListTile keeps a wider end padding.
  Widget _chevron(DriveChild child, bool open, SidebarMetrics m) {
    final c = context.appColors;
    final button = IconButton(
      key: ValueKey('drive-tree-toggle-${child.subject}'),
      mouseCursor: WidgetStateMouseCursor.clickable,
      tooltip: open ? 'Collapse' : 'Expand',
      padding: EdgeInsets.zero,
      iconSize: m.chevronSize,
      constraints:
          BoxConstraints.tightFor(width: m.chevronSlot, height: m.chevronSlot),
      style: IconButton.styleFrom(
          tapTargetSize: MaterialTapTargetSize.shrinkWrap),
      icon: AnimatedRotation(
        turns: open ? 0 : -0.25,
        duration: const Duration(milliseconds: 120),
        child: Icon(Icons.expand_more,
            size: m.chevronSize, color: c.textSecondary),
      ),
      onPressed: () => _toggle(child.subject),
    );
    if (m.compact) return button;
    // A touch ListTile ends its trailing box 24 from the edge, not hPad.
    return Transform.translate(
        offset: Offset((m.chevronSlot - m.chevronSize) / 2 + 24 - m.hPad, 0),
        child: button);
  }

  Widget _row(_ChildItem item) {
    final child = item.child;
    final lead = leadingOf(child.picture, child.emoji, child.className);
    final open = _open.contains(child.subject);
    final m = SidebarMetrics.of(context);
    final row = Padding(
      key: ValueKey('drive-tree-row-${child.subject}'),
      // Compact rows indent themselves (full-bleed tint, same icon grid).
      padding: EdgeInsets.only(left: m.compact ? 0 : 16.0 * item.depth),
      child: ResourceRow(
        depth: item.depth,
        subject: child.subject,
        icon: lead.icon,
        image: lead.image,
        shape: lead.shape,
        showInitial: lead.initial,
        title: child.title.isEmpty ? 'Untitled' : child.title,
        trailing: child.expandable && _canHaveChildren(child)
            ? _chevron(child, open, m)
            : null,
        onTap: () => widget.onOpen(child),
      ),
    );
    return _DragRow(
      key: ValueKey('drive-tree-drag-${child.subject}'),
      // A mouse drags at once; a finger holds first, so a swipe still scrolls.
      holdToDrag: !m.compact,
      data: DriveDrag(child.subject, item.parent, widget.drive),
      title: child.title.isEmpty ? 'Untitled' : child.title,
      canHoldChildren: _canDropInto(child),
      hint: _hint?.subject == child.subject ? _hint!.zone : null,
      resolve: (dragged, zone) => _resolve(dragged, item, zone),
      onHint: (zone) =>
          _setHint(zone == null ? null : _Hint(child.subject, zone)),
      onDrop: (dragged, zone) {
        final move = _resolve(dragged, item, zone);
        _setHint(null);
        if (move != null) _move(dragged.subject, dragged.parent, move);
      },
      child: row,
    );
  }

  _Hint? _hint;

  void _setHint(_Hint? hint) {
    if (_hint == hint) return;
    setState(() => _hint = hint);
  }

  /// Like the web sidebar, any resource whose children the sidebar unfolds
  /// takes a drop into it (the host marks tables, chat rooms and the like not
  /// expandable).
  bool _canDropInto(DriveChild child) => child.expandable;

  DriveMove? _resolve(DriveDrag dragged, _ChildItem item, DropZone zone) =>
      resolveDrop(
        dragged: dragged.subject,
        row: item.child.subject,
        parent: item.parent,
        path: item.path,
        siblings: item.siblings,
        zone: zone,
        canHoldChildren: _canDropInto(item.child),
      );

  /// Moves a resource to the drive's root, at the end (a drop on the header).
  Future<void> moveToRoot(DriveDrag dragged) => _move(
      dragged.subject, dragged.parent, DriveMove(widget.drive, driveMoveToEnd));

  /// Asks the host to move [subject] and reads the two affected levels again.
  /// A folder dropped into opens, so the result shows.
  Future<void> _move(String subject, String from, DriveMove to) async {
    try {
      await widget.api.moveResource(subject, to.parent, to.index);
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.maybeOf(context)?.showSnackBar(SnackBar(
          key: const Key('drive-tree-move-error'),
          content: Text('Could not move: $e')));
      return;
    }
    if (!mounted) return;
    if (to.parent != widget.drive && !_open.contains(to.parent)) {
      setState(() => _open.add(to.parent));
      _saveOpen();
    }
    _load(from, again: true);
    if (to.parent != from) _load(to.parent, again: true);
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
    final m = SidebarMetrics.of(context);
    final pad = m.compact
        ? EdgeInsets.only(left: m.titleX(s.depth, icon: false), right: m.hPad)
        : EdgeInsets.only(left: 16.0 + 16.0 * s.depth, right: 16);
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
    final m = SidebarMetrics.of(context);
    if (m.compact) {
      return SidebarRow(
        key: const Key('drive-new-row'),
        icon: Icon(Icons.add, size: m.iconSize, color: c.textSecondary),
        title: 'New',
        titleStyle: SidebarRow.text(c.textSecondary, m.textSize),
        onTap: widget.onNew,
      );
    }
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

/// A tree row that can be dragged and dropped on: dragging it moves the
/// resource, dropping another row on its top or bottom quarter puts that one
/// next to it, on its middle (when it can hold children) into it. A mouse
/// drags at once; with [holdToDrag] (touch) a long press starts the drag, so a
/// swipe still scrolls the list and a tap still opens the row.
class _DragRow extends StatelessWidget {
  final bool holdToDrag;
  final DriveDrag data;
  final String title;
  final bool canHoldChildren;

  /// Where a drop would land on this row now (the drop line or highlight).
  final DropZone? hint;

  /// Where [DropZone] of this row puts a drag; null: a drop there is refused.
  final DriveMove? Function(DriveDrag, DropZone) resolve;
  final ValueChanged<DropZone?> onHint;
  final void Function(DriveDrag, DropZone) onDrop;
  final Widget child;

  const _DragRow({
    super.key,
    required this.holdToDrag,
    required this.data,
    required this.title,
    required this.canHoldChildren,
    required this.hint,
    required this.resolve,
    required this.onHint,
    required this.onDrop,
    required this.child,
  });

  DropZone _zoneAt(BuildContext context, Offset global) {
    final box = context.findRenderObject();
    if (box is! RenderBox || !box.hasSize) return DropZone.after;
    final h = box.size.height;
    final y = box.globalToLocal(global).dy;
    if (canHoldChildren) {
      if (y < h * 0.25) return DropZone.before;
      if (y > h * 0.75) return DropZone.after;
      return DropZone.into;
    }
    return y < h / 2 ? DropZone.before : DropZone.after;
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final accent = Theme.of(context).colorScheme.primary;
    final feedback = Material(
      elevation: 4,
      color: c.bg1,
      borderRadius: BorderRadius.circular(8),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 260),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Text(title,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                  color: c.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                  decoration: TextDecoration.none)),
        ),
      ),
    );
    final whileDragging = Opacity(opacity: 0.35, child: child);
    final Widget source = holdToDrag
        ? LongPressDraggable<DriveDrag>(
            data: data,
            dragAnchorStrategy: pointerDragAnchorStrategy,
            feedback: feedback,
            childWhenDragging: whileDragging,
            child: child)
        : Draggable<DriveDrag>(
            data: data,
            dragAnchorStrategy: pointerDragAnchorStrategy,
            feedback: feedback,
            childWhenDragging: whileDragging,
            child: child);
    return DragTarget<DriveDrag>(
      onWillAcceptWithDetails: (d) => d.data.subject != data.subject,
      onMove: (d) {
        final zone = _zoneAt(context, d.offset);
        onHint(resolve(d.data, zone) == null ? null : zone);
      },
      onLeave: (_) => onHint(null),
      onAcceptWithDetails: (d) => onDrop(d.data, _zoneAt(context, d.offset)),
      builder: (context, candidate, rejected) {
        final zone = hint;
        return Stack(fit: StackFit.passthrough, children: [
          source,
          if (zone == DropZone.into)
            Positioned.fill(
              child: IgnorePointer(
                child: DecoratedBox(
                  key: const Key('drop-into'),
                  decoration: BoxDecoration(
                    color: accent.withValues(alpha: 0.14),
                    border: Border.all(color: accent, width: 1.5),
                    borderRadius: BorderRadius.circular(6),
                  ),
                ),
              ),
            ),
          if (zone == DropZone.before || zone == DropZone.after)
            Positioned(
              top: zone == DropZone.before ? 0 : null,
              bottom: zone == DropZone.after ? 0 : null,
              left: 0,
              right: 0,
              height: 2,
              child: IgnorePointer(
                child: ColoredBox(
                    key: Key(zone == DropZone.before
                        ? 'drop-before'
                        : 'drop-after'),
                    color: accent),
              ),
            ),
        ]);
      },
    );
  }
}
