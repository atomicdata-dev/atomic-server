import 'package:flutter/foundation.dart' show defaultTargetPlatform;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart' show RendererBinding;
import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColorsExt, SectionHeaderStyle;

/// The density of the Home sidebar: every row type reads its sizes from here,
/// so they sit on one grid. The icon column starts at [hPad] (plus [indent]
/// per tree level) and is [iconSlot] wide, titles start [gap] after it,
/// chevrons and trailing parts end [hPad] before the right edge.
///
/// [touch] is today's layout for fingers (phones and tablets: the list tiles
/// keep their own sizes, these values describe them for reference); [compact]
/// is the desktop one. [SidebarMetricsScope] picks one for everything below it;
/// outside a scope [SidebarMetrics.of] is [touch], so rows in other lists
/// (search, the attachment sheet, full-page lists) never change.
class SidebarMetrics {
  final bool compact;

  /// The least height of a tree / panel row (it grows with the text scale).
  final double rowHeight;
  final double iconSize;

  /// Width of the column the icon, picture or avatar sits in.
  final double iconSlot;

  /// Between the icon column and the title.
  final double gap;
  final double textSize;

  /// Left and right inset of every row.
  final double hPad;

  /// Extra left inset per tree level.
  final double indent;
  final double chevronSize;

  /// The chevron's box (also its hit area); its right edge is [hPad] from
  /// the row's.
  final double chevronSlot;

  /// The least height of a panel header band.
  final double headerHeight;
  final double headerTextSize;
  final double driveHeaderHeight;
  final double driveAvatar;
  final double driveNameSize;

  const SidebarMetrics({
    required this.compact,
    required this.rowHeight,
    required this.iconSize,
    required this.iconSlot,
    required this.gap,
    required this.textSize,
    required this.hPad,
    required this.indent,
    required this.chevronSize,
    required this.chevronSlot,
    required this.headerHeight,
    required this.headerTextSize,
    required this.driveHeaderHeight,
    required this.driveAvatar,
    required this.driveNameSize,
  });

  static const touch = SidebarMetrics(
    compact: false,
    rowHeight: 56,
    iconSize: 20,
    iconSlot: 32,
    gap: 16,
    textSize: 15,
    hPad: 16,
    indent: 16,
    chevronSize: 22,
    chevronSlot: 40,
    headerHeight: 48,
    headerTextSize: 14,
    driveHeaderHeight: 40,
    driveAvatar: 28,
    driveNameSize: 20,
  );

  static const desktop = SidebarMetrics(
    compact: true,
    rowHeight: 28,
    iconSize: 18,
    iconSlot: 20,
    gap: 8,
    textSize: 13,
    hPad: 12,
    indent: 14,
    chevronSize: 16,
    chevronSlot: 24,
    headerHeight: 30,
    headerTextSize: 12,
    driveHeaderHeight: 40,
    driveAvatar: 28,
    driveNameSize: 15,
  );

  /// Where a title starts, from the row's left edge, at tree [depth].
  double titleX(int depth, {bool icon = true}) =>
      hPad + indent * depth + (icon ? iconSlot + gap : 0);

  /// Forces a density everywhere (tests); null to follow the platform.
  static SidebarMetrics? debugOverride;

  /// Desktop platforms, or a window of 900 dp or more with a mouse.
  static SidebarMetrics resolve(BuildContext context) {
    final forced = debugOverride;
    if (forced != null) return forced;
    final desktop = switch (defaultTargetPlatform) {
      TargetPlatform.macOS ||
      TargetPlatform.linux ||
      TargetPlatform.windows =>
        true,
      _ => false,
    };
    if (desktop) return SidebarMetrics.desktop;
    final wide = MediaQuery.sizeOf(context).width >= 900;
    final mouse = RendererBinding.instance.mouseTracker.mouseIsConnected;
    return wide && mouse ? SidebarMetrics.desktop : SidebarMetrics.touch;
  }

  static SidebarMetrics of(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<_MetricsScope>()?.metrics ??
      SidebarMetrics.touch;
}

/// Gives the rows below it the density that suits the platform and pointer.
class SidebarMetricsScope extends StatelessWidget {
  final Widget child;
  final SidebarMetrics? metrics;

  const SidebarMetricsScope({super.key, required this.child, this.metrics});

  @override
  Widget build(BuildContext context) => _MetricsScope(
      metrics: metrics ?? SidebarMetrics.resolve(context), child: child);
}

class _MetricsScope extends InheritedWidget {
  final SidebarMetrics metrics;

  const _MetricsScope({required this.metrics, required super.child});

  @override
  bool updateShouldNotify(_MetricsScope old) => metrics != old.metrics;
}

/// One compact row of the sidebar: [icon] in the icon column (none when
/// [icon] is null and [slot] false), the title [gap] after it, [trailing]
/// ending [SidebarMetrics.hPad] before the right edge. The tint (selected,
/// hover) is full-bleed; the row is at least [SidebarMetrics.rowHeight] high
/// and grows with the text scale.
class SidebarRow extends StatefulWidget {
  final int depth;
  final Widget? icon;

  /// Keep the icon column even without an [icon] (text lines under icons).
  final bool slot;
  final String title;
  final TextStyle? titleStyle;
  final Widget? trailing;
  final VoidCallback? onTap;
  final VoidCallback? onLongPress;
  final bool selected;
  final String? tooltip;

  const SidebarRow({
    super.key,
    required this.title,
    this.depth = 0,
    this.icon,
    this.slot = false,
    this.titleStyle,
    this.trailing,
    this.onTap,
    this.onLongPress,
    this.selected = false,
    this.tooltip,
  });

  /// The compact title style: [size] sp with a 1.2 line height.
  static TextStyle text(Color color, double size,
          {FontWeight weight = FontWeight.w400}) =>
      TextStyle(color: color, fontSize: size, height: 1.2, fontWeight: weight);

  static StrutStyle strut(double size) =>
      StrutStyle(fontSize: size, height: 1.2, forceStrutHeight: true);

  @override
  State<SidebarRow> createState() => _SidebarRowState();
}

class _SidebarRowState extends State<SidebarRow> {
  bool _hovered = false;

  @override
  Widget build(BuildContext context) {
    final m = SidebarMetrics.of(context);
    final c = context.appColors;
    final w = widget;
    final tint = w.selected
        ? c.rowHighlight
        : _hovered && w.onTap != null
            ? Color.alphaBlend(c.textPrimary.withValues(alpha: 0.06), c.bgBody)
            : Colors.transparent;
    final style = w.titleStyle ??
        SidebarRow.text(
            w.selected ? c.mainSelectedFg : c.textPrimary, m.textSize);
    Widget title = Text(w.title,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        strutStyle: SidebarRow.strut(style.fontSize ?? m.textSize),
        style: style);
    if (w.tooltip != null && w.tooltip!.isNotEmpty) {
      title = Tooltip(
          message: w.tooltip!,
          waitDuration: const Duration(seconds: 1),
          child: title);
    }
    final row = ConstrainedBox(
      constraints: BoxConstraints(minHeight: m.rowHeight),
      child: Padding(
        padding: EdgeInsets.fromLTRB(m.hPad + m.indent * w.depth, 2, m.hPad, 2),
        child: Row(children: [
          if (w.icon != null || w.slot) ...[
            SizedBox(
                width: m.iconSlot,
                height: m.iconSlot,
                child: Center(child: w.icon)),
            SizedBox(width: m.gap),
          ],
          Expanded(child: title),
          if (w.trailing != null) ...[
            SizedBox(width: m.gap),
            w.trailing!,
          ],
        ]),
      ),
    );
    return MouseRegion(
      onEnter: (_) => setState(() => _hovered = true),
      onExit: (_) => setState(() => _hovered = false),
      child: Material(
        color: tint,
        child: w.onTap == null
            ? row
            : InkWell(
                mouseCursor: WidgetStateMouseCursor.clickable,
                hoverColor: Colors.transparent,
                onTap: w.onTap,
                onLongPress: w.onLongPress,
                child: row),
      ),
    );
  }
}
