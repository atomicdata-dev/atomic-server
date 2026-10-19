import 'dart:math' as math;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/semantics.dart';
import 'package:flutter/services.dart';

import 'theme.dart';

/// One choice of a [HoldFan]: a short text pill, optionally led by an emoji.
@immutable
class HoldFanItem<T> {
  final String label;
  final String? emoji;
  final T value;

  const HoldFanItem(this.label, this.value, {this.emoji});

  String get text => emoji == null ? label : '$emoji $label';
}

/// How a [HoldFan] arranges its choices.
enum HoldFanLayout {
  /// Curving away from the button along the arc a thumb sweeps: for a few
  /// kinds of "new" and for drawing tools.
  fan,

  /// Stacked straight above (or, with no room above, below) the button: for
  /// choices taken from a list (drives, recent resources, chats).
  list,
}

/// A button with more than one action, after the colour and width fans of
/// the Atomic drawing tools: a tap does [onTap], the default action; touching
/// and holding (a short moment, with a haptic tick) fans [items] out above the
/// button, and the finger, still down, slides onto one (a tick on each
/// change) and lets go to pick it ([onSelected]). Letting go anywhere else,
/// or the touch being cancelled, closes the fan without a choice. Letting go
/// where the hold started (the finger never went anywhere, as after a plain
/// long press) keeps the fan open as a menu: a tap on a pill picks it, a tap
/// anywhere else closes it.
///
/// The fan is drawn in the root [Overlay], over everything, with the page
/// dimmed a little; the button itself does not move. It opens upwards, the
/// first item (the default) nearest the thumb, the rest curving towards the
/// middle of the screen, and stays inside the screen.
///
/// For assistive technology the button has a long-press action
/// ([menuLabel]) that lists the same choices in a plain menu.
///
/// [child] is what the button shows (an icon); [HoldFan] is the tap target.
class HoldFan<T> extends StatefulWidget {
  final Widget child;

  /// The default action; null leaves the button without a tap (the fan still
  /// opens on hold).
  final VoidCallback? onTap;

  final List<HoldFanItem<T>> items;
  final ValueChanged<T> onSelected;

  /// The item marked as the default (what a tap does), or null.
  final int? defaultIndex;

  /// The button's tooltip and accessible name.
  final String? tooltip;

  /// How the choices are laid out.
  final HoldFanLayout layout;

  /// How long to hold before the fan opens.
  final Duration holdDuration;

  /// Called as the fan opens, before it is laid out from [items].
  final VoidCallback? onOpen;

  /// The accessible long-press action and the menu's title.
  final String menuLabel;

  /// Shown as the current page: drawn as is, and marked selected.
  final bool selected;

  /// Side of the square tap target (its height when [width] is set).
  final double size;

  /// Width of the tap target when it is not square (`double.infinity` fills
  /// the space it is given): for a heading or a row that opens a fan.
  final double? width;

  const HoldFan({
    super.key,
    required this.child,
    required this.items,
    required this.onSelected,
    this.onTap,
    this.defaultIndex = 0,
    this.tooltip,
    this.layout = HoldFanLayout.fan,
    this.holdDuration = const Duration(milliseconds: 180),
    this.onOpen,
    this.menuLabel = 'More options',
    this.selected = false,
    this.size = 48,
    this.width,
  });

  @override
  State<HoldFan<T>> createState() => _HoldFanState<T>();
}

/// Where the pills of a fan go, in the overlay's coordinates: above
/// [anchor] (the button's centre), one per size, the first nearest it, each
/// next one higher and bent further towards the middle of [bounds] along a
/// circle (the arc a thumb sweeps), kept inside [bounds].
List<Rect> holdFanLayout({
  required Offset anchor,
  required List<Size> sizes,
  required Rect bounds,
  double lift = 64,
  double gap = 12,
}) {
  if (sizes.isEmpty) return const [];
  final towardsMiddle = anchor.dx <= bounds.center.dx ? 1.0 : -1.0;
  final rises = <double>[];
  var rise = lift;
  for (final s in sizes) {
    rises.add(rise + s.height / 2);
    rise += s.height + gap;
  }
  final radius = math.max(300.0, rises.last + 60);
  return [
    for (var i = 0; i < sizes.length; i++)
      () {
        final s = sizes[i];
        final up = rises[i];
        final bend = radius - math.sqrt(radius * radius - up * up);
        // The first pill sits right above the button; the rest curve away.
        final shift = towardsMiddle * (bend + (i == 0 ? 0 : 16));
        var left = anchor.dx + shift - s.width / 2;
        var top = anchor.dy - up - s.height / 2;
        left = left.clamp(
            bounds.left, math.max(bounds.left, bounds.right - s.width));
        top = top.clamp(
            bounds.top, math.max(bounds.top, bounds.bottom - s.height));
        return Rect.fromLTWH(left, top, s.width, s.height);
      }(),
  ];
}

/// Where the pills of a vertical menu go: one above the other, all as wide as
/// the widest, centred on [anchor]'s x (kept inside [bounds]). The first
/// is nearest the button: above it, going up, or, when [bounds] has no room
/// above, below it, going down.
List<Rect> holdFanListLayout({
  required Offset anchor,
  required List<Size> sizes,
  required Rect bounds,
  double lift = 40,
  double gap = 8,
}) {
  if (sizes.isEmpty) return const [];
  final width = sizes.map((s) => s.width).reduce(math.max);
  final total =
      sizes.fold<double>(0, (a, s) => a + s.height) + gap * (sizes.length - 1);
  final above = anchor.dy - lift - total >= bounds.top;
  var left = anchor.dx - width / 2;
  left = left.clamp(bounds.left, math.max(bounds.left, bounds.right - width));
  final rects = <Rect>[];
  if (above) {
    var bottom = anchor.dy - lift;
    for (final s in sizes) {
      rects.add(Rect.fromLTWH(left, bottom - s.height, width, s.height));
      bottom -= s.height + gap;
    }
  } else {
    var top = anchor.dy + lift;
    for (final s in sizes) {
      rects.add(Rect.fromLTWH(left, top, width, s.height));
      top += s.height + gap;
    }
    // Never past the bottom edge.
    final over = rects.last.bottom - bounds.bottom;
    if (over > 0) {
      for (var i = 0; i < rects.length; i++) {
        rects[i] = rects[i].shift(Offset(0, -over));
      }
    }
  }
  return rects;
}

/// The pill under [point], or null: a pill counts a little beyond its edges,
/// and of two candidates the one whose centre is nearer wins.
int? holdFanHit(List<Rect> rects, Offset point, {double slop = 10}) {
  int? best;
  var bestDistance = double.infinity;
  for (var i = 0; i < rects.length; i++) {
    if (!rects[i].inflate(slop).contains(point)) continue;
    final d = (rects[i].center - point).distance;
    if (d < bestDistance) {
      bestDistance = d;
      best = i;
    }
  }
  return best;
}

const _pillStyle = TextStyle(fontSize: 15, fontWeight: FontWeight.w600);
const _pillPadding = EdgeInsets.symmetric(horizontal: 18, vertical: 11);
const _pillMinHeight = 44.0;

/// The widest the pill's outline gets (the default pill's): the decoration
/// takes it off the room for the label, so the pill must be that much bigger.
const _pillBorder = 1.5;

class _HoldFanState<T> extends State<HoldFan<T>>
    with SingleTickerProviderStateMixin {
  late final AnimationController _anim;

  @override
  void initState() {
    super.initState();
    _anim = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 80),
    );
  }

  OverlayEntry? _entry;
  RenderBox? _overlayBox;
  List<HoldFanItem<T>> _shown = const [];
  List<Rect> _rects = const [];
  TextStyle _style = _pillStyle;
  Offset _anchor = Offset.zero;
  final ValueNotifier<int?> _hover = ValueNotifier(null);

  /// Where the hold started, and whether the finger has left it since.
  Offset _downAt = Offset.zero;
  bool _wandered = false;

  /// The fan stays open after the finger lifted and waits for a tap.
  bool _sticky = false;

  /// The fan is open and follows the finger.
  bool get _open => _entry != null && _anim.status != AnimationStatus.reverse;

  @override
  void dispose() {
    _removeEntry();
    _anim.dispose();
    _hover.dispose();
    super.dispose();
  }

  void _removeEntry() {
    _entry?.remove();
    _entry?.dispose();
    _entry = null;
  }

  void _start(LongPressStartDetails details) {
    widget.onOpen?.call();
    final items = widget.items;
    if (items.isEmpty || !mounted) return;
    final overlay = Overlay.maybeOf(context, rootOverlay: true);
    final box = context.findRenderObject() as RenderBox?;
    final overlayBox = overlay?.context.findRenderObject() as RenderBox?;
    if (overlay == null || box == null || overlayBox == null) return;
    _removeEntry();
    _overlayBox = overlayBox;
    _shown = List.of(items);
    _anchor = overlayBox
        .globalToLocal(box.localToGlobal(box.size.center(Offset.zero)));
    // A wide target (a heading): the menu opens over the finger, not over the
    // middle of the row.
    if (widget.width != null) {
      _anchor = Offset(
          overlayBox.globalToLocal(details.globalPosition).dx, _anchor.dy);
    }
    _downAt = details.globalPosition;
    _wandered = false;
    _sticky = false;
    final media = MediaQuery.of(context);
    final scaler = MediaQuery.textScalerOf(context);
    // The overlay's Material styles the pill text with the theme's body
    // style, so measure with that same style or the pills come out too
    // narrow for their labels.
    _style = (Theme.of(context).textTheme.bodyMedium ?? const TextStyle())
        .merge(_pillStyle);
    final bounds = (Offset.zero & overlayBox.size).deflate(8);
    final area = Rect.fromLTRB(
      bounds.left + media.padding.left,
      bounds.top + media.padding.top,
      bounds.right - media.padding.right,
      bounds.bottom,
    );
    final sizes = [
      for (final item in _shown)
        _pillSize(item.text, scaler, _style, area.width),
    ];
    _rects = widget.layout == HoldFanLayout.list
        ? holdFanListLayout(anchor: _anchor, sizes: sizes, bounds: area)
        : holdFanLayout(anchor: _anchor, sizes: sizes, bounds: area);
    _hover.value = null;
    _entry = OverlayEntry(builder: _buildFan);
    overlay.insert(_entry!);
    _anim.forward(from: 0);
    HapticFeedback.selectionClick();
  }

  Size _pillSize(String text, TextScaler scaler, TextStyle style, double max) {
    final painter = TextPainter(
      text: TextSpan(text: text, style: style),
      textDirection: Directionality.of(context),
      textScaler: scaler,
      maxLines: 1,
    )..layout();
    final size = Size(
      math.min(
          max,
          painter.width.ceilToDouble() +
              _pillPadding.horizontal +
              _pillBorder * 2),
      math.max(_pillMinHeight,
          painter.height + _pillPadding.vertical + _pillBorder * 2),
    );
    painter.dispose();
    return size;
  }

  void _move(PointerMoveEvent event) {
    final box = _overlayBox;
    if (!_open || box == null) return;
    if ((event.position - _downAt).distance > kTouchSlop) _wandered = true;
    final local = box.globalToLocal(event.position);
    final hit = holdFanHit(_rects, local);
    if (hit != _hover.value) {
      _hover.value = hit;
      if (hit != null) HapticFeedback.selectionClick();
    }
  }

  void _up(PointerUpEvent event) {
    if (!_open || _sticky) return;
    final box = _overlayBox;
    final hit = box == null
        ? _hover.value
        : holdFanHit(_rects, box.globalToLocal(event.position));
    if (hit == null && !_wandered) {
      // A plain long press: keep the menu up for a tap.
      _sticky = true;
      _entry?.markNeedsBuild();
      return;
    }
    _pick(hit);
  }

  void _pick(int? hit) {
    final items = _shown;
    _close();
    if (hit != null && hit < items.length) widget.onSelected(items[hit].value);
  }

  /// A tap while the fan waits as a menu: a pill picks it, elsewhere closes.
  void _tapSticky(TapUpDetails details) {
    if (!_sticky) return;
    final box = _overlayBox;
    _pick(box == null
        ? null
        : holdFanHit(_rects, box.globalToLocal(details.globalPosition),
            slop: 0));
  }

  void _close() {
    if (_entry == null) return;
    _sticky = false;
    _hover.value = null;
    _anim.reverse().whenCompleteOrCancel(() {
      if (mounted && _anim.status == AnimationStatus.dismissed) _removeEntry();
    });
  }

  /// The same choices as a plain menu, for assistive technology.
  Future<void> _openMenu() async {
    final items = widget.items;
    if (items.isEmpty) return;
    final picked = await showModalBottomSheet<HoldFanItem<T>>(
      context: context,
      builder: (context) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
              child: Text(
                widget.tooltip == null
                    ? widget.menuLabel
                    : '${widget.tooltip}: ${widget.menuLabel.toLowerCase()}',
                style: Theme.of(context).textTheme.titleMedium,
              ),
            ),
            for (final item in items)
              ListTile(
                leading: item.emoji == null ? null : Text(item.emoji!),
                title: Text(item.label),
                onTap: () => Navigator.of(context).pop(item),
              ),
          ],
        ),
      ),
    );
    if (picked != null && mounted) widget.onSelected(picked.value);
  }

  Widget _buildFan(BuildContext context) {
    final c = context.appColors;
    return IgnorePointer(
      ignoring: !_sticky,
      child: GestureDetector(
        key: const ValueKey('hold-fan-menu'),
        behavior: HitTestBehavior.opaque,
        onTapUp: _tapSticky,
        child: Material(
          type: MaterialType.transparency,
          child: AnimatedBuilder(
            animation: _anim,
            builder: (context, _) {
              final t = Curves.easeOutCubic.transform(_anim.value);
              return Stack(
                children: [
                  Positioned.fill(
                    child: Opacity(
                      opacity: t,
                      child: ColoredBox(color: c.overlayDim),
                    ),
                  ),
                  for (var i = 0; i < _rects.length; i++)
                    Positioned.fromRect(
                      rect: _rects[i],
                      child: Transform.translate(
                        offset: (_anchor - _rects[i].center) * (1 - t),
                        child: Transform.scale(
                          scale: 0.6 + 0.4 * t,
                          child: Opacity(
                            opacity: t,
                            child: ValueListenableBuilder<int?>(
                              valueListenable: _hover,
                              builder: (context, hover, _) => _Pill(
                                key: ValueKey('hold-fan-item-$i'),
                                text: _shown[i].text,
                                style: _style,
                                hovered: hover == i,
                                isDefault: widget.defaultIndex == i,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                ],
              );
            },
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final hold = widget.items.isNotEmpty;
    Widget target = InkResponse(
      onTap: widget.onTap,
      radius: widget.size / 2,
      child: SizedBox(
        width: widget.width ?? widget.size,
        height: widget.size,
        child:
            widget.width == null ? Center(child: widget.child) : widget.child,
      ),
    );
    if (widget.tooltip != null) {
      target = Tooltip(
        message: widget.tooltip,
        // A hold opens the fan, not the tooltip.
        triggerMode: TooltipTriggerMode.manual,
        excludeFromSemantics: true,
        child: target,
      );
    }
    if (hold) {
      target = Listener(
        onPointerMove: _move,
        onPointerUp: _up,
        onPointerCancel: (_) {
          if (!_sticky) _close();
        },
        child: RawGestureDetector(
          excludeFromSemantics: true,
          gestures: {
            LongPressGestureRecognizer: GestureRecognizerFactoryWithHandlers<
                LongPressGestureRecognizer>(
              () => LongPressGestureRecognizer(
                  duration: widget.holdDuration, debugOwner: this),
              (r) => r.onLongPressStart = _start,
            ),
          },
          child: target,
        ),
      );
    }
    return Semantics(
      container: true,
      button: true,
      selected: widget.selected,
      label: widget.tooltip,
      onLongPress: hold ? _openMenu : null,
      onLongPressHint: hold ? widget.menuLabel : null,
      customSemanticsActions: hold
          ? {CustomSemanticsAction(label: widget.menuLabel): _openMenu}
          : null,
      child: target,
    );
  }
}

class _Pill extends StatelessWidget {
  final String text;
  final TextStyle style;
  final bool hovered;
  final bool isDefault;

  const _Pill({
    super.key,
    required this.text,
    required this.style,
    required this.hovered,
    required this.isDefault,
  });

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return AnimatedScale(
      scale: hovered ? 1.1 : 1,
      duration: const Duration(milliseconds: 90),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 90),
        alignment: Alignment.center,
        padding: _pillPadding,
        decoration: ShapeDecoration(
          color: hovered ? c.main : c.panelBg,
          shape: StadiumBorder(
            side: BorderSide(
              color: hovered
                  ? c.main
                  : isDefault
                      ? c.main.withValues(alpha: 0.7)
                      : c.border,
              width: isDefault && !hovered ? 1.5 : 1,
            ),
          ),
          shadows: [
            BoxShadow(
              color: hovered ? c.hoverShadow : c.panelShadow,
              blurRadius: hovered ? 14 : 8,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        // The pill is as wide as its label; only a label wider than the
        // screen is shrunk (never cut).
        child: FittedBox(
          fit: BoxFit.scaleDown,
          child: Text(
            text,
            maxLines: 1,
            softWrap: false,
            style: style.copyWith(
              color: hovered ? Colors.white : c.textPrimary,
            ),
          ),
        ),
      ),
    );
  }
}
