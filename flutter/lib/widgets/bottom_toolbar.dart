import 'dart:async';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import '../canvas/fan_helpers.dart';
import '../theme.dart';
import 'fan_overlay.dart';

class BottomToolbar extends StatefulWidget {
  final Color penColor;
  final double penWidth;
  final bool canUndo;
  final bool canRedo;
  final bool eraserMode;
  final VoidCallback onEraserToggle;
  // Fan
  final ValueChanged<({FanType type, Offset center})> onFanOpen;
  final ValueChanged<Offset> onFanDrag;
  final VoidCallback onFanClose;
  // Taps
  final VoidCallback onColorTap;
  final VoidCallback onWidthTap;
  final VoidCallback onUndo;
  final VoidCallback onRedo;
  // History scrub
  final VoidCallback onUndoPressStart;
  final ValueChanged<double> onUndoPanDelta;
  final VoidCallback onUndoPanEnd;
  // Navigation
  final VoidCallback onGallery;
  final VoidCallback onNewCanvas;
  // Zoom
  final VoidCallback onZoomToFit;
  final VoidCallback onZoomScrubStart;
  final ValueChanged<double> onZoomScrubDelta;
  final VoidCallback onZoomScrubEnd;
  // Peek / overlay state
  final void Function(FanType type, Offset center) onPeek;
  final VoidCallback onPeekEnd;
  final VoidCallback onPeekHistory;
  final VoidCallback onPeekZoom;
  final FanType? activeFan; // non-null when fan overlay is showing
  final bool historyMode; // true when history scrubber is showing
  final bool zoomMode; // true when zoom scrubber is showing

  const BottomToolbar({
    super.key,
    required this.penColor,
    required this.penWidth,
    required this.canUndo,
    required this.canRedo,
    required this.eraserMode,
    required this.onEraserToggle,
    required this.onFanOpen,
    required this.onFanDrag,
    required this.onFanClose,
    required this.onColorTap,
    required this.onWidthTap,
    required this.onUndo,
    required this.onRedo,
    required this.onUndoPressStart,
    required this.onUndoPanDelta,
    required this.onUndoPanEnd,
    required this.onGallery,
    required this.onNewCanvas,
    required this.onZoomToFit,
    required this.onZoomScrubStart,
    required this.onZoomScrubDelta,
    required this.onZoomScrubEnd,
    required this.onPeek,
    required this.onPeekEnd,
    required this.onPeekHistory,
    required this.onPeekZoom,
    this.activeFan,
    this.historyMode = false,
    this.zoomMode = false,
  });

  @override
  State<BottomToolbar> createState() => _BottomToolbarState();
}

class _BottomToolbarState extends State<BottomToolbar> {
  final _colorKey = GlobalKey();
  final _widthKey = GlobalKey();

  Offset _buttonCenter(GlobalKey key) {
    final box = key.currentContext!.findRenderObject() as RenderBox;
    return box.localToGlobal(Offset(box.size.width / 2, box.size.height / 2));
  }

  /// Whether overlays are active (fan or history scrubber showing).
  bool get _overlayActive =>
      widget.activeFan != null || widget.historyMode || widget.zoomMode;

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final isCompact = MediaQuery.of(context).size.width < 500;
    final btnSize = isCompact ? 40.0 : 48.0;
    final fraction = (widget.penWidth - widthOptions.first) /
        (widthOptions.last - widthOptions.first);
    final dotSize =
        (4 + fraction.clamp(0, 1) * (isCompact ? 20 : 28)).toDouble();
    final af = widget.activeFan;
    final hm = widget.historyMode;

    // Color swatch button (always built so GlobalKey stays mounted)
    final colorBtn = _HoverCircle(
      builder: (hovered) => Listener(
        onPointerDown: (_) {
          widget.onPeek(FanType.color, _buttonCenter(_colorKey));
        },
        onPointerUp: (_) {
          if (widget.activeFan == null) {
            widget.onPeekEnd();
            widget.onColorTap();
          }
        },
        child: GestureDetector(
          key: _colorKey,
          onPanStart: (_) {
            widget.onFanOpen(
                (type: FanType.color, center: _buttonCenter(_colorKey)));
          },
          onPanUpdate: (d) => widget.onFanDrag(d.delta),
          onPanEnd: (_) => widget.onFanClose(),
          child: Builder(
            builder: (ctx) {
              final isDark = Theme.of(ctx).brightness == Brightness.dark;
              return Container(
                width: btnSize,
                height: btnSize,
                decoration: BoxDecoration(
                  color: adjustColorForDarkMode(widget.penColor, isDark),
                  shape: BoxShape.circle,
                  border: Border.all(color: c.border, width: 2),
                  boxShadow: hovered
                      ? [
                          BoxShadow(
                              color: c.hoverShadow,
                              blurRadius: 8,
                              spreadRadius: 1)
                        ]
                      : null,
                ),
              );
            },
          ),
        ),
      ),
    );

    // Width dot button (always built so GlobalKey stays mounted)
    final widthBtn = _HoverCircle(
      builder: (hovered) => Listener(
        onPointerDown: (_) {
          widget.onPeek(FanType.width, _buttonCenter(_widthKey));
        },
        onPointerUp: (_) {
          if (widget.activeFan == null) {
            widget.onPeekEnd();
            widget.onWidthTap();
          }
        },
        child: GestureDetector(
          key: _widthKey,
          onPanStart: (_) {
            widget.onFanOpen(
                (type: FanType.width, center: _buttonCenter(_widthKey)));
          },
          onPanUpdate: (d) => widget.onFanDrag(d.delta),
          onPanEnd: (_) => widget.onFanClose(),
          child: Container(
            width: btnSize,
            height: btnSize,
            decoration: BoxDecoration(
              color: c.panelBg.withValues(alpha: hovered ? 1.0 : 0.9),
              shape: BoxShape.circle,
              border: Border.all(color: c.border),
              boxShadow: hovered
                  ? [
                      BoxShadow(
                          color: c.hoverShadow, blurRadius: 6, spreadRadius: 1)
                    ]
                  : null,
            ),
            child: Center(
              child: Container(
                width: dotSize.clamp(4, 36),
                height: dotSize.clamp(4, 36),
                decoration: BoxDecoration(
                  color: c.dot,
                  shape: BoxShape.circle,
                ),
              ),
            ),
          ),
        ),
      ),
    );

    // Undo button (always built for consistency)
    final undoBtn = _UndoButton(
      canUndo: widget.canUndo,
      onPeekHistory: widget.onPeekHistory,
      onPeekEnd: widget.onPeekEnd,
      onUndo: widget.onUndo,
      onUndoPressStart: widget.onUndoPressStart,
      onUndoPanDelta: widget.onUndoPanDelta,
      onUndoPanEnd: widget.onUndoPanEnd,
      iconColor: c.iconColor,
      iconDisabled: c.iconDisabled,
    );

    // Which button is "active" during overlay
    final bool colorActive = af == FanType.color;
    final bool widthActive = af == FanType.width;
    final bool undoActive = hm;
    final bool zoomActive = widget.zoomMode;

    Widget maybeHide(Widget child, bool isActive) {
      if (!_overlayActive || isActive) return child;
      return Opacity(opacity: 0, child: IgnorePointer(child: child));
    }

    // Gallery button
    final galleryBtn = _HoverCircle(
      builder: (hovered) => GestureDetector(
        onTap: widget.onGallery,
        child: _CircleBtn(
          hovered: hovered,
          child: Icon(Icons.grid_view, size: 22, color: c.iconColor),
        ),
      ),
    );

    // New canvas button
    final newBtn = _HoverCircle(
      builder: (hovered) => GestureDetector(
        onTap: widget.onNewCanvas,
        child: _CircleBtn(
          hovered: hovered,
          child: Icon(Icons.add, size: 24, color: c.iconColor),
        ),
      ),
    );

    // Redo button
    final redoBtn = _HoverCircle(
      builder: (hovered) => GestureDetector(
        onTap: widget.canRedo ? widget.onRedo : null,
        child: _CircleBtn(
          hovered: hovered,
          enabled: widget.canRedo,
          child: Icon(Icons.redo,
              size: 22, color: widget.canRedo ? c.iconColor : c.iconDisabled),
        ),
      ),
    );

    // Zoom button
    final zoomBtn = _HoverCircle(
      builder: (hovered) => Listener(
        onPointerDown: (_) => widget.onPeekZoom(),
        onPointerUp: (_) {
          widget.onPeekEnd();
          widget.onZoomToFit();
        },
        child: GestureDetector(
          onHorizontalDragStart: (_) => widget.onZoomScrubStart(),
          onHorizontalDragUpdate: (d) => widget.onZoomScrubDelta(d.delta.dx),
          onHorizontalDragEnd: (_) => widget.onZoomScrubEnd(),
          child: _CircleBtn(
            hovered: hovered,
            child: Icon(Icons.zoom_out_map, size: 22, color: c.iconColor),
          ),
        ),
      ),
    );

    // Eraser button
    final eraserBtn = _HoverCircle(
      builder: (hovered) => GestureDetector(
        onTap: widget.onEraserToggle,
        child: _CircleBtn(
          hovered: hovered,
          child: Icon(
            widget.eraserMode ? Icons.edit : Icons.delete_outline,
            size: 22,
            color: widget.eraserMode ? c.iconColor : c.iconColor,
          ),
        ),
      ),
    );

    final buttons = [
      maybeHide(galleryBtn, false),
      maybeHide(newBtn, false),
      maybeHide(eraserBtn, false),
      maybeHide(colorBtn, colorActive),
      maybeHide(widthBtn, widthActive),
      maybeHide(undoBtn, undoActive),
      maybeHide(redoBtn, false),
      maybeHide(zoomBtn, zoomActive),
    ];

    if (isCompact) {
      // Full-width row for small screens, respects system nav bar
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 6),
        color: _overlayActive
            ? Colors.transparent
            : c.panelBg.withValues(alpha: 0.95),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: buttons,
        ),
      );
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      decoration: BoxDecoration(
        color: _overlayActive
            ? Colors.transparent
            : c.panelBg.withValues(alpha: 0.88),
        borderRadius: BorderRadius.circular(32),
        boxShadow: _overlayActive
            ? null
            : [
                BoxShadow(
                    color: c.panelShadow,
                    blurRadius: 12,
                    offset: const Offset(0, 3)),
              ],
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          for (int i = 0; i < buttons.length; i++) ...[
            if (i > 0) const SizedBox(width: 6),
            buttons[i],
          ],
        ],
      ),
    );
  }
}

/// Simple circle button container with hover support.
class _CircleBtn extends StatelessWidget {
  final bool hovered;
  final bool enabled;
  final Widget child;

  const _CircleBtn({
    required this.hovered,
    this.enabled = true,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final isCompact = MediaQuery.of(context).size.width < 500;
    final size = isCompact ? 40.0 : 48.0;
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color:
            c.panelBg.withValues(alpha: enabled ? (hovered ? 1.0 : 0.9) : 0.5),
        shape: BoxShape.circle,
        boxShadow: hovered && enabled
            ? [BoxShadow(color: c.hoverShadow, blurRadius: 6, spreadRadius: 1)]
            : null,
      ),
      child: Center(child: child),
    );
  }
}

/// Tracks mouse/stylus hover and exposes it to [builder].
class _HoverCircle extends StatefulWidget {
  final Widget Function(bool hovered) builder;
  const _HoverCircle({required this.builder});

  @override
  State<_HoverCircle> createState() => _HoverCircleState();
}

class _HoverCircleState extends State<_HoverCircle> {
  bool _hovered = false;
  Timer? _stylusExitTimer;

  void _setHovered(bool v) {
    if (_hovered != v) setState(() => _hovered = v);
  }

  @override
  void dispose() {
    _stylusExitTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MouseRegion(
      onEnter: (_) => _setHovered(true),
      onExit: (_) => _setHovered(false),
      child: Listener(
        onPointerHover: (e) {
          if (e.kind == PointerDeviceKind.stylus ||
              e.kind == PointerDeviceKind.invertedStylus) {
            _setHovered(true);
            _stylusExitTimer?.cancel();
            _stylusExitTimer = Timer(
              const Duration(milliseconds: 50),
              () => _setHovered(false),
            );
          }
        },
        child: widget.builder(_hovered),
      ),
    );
  }
}

/// Undo button with tap-to-undo and drag-to-scrub.
/// Tracks whether a drag happened to avoid undoing on pointer-up after a scrub.
class _UndoButton extends StatefulWidget {
  final bool canUndo;
  final VoidCallback onPeekHistory;
  final VoidCallback onPeekEnd;
  final VoidCallback onUndo;
  final VoidCallback onUndoPressStart;
  final ValueChanged<double> onUndoPanDelta;
  final VoidCallback onUndoPanEnd;
  final Color iconColor;
  final Color iconDisabled;

  const _UndoButton({
    required this.canUndo,
    required this.onPeekHistory,
    required this.onPeekEnd,
    required this.onUndo,
    required this.onUndoPressStart,
    required this.onUndoPanDelta,
    required this.onUndoPanEnd,
    required this.iconColor,
    required this.iconDisabled,
  });

  @override
  State<_UndoButton> createState() => _UndoButtonState();
}

class _UndoButtonState extends State<_UndoButton> {
  bool _scrubStarted = false;
  double? _startX;

  @override
  Widget build(BuildContext context) {
    return _HoverCircle(
      builder: (hovered) => Listener(
        onPointerDown: widget.canUndo
            ? (e) {
                _scrubStarted = false;
                _startX = e.position.dx;
                widget.onPeekHistory();
              }
            : null,
        onPointerMove: widget.canUndo
            ? (e) {
                if (_startX == null) return;
                final dx = e.position.dx - _startX!;
                if (!_scrubStarted && dx.abs() > 5) {
                  _scrubStarted = true;
                  widget.onUndoPressStart();
                }
                if (_scrubStarted) {
                  widget.onUndoPanDelta(e.delta.dx);
                }
              }
            : null,
        onPointerUp: widget.canUndo
            ? (_) {
                if (_scrubStarted) {
                  widget.onUndoPanEnd();
                } else {
                  widget.onPeekEnd();
                  widget.onUndo();
                }
                _startX = null;
                _scrubStarted = false;
              }
            : null,
        onPointerCancel: widget.canUndo
            ? (_) {
                widget.onPeekEnd();
                _startX = null;
                _scrubStarted = false;
              }
            : null,
        child: _CircleBtn(
          hovered: hovered,
          enabled: widget.canUndo,
          child: Icon(Icons.undo,
              size: 22,
              color: widget.canUndo ? widget.iconColor : widget.iconDisabled),
        ),
      ),
    );
  }
}
