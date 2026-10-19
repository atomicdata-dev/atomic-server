import 'package:flutter/material.dart';
import '../theme.dart';

const _widthOptions = [1.0, 2.0, 5.0, 10.0, 18.0, 30.0, 46.0];

class CanvasToolbar extends StatefulWidget {
  final String tool;
  final Color penColor;
  final double penWidth;
  final bool canUndo;
  final bool canRedo;
  final ValueChanged<String> onToolChanged;
  final ValueChanged<Color> onColorChanged;
  final ValueChanged<double> onWidthChanged;
  final VoidCallback onUndo;
  final VoidCallback onRedo;
  // History scrub callbacks
  final VoidCallback onUndoPressStart;
  final ValueChanged<double> onUndoPanDelta; // dx in logical pixels
  final VoidCallback onUndoPanEnd;

  const CanvasToolbar({
    super.key,
    required this.tool,
    required this.penColor,
    required this.penWidth,
    required this.canUndo,
    required this.canRedo,
    required this.onToolChanged,
    required this.onColorChanged,
    required this.onWidthChanged,
    required this.onUndo,
    required this.onRedo,
    required this.onUndoPressStart,
    required this.onUndoPanDelta,
    required this.onUndoPanEnd,
  });

  @override
  State<CanvasToolbar> createState() => _CanvasToolbarState();
}

class _CanvasToolbarState extends State<CanvasToolbar> {
  bool _showColorPicker = false;
  bool _showWidthPicker = false;
  bool _undoDragging = false;

  static const _colors = [
    Colors.white,
    Color(0xFFCCCCCC),
    Color(0xFF888888),
    Color(0xFF555555),
    Colors.red,
    Colors.orange,
    Colors.yellow,
    Colors.green,
    Colors.blue,
    Colors.purple,
    Colors.pink,
    Colors.brown,
  ];

  Widget _toolBtn({
    required IconData icon,
    required String toolName,
    String? label,
    VoidCallback? onTap,
    bool active = false,
    bool enabled = true,
  }) {
    final c = context.appColors;
    final isActive = active || widget.tool == toolName;
    return Tooltip(
      message: label ?? toolName,
      child: GestureDetector(
        onTap: enabled ? (onTap ?? () => widget.onToolChanged(toolName)) : null,
        child: Container(
          width: 48,
          height: 48,
          decoration: BoxDecoration(
            color: isActive
                ? const Color(0xFF1976D2)
                : c.panelBg.withValues(alpha: 0.9),
            shape: BoxShape.circle,
            boxShadow: [BoxShadow(color: c.panelShadow, blurRadius: 4)],
          ),
          child: Icon(icon,
              size: 22,
              color: isActive
                  ? Colors.white
                  : (enabled ? c.iconColor : c.iconDisabled)),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Stack(
      clipBehavior: Clip.none,
      children: [
        Container(
          width: 56,
          decoration: BoxDecoration(
            color: c.panelBg.withValues(alpha: 0.92),
            borderRadius: BorderRadius.circular(28),
            boxShadow: [
              BoxShadow(
                  color: c.panelShadow,
                  blurRadius: 8,
                  offset: const Offset(0, 2))
            ],
          ),
          padding: const EdgeInsets.symmetric(vertical: 10),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Undo — tap = undo, horizontal drag = scrub history
              Tooltip(
                message: 'Undo / scrub history',
                child: GestureDetector(
                  onTapDown: (_) => widget.onUndoPressStart(),
                  onTapUp: (_) {
                    if (!_undoDragging) widget.onUndo();
                    _undoDragging = false;
                    widget.onUndoPanEnd();
                  },
                  onTapCancel: () {
                    _undoDragging = false;
                    widget.onUndoPanEnd();
                  },
                  onHorizontalDragStart: (_) {
                    _undoDragging = true;
                    widget.onUndoPressStart();
                  },
                  onHorizontalDragUpdate: (d) =>
                      widget.onUndoPanDelta(d.delta.dx),
                  onHorizontalDragEnd: (_) {
                    _undoDragging = false;
                    widget.onUndoPanEnd();
                  },
                  child: Container(
                    width: 48,
                    height: 48,
                    decoration: BoxDecoration(
                      color: widget.canUndo
                          ? c.panelBg.withValues(alpha: 0.9)
                          : c.panelBg.withValues(alpha: 0.5),
                      shape: BoxShape.circle,
                      boxShadow: [
                        BoxShadow(color: c.panelShadow, blurRadius: 4)
                      ],
                    ),
                    child: Icon(Icons.undo,
                        size: 22,
                        color: widget.canUndo ? c.iconColor : c.iconDisabled),
                  ),
                ),
              ),
              const SizedBox(height: 4),
              _toolBtn(
                  icon: Icons.redo,
                  toolName: '',
                  label: 'Redo',
                  onTap: widget.onRedo,
                  enabled: widget.canRedo),
              const Divider(height: 16, indent: 8, endIndent: 8),
              _toolBtn(icon: Icons.edit, toolName: 'pen', label: 'Pen'),
              const SizedBox(height: 4),
              _toolBtn(
                  icon: Icons.crop_free, toolName: 'select', label: 'Select'),
              const Divider(height: 16, indent: 8, endIndent: 8),
              // Color swatch
              Tooltip(
                message: 'Color',
                child: GestureDetector(
                  onTap: () => setState(() {
                    _showColorPicker = !_showColorPicker;
                    _showWidthPicker = false;
                  }),
                  child: Container(
                    width: 36,
                    height: 36,
                    decoration: BoxDecoration(
                      color: widget.penColor,
                      shape: BoxShape.circle,
                      border: Border.all(color: c.swatchBorder, width: 2),
                      boxShadow: [
                        BoxShadow(color: c.hoverShadow, blurRadius: 3)
                      ],
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 8),
              // Width button
              Tooltip(
                message: 'Stroke width',
                child: GestureDetector(
                  onTap: () => setState(() {
                    _showWidthPicker = !_showWidthPicker;
                    _showColorPicker = false;
                  }),
                  child: Container(
                    width: 36,
                    height: 36,
                    decoration: BoxDecoration(
                      color: c.panelBg,
                      shape: BoxShape.circle,
                      border: Border.all(color: c.border),
                    ),
                    child: Center(
                      child: Container(
                        width:
                            (widget.penWidth / 46.0 * 24 + 2).clamp(2.0, 26.0),
                        height:
                            (widget.penWidth / 46.0 * 24 + 2).clamp(2.0, 26.0),
                        decoration:
                            BoxDecoration(color: c.dot, shape: BoxShape.circle),
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
        if (_showColorPicker)
          Positioned(
            left: 64,
            top: 0,
            child: Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: c.panelBg.withValues(alpha: 0.95),
                borderRadius: BorderRadius.circular(16),
                boxShadow: [BoxShadow(color: c.hoverShadow, blurRadius: 8)],
              ),
              child: Wrap(
                spacing: 8,
                runSpacing: 8,
                children: _colors.map((col) {
                  final selected = col.toARGB32() == widget.penColor.toARGB32();
                  return GestureDetector(
                    onTap: () {
                      widget.onColorChanged(col);
                      setState(() => _showColorPicker = false);
                    },
                    child: Container(
                      width: 36,
                      height: 36,
                      decoration: BoxDecoration(
                        color: col,
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: selected ? Colors.blue : c.swatchBorder,
                          width: selected ? 3 : 1.5,
                        ),
                      ),
                    ),
                  );
                }).toList(),
              ),
            ),
          ),
        if (_showWidthPicker)
          Positioned(
            left: 64,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: BoxDecoration(
                color: c.panelBg.withValues(alpha: 0.95),
                borderRadius: BorderRadius.circular(16),
                boxShadow: [BoxShadow(color: c.hoverShadow, blurRadius: 8)],
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: _widthOptions.map((w) {
                  final selected = w == widget.penWidth;
                  return GestureDetector(
                    onTap: () {
                      widget.onWidthChanged(w);
                      setState(() => _showWidthPicker = false);
                    },
                    child: Container(
                      width: 120,
                      height: 36,
                      decoration: BoxDecoration(
                        color:
                            selected ? c.widthSelectedBg : Colors.transparent,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Center(
                        child: Container(
                          width: 80,
                          height: w.clamp(1.5, 30),
                          decoration: BoxDecoration(
                            color: c.dot,
                            borderRadius: BorderRadius.circular(w / 2),
                          ),
                        ),
                      ),
                    ),
                  );
                }).toList(),
              ),
            ),
          ),
      ],
    );
  }
}
