import 'package:flutter/material.dart';

/// The atomic.place mark (brand/src/place-mark-mono.svg): an orb inside a
/// sweep, drawn in [color] so it follows the theme like the other icons.
class AtomicPlaceMark extends StatelessWidget {
  final double size;

  /// Defaults to the surrounding icon colour (so it follows an IconButton).
  final Color? color;

  const AtomicPlaceMark({super.key, this.size = 24, this.color});

  @override
  Widget build(BuildContext context) => SizedBox.square(
        dimension: size,
        child: CustomPaint(
            painter: _MarkPainter(
                color ?? IconTheme.of(context).color ?? Colors.white)),
      );
}

class _MarkPainter extends CustomPainter {
  final Color color;

  const _MarkPainter(this.color);

  @override
  void paint(Canvas canvas, Size size) {
    final unit = size.width / 100;
    canvas.save();
    canvas.scale(unit);
    // The source is a 100x100 box with the whole mark shifted up by 2.
    canvas.translate(0, -2);
    final stroke = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 14
      ..strokeCap = StrokeCap.round;
    // M74 52 A 24 24 0 1 1 50 28: three quarters of a circle around (50, 52),
    // from the right, clockwise, to the top.
    canvas.drawArc(
      Rect.fromCircle(center: const Offset(50, 52), radius: 24),
      0,
      3 * 3.141592653589793 / 2,
      false,
      stroke,
    );
    canvas.drawCircle(const Offset(50, 52), 12, Paint()..color = color);
    canvas.restore();
  }

  @override
  bool shouldRepaint(_MarkPainter old) => old.color != color;
}
