import 'dart:math' as math;

import 'package:flutter/material.dart';

/// The camera preview of the QR scanner at the camera's own shape: a rounded
/// 16 dp frame as wide as the screen less 16 dp gutters (at most 520 dp), as
/// tall as the camera's aspect ratio makes it (at most 65% of the screen), in
/// the screen's orientation. A portrait phone shows a portrait preview, not
/// a wide strip; a landscape one shows it wide.
///
/// The preview inside is cropped with `BoxFit.cover`, which is lossless because
/// the frame has the camera's aspect ratio. A scan area of corner brackets
/// (70% of the frame's shorter side) is drawn in the middle, and the torch and
/// camera switch stay inside the frame.
class ScannerFrame extends StatelessWidget {
  const ScannerFrame({
    super.key,
    required this.cameraSize,
    required this.child,
    this.onTorch,
    this.onFlip,
  });

  /// The size the camera reports for its preview, in either orientation; zero
  /// or null while it is not known (a portrait 3:4 is used then).
  final Size? cameraSize;
  final Widget child;
  final VoidCallback? onTorch;
  final VoidCallback? onFlip;

  /// The frame's width and height for a camera of [cameraSize] on a [screen]
  /// held [portrait] or not.
  static Size frameSize(Size screen, Size? cameraSize,
      {required bool portrait}) {
    var aspect = 3 / 4;
    final camera = cameraSize;
    if (camera != null && camera.width > 0 && camera.height > 0) {
      aspect = camera.width / camera.height;
      // Sensors report landscape; the preview is turned to the screen.
      if (portrait && aspect > 1 || !portrait && aspect < 1) {
        aspect = 1 / aspect;
      }
    } else if (!portrait) {
      aspect = 4 / 3;
    }
    final maxWidth = math.min(screen.width - 32, 520.0);
    final maxHeight = screen.height * 0.65;
    var width = maxWidth;
    var height = width / aspect;
    if (height > maxHeight) {
      height = maxHeight;
      width = height * aspect;
    }
    return Size(width, height);
  }

  @override
  Widget build(BuildContext context) {
    final media = MediaQuery.of(context);
    final size = frameSize(media.size, cameraSize,
        portrait: media.orientation == Orientation.portrait);
    return Center(
      child: SizedBox(
        key: const Key('scanner-frame'),
        width: size.width,
        height: size.height,
        child: ClipRRect(
          borderRadius: BorderRadius.circular(16),
          child: Stack(fit: StackFit.expand, children: [
            ColoredBox(color: Colors.black, child: child),
            IgnorePointer(child: CustomPaint(painter: _Brackets(size))),
            if (onFlip != null)
              Positioned(
                left: 8,
                bottom: 8,
                child: _RoundButton(
                    icon: Icons.cameraswitch_outlined,
                    tooltip: 'Switch camera',
                    onPressed: onFlip!),
              ),
            if (onTorch != null)
              Positioned(
                right: 8,
                bottom: 8,
                child: _RoundButton(
                    icon: Icons.flashlight_on_outlined,
                    tooltip: 'Torch',
                    onPressed: onTorch!),
              ),
          ]),
        ),
      ),
    );
  }
}

class _RoundButton extends StatelessWidget {
  const _RoundButton(
      {required this.icon, required this.tooltip, required this.onPressed});

  final IconData icon;
  final String tooltip;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) => IconButton(
        tooltip: tooltip,
        onPressed: onPressed,
        icon: Icon(icon, size: 24),
        color: Colors.white,
        style: IconButton.styleFrom(
          backgroundColor: Colors.black54,
          minimumSize: const Size(48, 48),
        ),
      );
}

/// Four corner brackets around a square of 70% of the frame's shorter side.
class _Brackets extends CustomPainter {
  _Brackets(this.size);

  final Size size;

  @override
  void paint(Canvas canvas, Size _) {
    final side = math.min(size.width, size.height) * 0.7;
    final box = Rect.fromCenter(
        center: Offset(size.width / 2, size.height / 2),
        width: side,
        height: side);
    final arm = side * 0.18;
    final paint = Paint()
      ..color = Colors.white
      ..style = PaintingStyle.stroke
      ..strokeWidth = 3
      ..strokeCap = StrokeCap.round;
    for (final (corner, dx, dy) in [
      (box.topLeft, 1.0, 1.0),
      (box.topRight, -1.0, 1.0),
      (box.bottomLeft, 1.0, -1.0),
      (box.bottomRight, -1.0, -1.0),
    ]) {
      canvas.drawLine(corner, corner + Offset(arm * dx, 0), paint);
      canvas.drawLine(corner, corner + Offset(0, arm * dy), paint);
    }
  }

  @override
  bool shouldRepaint(_Brackets old) => old.size != size;
}
