import 'package:flutter/material.dart';

/// The pointer over anything tappable: [SystemMouseCursors.click] when
/// [enabled], the plain arrow otherwise. Material buttons and InkWells already
/// do this; wrap custom `GestureDetector` / `Listener` controls in this so every
/// control behaves the same.
class ClickCursor extends StatelessWidget {
  final bool enabled;
  final Widget child;

  const ClickCursor({super.key, required this.enabled, required this.child});

  @override
  Widget build(BuildContext context) => MouseRegion(
        cursor: enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
        child: child,
      );
}
