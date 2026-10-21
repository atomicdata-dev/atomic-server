import 'dart:math' as math;

import 'package:flutter/gestures.dart' show PointerDeviceKind;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show HapticFeedback;

/// A mild iOS-like rubber band for every scrollable, on Android too (the
/// embedded web views bounce the same way): firmer than
/// [BouncingScrollPhysics] while dragging past an edge, and a quick,
/// critically damped return with no wobble.
///
/// Only [frictionFactor] and [spring] differ from stock iOS; the fling
/// (deceleration, velocities, drag threshold, momentum carry) is inherited
/// unchanged, `ScrollDecelerationRate.normal`. The stock range-maintaining
/// parent is kept so content growing above the viewport does not jump.
class AppScrollPhysics extends BouncingScrollPhysics {
  const AppScrollPhysics({ScrollPhysics? parent})
      : super(
            parent: parent ??
                const RangeMaintainingScrollPhysics(
                    parent: AlwaysScrollableScrollPhysics()));

  @override
  AppScrollPhysics applyTo(ScrollPhysics? ancestor) =>
      AppScrollPhysics(parent: buildParent(ancestor));

  /// iOS uses 0.52 * (1 - fraction)^2.
  @override
  double frictionFactor(double overscrollFraction) =>
      0.35 * math.pow(1 - overscrollFraction, 2);

  /// Critically damped (ratio 1.0): settles without crossing the edge.
  @override
  SpringDescription get spring =>
      SpringDescription.withDampingRatio(mass: 0.5, stiffness: 130, ratio: 1.0);
}

/// Installs [AppScrollPhysics] on every scrollable below it, without the
/// Android glow or stretch indicator.
class AppScrollBehavior extends MaterialScrollBehavior {
  const AppScrollBehavior();

  @override
  Set<PointerDeviceKind> get dragDevices => const {
        PointerDeviceKind.touch,
        PointerDeviceKind.mouse,
        PointerDeviceKind.stylus,
        PointerDeviceKind.trackpad,
      };

  @override
  ScrollPhysics getScrollPhysics(BuildContext context) =>
      const AppScrollPhysics();

  @override
  Widget buildOverscrollIndicator(
          BuildContext context, Widget child, ScrollableDetails details) =>
      _OverscrollHaptic(child: child);
}

/// A very light tick, once per drag, when the finger pulls a list past its
/// end: feedback that the touch was registered. Not for flings.
class _OverscrollHaptic extends StatefulWidget {
  final Widget child;
  const _OverscrollHaptic({required this.child});

  @override
  State<_OverscrollHaptic> createState() => _OverscrollHapticState();
}

class _OverscrollHapticState extends State<_OverscrollHaptic> {
  bool _ticked = false;
  DateTime _last = DateTime.fromMillisecondsSinceEpoch(0);

  bool _onScroll(ScrollNotification n) {
    if (n.depth != 0) return false;
    if (n is ScrollStartNotification || n is ScrollEndNotification) {
      _ticked = false;
    } else if (n is ScrollUpdateNotification &&
        n.dragDetails != null &&
        n.metrics.outOfRange &&
        !_ticked) {
      _ticked = true;
      final now = DateTime.now();
      if (now.difference(_last) > const Duration(milliseconds: 250)) {
        _last = now;
        HapticFeedback.selectionClick();
      }
    }
    return false;
  }

  @override
  Widget build(BuildContext context) =>
      NotificationListener<ScrollNotification>(
          onNotification: _onScroll, child: widget.child);
}
