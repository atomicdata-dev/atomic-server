import 'package:flutter/gestures.dart' show PointerDeviceKind;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show HapticFeedback;

/// Clamping scroll physics with the Android 12 stretch for overscroll: the
/// content never leaves the edge (pixels stay within the scroll extent), and
/// [StretchingOverscrollIndicator] stretches it a little instead. Used on
/// every platform.
///
/// Fling decision: the in-range fling is [ClampingScrollPhysics]' (Android
/// deceleration), not the iOS one; [BouncingScrollPhysics]' simulation
/// overscrolls and springs back, which is exactly what this replaces. A fling
/// into an edge still shows the stretch, scaled by its velocity.
///
/// The stock range-maintaining parent is kept so content growing above the
/// viewport does not jump, and [AlwaysScrollableScrollPhysics] so short lists
/// can still be pulled (for pull-to-refresh and the stretch).
class AppScrollPhysics extends ClampingScrollPhysics {
  const AppScrollPhysics({ScrollPhysics? parent})
      : super(
            parent: parent ??
                const RangeMaintainingScrollPhysics(
                    parent: AlwaysScrollableScrollPhysics()));

  @override
  AppScrollPhysics applyTo(ScrollPhysics? ancestor) =>
      AppScrollPhysics(parent: buildParent(ancestor));
}

/// Installs [AppScrollPhysics] on every scrollable below it, and the
/// [StretchingOverscrollIndicator] on every platform (stock only does so on
/// Android).
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
      _OverscrollHaptic(
          child: StretchingOverscrollIndicator(
              axisDirection: details.direction, child: child));
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
    } else if (n is OverscrollNotification && n.dragDetails != null && !_ticked) {
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
