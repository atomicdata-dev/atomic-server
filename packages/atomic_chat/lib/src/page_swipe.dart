import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';

import 'app_shell.dart' show ShellLayout, ShellScope;
import 'slide_back_route.dart';

/// The swipe back over a web view. The web view takes every touch, so the
/// page-wide drag of [SlideBackRoute] never sees one. This reads the raw
/// pointer events (a translucent [Listener]: the web view still gets all of
/// them) and, for a clearly rightward drag, drives the route's slide with the
/// finger. A vertical drag, a leftward one, a drag the page claimed for itself
/// ([blocked], e.g. a canvas) and a touch that starts in the system's back
/// gesture zone are left alone.
class PageSwipe extends StatefulWidget {
  /// Whether the page wants horizontal drags itself right now.
  final bool Function() blocked;

  const PageSwipe({super.key, required this.blocked});

  /// How far a finger moves before the drag is judged (a tap stays a tap).
  static const slop = 18.0;

  @override
  State<PageSwipe> createState() => _PageSwipeState();
}

enum _Phase { idle, undecided, rejected, claimed }

class _PageSwipeState extends State<PageSwipe> {
  _Phase _phase = _Phase.idle;
  int? _pointer;
  Offset _origin = Offset.zero;
  Offset _last = Offset.zero;
  VelocityTracker? _velocity;
  SlideBackRoute<dynamic>? _route;

  void _down(PointerDownEvent e) {
    if (_pointer != null) {
      // A second finger (pinch, two-finger pan) is never a swipe back.
      if (_phase == _Phase.claimed) _finish(cancel: true);
      _phase = _Phase.rejected;
      return;
    }
    final route = ModalRoute.of(context);
    final inset = MediaQuery.maybeOf(context)?.systemGestureInsets.left ?? 0;
    _pointer = e.pointer;
    _origin = _last = e.position;
    _velocity = VelocityTracker.withKind(e.kind);
    _velocity!.addPosition(e.timeStamp, e.position);
    _route = route is SlideBackRoute ? route : null;
    final split = ShellScope.maybeOf(context) != null &&
        ShellScope.layoutOf(context) == ShellLayout.split;
    _phase = _route == null || split || e.position.dx < inset
        ? _Phase.rejected
        : _Phase.undecided;
  }

  void _move(PointerMoveEvent e) {
    if (e.pointer != _pointer) return;
    _velocity?.addPosition(e.timeStamp, e.position);
    switch (_phase) {
      case _Phase.undecided:
        final d = e.position - _origin;
        if (d.dx.abs() < PageSwipe.slop && d.dy.abs() < PageSwipe.slop) return;
        if (d.dx > PageSwipe.slop &&
            d.dx > 2 * d.dy.abs() &&
            !widget.blocked() &&
            _route!.beginHandDrag()) {
          _phase = _Phase.claimed;
          _last = e.position;
        } else {
          _phase = _Phase.rejected;
        }
      case _Phase.claimed:
        _route?.updateHandDrag(e.position.dx - _last.dx);
        _last = e.position;
      case _Phase.idle || _Phase.rejected:
        break;
    }
  }

  void _up(PointerUpEvent e) {
    if (e.pointer != _pointer) return;
    _finish(cancel: false);
  }

  void _cancel(PointerCancelEvent e) {
    if (e.pointer != _pointer) return;
    _finish(cancel: true);
  }

  void _finish({required bool cancel}) {
    if (_phase == _Phase.claimed) {
      if (cancel) {
        _route?.cancelHandDrag();
      } else {
        _route?.endHandDrag(_velocity?.getVelocity().pixelsPerSecond.dx ?? 0);
      }
    }
    _phase = _Phase.idle;
    _pointer = null;
    _velocity = null;
  }

  @override
  void dispose() {
    if (_phase == _Phase.claimed) _route?.cancelHandDrag();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Listener(
        behavior: HitTestBehavior.translucent,
        onPointerDown: _down,
        onPointerMove: _move,
        onPointerUp: _up,
        onPointerCancel: _cancel,
        child: const SizedBox.expand(),
      );
}
