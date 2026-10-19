import 'package:flutter/material.dart';
import 'package:flutter/physics.dart';

import 'covered_insets_freeze.dart';

/// A page that slides in from the right over the page it was opened from, and
/// that the whole page can be dragged back to the right to leave: the page
/// below is there on the left while it moves. The back button and the system
/// back run the same slide.
class SlideBackRoute<T> extends PageRouteBuilder<T> {
  SlideBackRoute({required WidgetBuilder builder})
      : super(
          pageBuilder: (context, _, __) =>
              CoveredInsetsFreeze(child: builder(context)),
          transitionDuration: const Duration(milliseconds: 380),
          reverseTransitionDuration: const Duration(milliseconds: 320),
        );

  /// Work the page must finish before it is gone (an embedded page handing
  /// over its last edits). A swipe that leaves slides the page out at once,
  /// then waits for this before the route is removed. The page itself sets it
  /// ([ModalRoute.of]); the back button and the system back go through its
  /// `PopScope` instead.
  Future<void> Function()? beforeSwipeLeave;

  /// A finger or a spring is moving the page: its position is the animation's
  /// value as it is. Otherwise (a push, the back button) the value goes
  /// through a curve that starts fast and settles slowly.
  bool _byHand = false;

  @override
  Widget buildTransitions(BuildContext context, Animation<double> animation,
      Animation<double> secondaryAnimation, Widget child) {
    return AnimatedBuilder(
      animation: animation,
      child: _SwipeBack(route: this, child: child),
      builder: (context, child) {
        final t = _byHand
            ? animation.value
            : animation.status == AnimationStatus.reverse
                ? Curves.easeInCubic.transform(animation.value)
                : Curves.easeOutCubic.transform(animation.value);
        return FractionalTranslation(
          translation: Offset(1 - t, 0),
          child: DecoratedBox(
            decoration: BoxDecoration(
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.35 * t),
                  blurRadius: 16,
                ),
              ],
            ),
            child: child,
          ),
        );
      },
    );
  }
}

class _SwipeBack extends StatefulWidget {
  final SlideBackRoute<dynamic> route;
  final Widget child;

  const _SwipeBack({required this.route, required this.child});

  @override
  State<_SwipeBack> createState() => _SwipeBackState();
}

class _SwipeBackState extends State<_SwipeBack> {
  bool _dragging = false;

  AnimationController? get _controller =>
      // ignore: invalid_use_of_protected_member
      widget.route.controller;

  void _start(DragStartDetails _) {
    if (!widget.route.isCurrent || !widget.route.navigator!.canPop()) return;
    _dragging = true;
    widget.route._byHand = true;
    widget.route.navigator!.didStartUserGesture();
  }

  void _update(DragUpdateDetails d) {
    final controller = _controller;
    if (!_dragging || controller == null) return;
    final width = context.size?.width ?? 1;
    controller.value = (controller.value - d.primaryDelta! / width).clamp(0, 1);
  }

  void _end(DragEndDetails d) {
    final controller = _controller;
    if (!_dragging || controller == null) return;
    _dragging = false;
    final navigator = widget.route.navigator!;
    final width = context.size?.width ?? 1;
    // Units of the page's width per second, moving right.
    final velocity = d.velocity.pixelsPerSecond.dx / width;
    final leave = velocity.abs() > 1 ? velocity > 0 : controller.value < 0.5;
    if (leave) {
      // Out: as long as the page still has to travel, at the speed the finger
      // had (not slower than a gentle push), slowing down as it goes.
      final route = widget.route;
      final hold = route.beforeSwipeLeave;
      if (hold == null) navigator.pop();
      final seconds = controller.value / velocity.clamp(1.2, 6.0);
      final out = controller.animateBack(0,
          duration:
              Duration(milliseconds: (seconds * 1000).clamp(140, 420).round()),
          curve: Curves.easeOutCubic);
      if (hold != null) {
        // Gone once it is out of sight and the page is done. Removed rather
        // than popped: its animation has nothing left to run.
        Future.wait([
          out.orCancel.catchError((_) {}),
          hold().catchError((_) {}),
        ]).whenComplete(() {
          if (route.isActive) navigator.removeRoute(route);
        });
      }
    } else {
      // Back in: a spring with the finger's speed, so a quick flick back
      // overshoots the decision and settles.
      controller.animateWith(SpringSimulation(
        const SpringDescription(mass: 1, stiffness: 380, damping: 38),
        controller.value,
        1,
        -velocity,
      ));
    }
    void done(AnimationStatus status) {
      if (!controller.isAnimating) {
        controller.removeStatusListener(done);
        widget.route._byHand = false;
        navigator.didStopUserGesture();
      }
    }

    controller.addStatusListener(done);
  }

  void _cancel() {
    if (!_dragging) return;
    _dragging = false;
    _controller?.animateTo(1, duration: const Duration(milliseconds: 200));
    widget.route._byHand = false;
    widget.route.navigator!.didStopUserGesture();
  }

  @override
  Widget build(BuildContext context) => GestureDetector(
        behavior: HitTestBehavior.translucent,
        onHorizontalDragStart: _start,
        onHorizontalDragUpdate: _update,
        onHorizontalDragEnd: _end,
        onHorizontalDragCancel: _cancel,
        child: widget.child,
      );
}
