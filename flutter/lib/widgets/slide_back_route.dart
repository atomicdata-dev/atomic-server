import 'package:flutter/material.dart';

/// A page that slides in from the right over the page it was opened from, and
/// that the whole page can be dragged back to the right to leave: the page
/// below is there on the left while it moves. The back button and the system
/// back run the same slide.
class SlideBackRoute<T> extends PageRouteBuilder<T> {
  SlideBackRoute({required WidgetBuilder builder})
      : super(
          pageBuilder: (context, _, __) => builder(context),
          transitionDuration: const Duration(milliseconds: 300),
          reverseTransitionDuration: const Duration(milliseconds: 260),
        );

  @override
  Widget buildTransitions(BuildContext context, Animation<double> animation,
      Animation<double> secondaryAnimation, Widget child) {
    return SlideTransition(
      position:
          Tween(begin: const Offset(1, 0), end: Offset.zero).animate(animation),
      child: DecoratedBox(
        decoration: BoxDecoration(
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.35),
              blurRadius: 16,
            ),
          ],
        ),
        child: _SwipeBack(route: this, child: child),
      ),
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
    final velocity = d.velocity.pixelsPerSecond.dx / width;
    final leave = velocity.abs() > 1 ? velocity > 0 : controller.value < 0.5;
    if (leave) {
      navigator.pop();
    } else {
      controller.animateTo(1,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOutCubic);
    }
    if (controller.isAnimating) {
      void done(AnimationStatus status) {
        if (!controller.isAnimating) {
          controller.removeStatusListener(done);
          navigator.didStopUserGesture();
        }
      }

      controller.addStatusListener(done);
    } else {
      navigator.didStopUserGesture();
    }
  }

  void _cancel() {
    if (!_dragging) return;
    _dragging = false;
    _controller?.animateTo(1, duration: const Duration(milliseconds: 200));
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
