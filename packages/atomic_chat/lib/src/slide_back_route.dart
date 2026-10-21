import 'package:atomic_flutter/atomic_flutter.dart' show AppColors;
import 'package:flutter/material.dart';
import 'package:flutter/physics.dart';

import 'app_shell.dart' show ShellLayout, ShellScope;
import 'covered_insets_freeze.dart';

/// A page that slides in from the right over the page it was opened from, and
/// that the whole page can be dragged back to the right to leave: the page
/// below is there on the left while it moves. The back button and the system
/// back run the same slide.
///
/// The slide is short ([duration]): a tap should show the page about at once,
/// and a long slide is time the page waits to be seen. With [instant] there is
/// none (the detail pane next to a list just shows the next page).
class SlideBackRoute<T> extends PageRouteBuilder<T> {
  SlideBackRoute(
      {required WidgetBuilder builder, super.settings, bool instant = false})
      : _instant = instant,
        super(
          pageBuilder: (context, _, __) => ColoredBox(
              color: surfaceOf(context),
              child: CoveredInsetsFreeze(child: builder(context))),
          transitionDuration: instant ? Duration.zero : duration,
          reverseTransitionDuration: instant ? Duration.zero : duration,
        );

  final bool _instant;

  /// What lies under every page: the app's surface colour. A page that is
  /// sliding or loading (a web view not yet painted, a placeholder without a
  /// colour) shows this, never the window's black.
  static Color surfaceOf(BuildContext context) {
    final theme = Theme.of(context);
    return theme.extension<AppColors>()?.bgBody ??
        theme.scaffoldBackgroundColor;
  }

  /// How long the slide in and out takes.
  static const duration = Duration(milliseconds: 150);

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

  /// The page-wide swipe, when this route has one (not in the split layout).
  _SwipeBackState? _swipe;

  /// Drives the same slide from outside the page's own gesture detector:
  /// a web view eats the touches, so its owner reads them itself and passes
  /// the drag on. False when the route does not take a swipe now.
  bool beginHandDrag() {
    final swipe = _swipe;
    // Already moved by the page's own drag (over a Flutter widget): that one
    // keeps it.
    if (swipe == null || swipe._dragging) return false;
    swipe._start(DragStartDetails());
    swipe._hand = swipe._dragging;
    return swipe._hand;
  }

  void updateHandDrag(double dx) {
    if (_swipe?._hand != true) return;
    _swipe!._update(DragUpdateDetails(
        globalPosition: Offset.zero, delta: Offset(dx, 0), primaryDelta: dx));
  }

  void endHandDrag(double velocityX) {
    final swipe = _swipe;
    if (swipe == null || !swipe._hand) return;
    swipe._hand = false;
    swipe._end(DragEndDetails(
        velocity: Velocity(pixelsPerSecond: Offset(velocityX, 0)),
        primaryVelocity: velocityX));
  }

  void cancelHandDrag() {
    final swipe = _swipe;
    if (swipe == null || !swipe._hand) return;
    swipe._hand = false;
    swipe._cancel();
  }

  @override
  Widget buildTransitions(BuildContext context, Animation<double> animation,
      Animation<double> secondaryAnimation, Widget child) {
    return AnimatedBuilder(
      animation: animation,
      // Next to a list there is nothing to swipe back to: a horizontal
      // drag claiming the page would fight its vertical scrolling.
      child: _instant ? child : _SwipeBack(route: this, child: child),
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

  /// The drag is passed in by [SlideBackRoute.beginHandDrag], not by the
  /// detector below.
  bool _hand = false;

  @override
  void initState() {
    super.initState();
    widget.route._swipe = this;
  }

  @override
  void dispose() {
    if (widget.route._swipe == this) widget.route._swipe = null;
    super.dispose();
  }

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
  Widget build(BuildContext context) =>
      // Next to a list (the detail pane) there is no page below to swipe
      // back to, and a horizontal drag claiming the whole page fights the
      // vertical scrolling of everything in it.
      ShellScope.layoutOf(context) == ShellLayout.split
          ? widget.child
          : _swipe();

  Widget _swipe() => GestureDetector(
        behavior: HitTestBehavior.translucent,
        onHorizontalDragStart: (d) => _hand ? null : _start(d),
        onHorizontalDragUpdate: (d) => _hand ? null : _update(d),
        onHorizontalDragEnd: (d) => _hand ? null : _end(d),
        onHorizontalDragCancel: () => _hand ? null : _cancel(),
        child: widget.child,
      );
}
