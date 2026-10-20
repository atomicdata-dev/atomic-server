import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'chat_window.dart';

/// The one "back to the newest message" button of every chat list. A small
/// round floating button, bottom right over the list (so above the composer
/// and the keyboard, which the list's own height already follows). Shown
/// only while the list is not at the bottom: scrolled up by more than
/// [ChatScrollKeeper.showButtonDistance], or the newest messages are not in
/// the window. It scales and fades in with a little overshoot, bounces its
/// arrows once, and shrinks to nothing when the list reaches the bottom.
/// [unseen] new messages are counted on a badge. Tapping scrolls to the
/// newest message ([ChatScrollKeeper.scrollToBottom]).
///
/// Place it directly in the [Stack] over the list.
class ScrollToBottomButton extends StatefulWidget {
  final ChatScrollKeeper keeper;

  /// New messages waiting while scrolled up.
  final int unseen;

  /// Called after the tap's scroll finished (the screen may reset state).
  final VoidCallback? onScrolled;

  const ScrollToBottomButton({
    super.key,
    required this.keeper,
    this.unseen = 0,
    this.onScrolled,
  });

  @override
  State<ScrollToBottomButton> createState() => _ScrollToBottomButtonState();
}

class _ScrollToBottomButtonState extends State<ScrollToBottomButton>
    with TickerProviderStateMixin {
  late final AnimationController _show = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 180),
    reverseDuration: const Duration(milliseconds: 140),
  );
  late final AnimationController _bounce = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 520),
  );
  late final Animation<double> _scale = CurvedAnimation(
    parent: _show,
    curve: Curves.easeOutBack,
    reverseCurve: Curves.easeIn,
  );
  bool _wanted = false;

  ChatScrollKeeper get _keeper => widget.keeper;

  @override
  void initState() {
    super.initState();
    _keeper.controller.addListener(_update);
    _keeper.window.addListener(_update);
    _show.addStatusListener((_) {
      if (mounted) setState(() {});
    });
    _wanted = _shouldShow();
    if (_wanted) _show.value = 1;
  }

  @override
  void didUpdateWidget(ScrollToBottomButton old) {
    super.didUpdateWidget(old);
    if (widget.unseen > old.unseen && _wanted) _bounce.forward(from: 0);
    _update();
  }

  @override
  void dispose() {
    _keeper.controller.removeListener(_update);
    _keeper.window.removeListener(_update);
    _show.dispose();
    _bounce.dispose();
    super.dispose();
  }

  bool _shouldShow() =>
      widget.unseen > 0 || _keeper.window.detached || _keeper.farFromBottom;

  void _update() {
    final want = _shouldShow();
    if (want == _wanted) return;
    _wanted = want;
    if (want) {
      _show.forward();
      _bounce.forward(from: 0);
    } else {
      _show.reverse();
    }
    // A scroll notification may arrive during layout.
    if (mounted) setState(() {});
  }

  Future<void> _tap() async {
    HapticFeedback.lightImpact();
    await _keeper.scrollToBottom();
    if (mounted) widget.onScrolled?.call();
  }

  @override
  Widget build(BuildContext context) {
    if (_show.isDismissed && !_wanted) return const SizedBox.shrink();
    final scheme = Theme.of(context).colorScheme;
    final far = _keeper.window.detached ||
        (_keeper.controller.hasClients &&
            _keeper.controller.position.pixels >
                _keeper.controller.position.viewportDimension);
    final unseen = widget.unseen;
    final icon = AnimatedBuilder(
      animation: _bounce,
      builder: (context, child) => Transform.translate(
        // A short hop down and back.
        offset: Offset(0, 3 * _hop(_bounce.value)),
        child: child,
      ),
      child: Icon(
        far ? Icons.keyboard_double_arrow_down : Icons.keyboard_arrow_down,
        size: 22,
        color: scheme.onPrimaryContainer,
      ),
    );
    return Positioned(
      right: 16 - 4,
      bottom: 16 - 4,
      child: FadeTransition(
        opacity: _show,
        child: ScaleTransition(
          key: const Key('scroll-to-bottom-scale'),
          scale: _scale,
          child: Semantics(
            button: true,
            label: unseen > 0 ? '$unseen new messages' : 'Scroll to newest',
            child: Tooltip(
              message: unseen > 0 ? '$unseen new' : 'Scroll to newest',
              child: InkResponse(
                key: const Key('scroll-to-bottom'),
                onTap: _show.isAnimating && !_wanted ? null : _tap,
                radius: 24,
                // 48 dp to hit, 40 dp to see.
                child: SizedBox(
                  width: 48,
                  height: 48,
                  child: Center(
                    child: Badge(
                      isLabelVisible: unseen > 0,
                      label: Text(unseen > 99 ? '99+' : '$unseen'),
                      child: Material(
                        elevation: 2,
                        shape: const CircleBorder(),
                        color: scheme.primaryContainer,
                        child: SizedBox(width: 40, height: 40, child: icon),
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  /// 0 -> 1 -> 0 over the bounce.
  static double _hop(double t) => t <= 0 || t >= 1
      ? 0
      : Curves.easeOut.transform(t < 0.4 ? t / 0.4 : (1 - t) / 0.6);
}
