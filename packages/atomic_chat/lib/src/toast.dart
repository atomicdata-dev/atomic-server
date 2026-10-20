import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';

/// One notice on screen. Identified by [key]: a second notice with the same
/// key is the same notice.
class ToastEntry {
  ToastEntry({
    required this.key,
    required this.message,
    this.icon = Icons.info_outline,
    this.actionLabel,
    this.onAction,
    this.duration = const Duration(seconds: 6),
  });

  final String key;
  final String message;
  final IconData icon;
  final String? actionLabel;
  final VoidCallback? onAction;
  final Duration duration;

  /// Bumped when the same notice is raised again; restarts the dismiss timer.
  int revision = 0;
}

/// What is on screen and what may be raised: at most [maxVisible] toasts,
/// de-duplicated by key, and a key that was just dismissed stays quiet for
/// [cooldown] (until [clearCooldown], which a success calls).
class ToastController extends ChangeNotifier {
  ToastController({
    this.maxVisible = 3,
    this.cooldown = const Duration(seconds: 30),
    DateTime Function()? now,
  }) : _now = now ?? DateTime.now;

  final int maxVisible;
  final Duration cooldown;
  final DateTime Function() _now;

  final List<ToastEntry> _toasts = [];
  final Map<String, DateTime> _dismissedAt = {};

  List<ToastEntry> get toasts => List.unmodifiable(_toasts);

  /// Raises a toast. Returns false when it was swallowed by the cool-down.
  bool show(
    String key,
    String message, {
    IconData icon = Icons.info_outline,
    String? actionLabel,
    VoidCallback? onAction,
    Duration duration = const Duration(seconds: 6),
  }) {
    final existing = _toasts.where((t) => t.key == key).firstOrNull;
    if (existing != null) {
      // Same notice: no second toast, only a fresh timer.
      existing.revision++;
      notifyListeners();

      return true;
    }
    final at = _dismissedAt[key];
    if (at != null && _now().difference(at) < cooldown) return false;

    _toasts.add(ToastEntry(
      key: key,
      message: message,
      icon: icon,
      actionLabel: actionLabel,
      onAction: onAction,
      duration: duration,
    ));
    while (_toasts.length > maxVisible) {
      final old = _toasts.removeAt(0);
      _dismissedAt[old.key] = _now();
    }
    notifyListeners();

    return true;
  }

  void dismiss(String key) {
    if (_toasts.any((t) => t.key == key)) {
      _toasts.removeWhere((t) => t.key == key);
      _dismissedAt[key] = _now();
      notifyListeners();
    }
  }

  /// The cause went away (a sync worked): drop the toast and allow the next
  /// failure to speak at once.
  void resolve(String key) {
    _dismissedAt.remove(key);
    if (_toasts.any((t) => t.key == key)) {
      _toasts.removeWhere((t) => t.key == key);
      notifyListeners();
    }
  }

  void clearCooldown(String key) => _dismissedAt.remove(key);
}

/// Gives descendants the app's [ToastController].
class ToastScope extends InheritedNotifier<ToastController> {
  const ToastScope({
    super.key,
    required ToastController controller,
    required super.child,
  }) : super(notifier: controller);

  static ToastController? maybeOf(BuildContext context) => context
      .getInheritedWidgetOfExactType<ToastScope>()
      ?.notifier;

  static ToastController of(BuildContext context) =>
      maybeOf(context) ?? (throw StateError('No ToastHost above this context'));
}

/// Draws the controller's toasts over [child] without taking space or touches
/// from it: top-right on wide windows (max 360 dp), full width minus 16 dp
/// margins on phones. Put it in `MaterialApp.builder`.
class ToastHost extends StatelessWidget {
  const ToastHost({super.key, required this.controller, required this.child});

  final ToastController controller;
  final Widget child;

  static const double maxWidth = 360;
  static const double margin = 16;

  @override
  Widget build(BuildContext context) {
    return ToastScope(
      controller: controller,
      child: Stack(
        children: [
          child,
          ListenableBuilder(
            listenable: controller,
            builder: (context, _) {
              final toasts = controller.toasts;
              if (toasts.isEmpty) return const SizedBox.shrink();
              final mq = MediaQuery.of(context);
              final wide = mq.size.width >= 600;

              return Positioned(
                top: mq.padding.top + 8,
                right: margin,
                left: wide ? null : margin,
                width: wide ? maxWidth : null,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    for (final t in toasts)
                      Padding(
                        key: ValueKey('toast-pad-${t.key}'),
                        padding: const EdgeInsets.only(bottom: 8),
                        child: _ToastCard(
                          key: ValueKey('toast-${t.key}'),
                          entry: t,
                          onDismiss: () => controller.dismiss(t.key),
                        ),
                      ),
                  ],
                ),
              );
            },
          ),
        ],
      ),
    );
  }
}

class _ToastCard extends StatefulWidget {
  const _ToastCard({super.key, required this.entry, required this.onDismiss});

  final ToastEntry entry;
  final VoidCallback onDismiss;

  @override
  State<_ToastCard> createState() => _ToastCardState();
}

class _ToastCardState extends State<_ToastCard> {
  Timer? _timer;
  bool _held = false;
  int _revision = 0;
  double _dragUp = 0;

  @override
  void initState() {
    super.initState();
    _revision = widget.entry.revision;
    _arm();
  }

  @override
  void didUpdateWidget(_ToastCard old) {
    super.didUpdateWidget(old);
    if (widget.entry.revision != _revision) {
      _revision = widget.entry.revision;
      _arm();
    }
  }

  void _arm() {
    _timer?.cancel();
    if (_held) return;
    _timer = Timer(widget.entry.duration, widget.onDismiss);
  }

  void _hold(bool held) {
    _held = held;
    if (held) {
      _timer?.cancel();
    } else {
      _arm();
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colors = context.appColors;
    final e = widget.entry;
    final card = Material(
      color: colors.surface,
      elevation: 6,
      borderRadius: BorderRadius.circular(12),
      clipBehavior: Clip.antiAlias,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        child: Row(
          children: [
            Icon(e.icon, size: 20, color: colors.textSecondary),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                e.message,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: colors.textPrimary, fontSize: 14),
              ),
            ),
            if (e.actionLabel != null)
              TextButton(
                onPressed: () {
                  widget.onDismiss();
                  e.onAction?.call();
                },
                child: Text(e.actionLabel!),
              ),
          ],
        ),
      ),
    );

    return MouseRegion(
      onEnter: (_) => _hold(true),
      onExit: (_) => _hold(false),
      child: Listener(
        onPointerDown: (_) => _hold(true),
        onPointerUp: (_) => _hold(false),
        onPointerCancel: (_) => _hold(false),
        child: GestureDetector(
          onVerticalDragUpdate: (d) => _dragUp -= d.delta.dy,
          onVerticalDragEnd: (d) {
            if (_dragUp > 24 || (d.primaryVelocity ?? 0) < -300) {
              widget.onDismiss();
            }
            _dragUp = 0;
          },
          child: Dismissible(
            key: ValueKey('dismiss-${e.key}-${e.hashCode}'),
            direction: DismissDirection.horizontal,
            onDismissed: (_) => widget.onDismiss(),
            child: TweenAnimationBuilder<double>(
              tween: Tween(begin: 0, end: 1),
              duration: const Duration(milliseconds: 220),
              curve: Curves.easeOutCubic,
              builder: (context, v, child) => Opacity(
                opacity: v,
                child: Transform.translate(
                  offset: Offset(0, -12 * (1 - v)),
                  child: child,
                ),
              ),
              child: card,
            ),
          ),
        ),
      ),
    );
  }
}
