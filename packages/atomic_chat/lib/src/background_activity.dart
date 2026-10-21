import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

/// What runs in the background right now: the host's own count (sync runs,
/// following and catching up on drives, picture downloads, activity lookups
/// and scans, uploads) plus the Dart-side tasks (a picture a row waits for).
@immutable
class BackgroundState {
  /// Running tasks.
  final int total;

  /// Running tasks by kind: `sync`, `drives`, `pictures`, `history`, `scan`,
  /// `upload`.
  final Map<String, int> byKind;

  /// The last background failure, cleared by the next success.
  final String? lastError;

  /// When a task last succeeded (ms since the epoch).
  final int? lastOkMs;

  /// Requests this device made to the public device directory in the last
  /// hour; null when the host does not count them.
  final int? directoryLookups;

  const BackgroundState({
    this.total = 0,
    this.byKind = const {},
    this.lastError,
    this.lastOkMs,
    this.directoryLookups,
  });

  static const idle = BackgroundState();

  bool get busy => total > 0;

  /// A failure to show: only while nothing runs.
  bool get problem => !busy && lastError != null && lastError!.isNotEmpty;

  static const _captions = {
    'sync': 'Syncing with your devices',
    'drives': 'Syncing drives',
    'pictures': 'Loading pictures',
    'history': 'Catching up on activity',
    'scan': 'Catching up on activity',
    'upload': 'Uploading',
  };

  /// One line for what runs, e.g. `Syncing drives · Loading pictures`.
  String get caption {
    final lines = <String>[];
    for (final kind in _captions.keys) {
      if ((byKind[kind] ?? 0) > 0 && !lines.contains(_captions[kind])) {
        lines.add(_captions[kind]!);
      }
    }
    return lines.isEmpty ? 'Syncing…' : lines.join(' · ');
  }

  /// The line of the Sync page's "Background activity" row.
  String get summary {
    final lookups = directoryLookups;
    final suffix = lookups == null
        ? ''
        : ' · $lookups directory ${lookups == 1 ? 'lookup' : 'lookups'} '
            'in the last hour';
    if (busy) {
      return '$caption · $total ${total == 1 ? 'task' : 'tasks'}$suffix';
    }
    if (problem) return lastError!;
    return 'Idle$suffix';
  }

  BackgroundState plus(Map<String, int> dart) {
    if (dart.isEmpty) return this;
    final merged = Map<String, int>.of(byKind);
    var extra = 0;
    dart.forEach((kind, n) {
      merged[kind] = (merged[kind] ?? 0) + n;
      extra += n;
    });
    return BackgroundState(
      total: total + extra,
      byKind: merged,
      lastError: lastError,
      lastOkMs: lastOkMs,
      directoryLookups: directoryLookups,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is BackgroundState &&
      other.total == total &&
      other.lastError == lastError &&
      other.lastOkMs == lastOkMs &&
      other.directoryLookups == directoryLookups &&
      mapEquals(other.byKind, byKind);

  @override
  int get hashCode => Object.hash(total, lastError, lastOkMs, byKind.length, directoryLookups);
}

/// Holds one Dart-side task in the count until [end] (safe to call twice).
class BackgroundToken {
  final BackgroundActivity _owner;
  final String _kind;
  bool _ended = false;

  BackgroundToken._(this._owner, this._kind);

  void end() {
    if (_ended) return;
    _ended = true;
    _owner._end(_kind);
  }
}

/// The app-wide background activity: a notifier of [BackgroundState]
/// combining Dart tokens ([begin]) with the host's counter ([hostPoller],
/// polled only while [start]ed: the app is in the foreground and the shell is
/// mounted).
class BackgroundActivity extends ValueNotifier<BackgroundState> {
  static final BackgroundActivity instance = BackgroundActivity();

  /// Reads the host's counter (synchronously; the Rust bridge's is). Null: no
  /// host counter, only Dart tokens count.
  BackgroundState Function()? hostPoller;

  /// The poll interval while something ran lately, and after [idleLimit]
  /// polls with nothing running.
  final Duration fast;
  final Duration slow;
  final int idleLimit;

  BackgroundActivity({
    this.fast = const Duration(seconds: 1),
    this.slow = const Duration(seconds: 3),
    this.idleLimit = 10,
  }) : super(BackgroundState.idle);

  final Map<String, int> _dart = {};
  BackgroundState _host = BackgroundState.idle;
  Timer? _timer;
  int _idlePolls = 0;
  int _starts = 0;

  /// Count a Dart-side task of [kind] until the token ends.
  BackgroundToken begin(String kind) {
    _dart[kind] = (_dart[kind] ?? 0) + 1;
    _combine();
    return BackgroundToken._(this, kind);
  }

  void _end(String kind) {
    final n = (_dart[kind] ?? 0) - 1;
    if (n <= 0) {
      _dart.remove(kind);
    } else {
      _dart[kind] = n;
    }
    _combine();
  }

  void _combine() {
    final next = _host.plus(_dart);
    if (next != value) value = next;
  }

  /// Read the host's counter now.
  void poll() {
    final read = hostPoller;
    if (read != null) {
      try {
        _host = read();
      } catch (e) {
        debugPrint('Background activity not read: $e');
      }
    }
    _combine();
  }

  /// Poll every [fast] (every [slow] after [idleLimit] idle polls) until
  /// [stop]. Calls nest: it stops when every start was stopped.
  void start() {
    _starts++;
    if (_timer != null) return;
    _idlePolls = 0;
    _schedule();
    poll();
  }

  void stop() {
    if (_starts > 0) _starts--;
    if (_starts > 0) return;
    _timer?.cancel();
    _timer = null;
  }

  bool get polling => _timer != null;

  void _schedule() {
    _timer?.cancel();
    final interval = _idlePolls >= idleLimit ? slow : fast;
    _timer = Timer(interval, () {
      _timer = null;
      if (_starts == 0) return;
      poll();
      _idlePolls = value.busy ? 0 : _idlePolls + 1;
      _schedule();
    });
  }
}

/// The sync mark on the corner of the avatar: a small ringed circle with a
/// rotating sync icon while something runs in the background (shown after
/// 400 ms, so a quick fetch does not flicker, and for at least 800 ms once
/// shown), a static amber icon when the last background run failed and nothing
/// runs, nothing otherwise. It is not a button: it ignores touches, so the
/// avatar button under it takes them. Mounting it starts the host polling
/// (while the app is in the foreground).
///
/// Put it in a [Stack] over the avatar, e.g. in a `Positioned(right: -4,
/// bottom: -4)`.
class BackgroundActivityBadge extends StatefulWidget {
  final BackgroundActivity? activity;

  /// How long activity must last before the mark shows, and how long it stays
  /// once shown.
  final Duration showAfter;
  final Duration minShown;

  /// The ring's colour (the surface the avatar sits on).
  final Color? ring;

  /// The size of the circle, ring included.
  static const size = 16.0;

  const BackgroundActivityBadge({
    super.key,
    this.activity,
    this.ring,
    this.showAfter = const Duration(milliseconds: 400),
    this.minShown = const Duration(milliseconds: 800),
  });

  /// What to append to the avatar button's label: `, syncing`,
  /// `, sync problem` or nothing.
  static String labelSuffix(BackgroundState s) =>
      s.busy ? ', syncing' : (s.problem ? ', sync problem' : '');

  @override
  State<BackgroundActivityBadge> createState() =>
      _BackgroundActivityBadgeState();
}

class _BackgroundActivityBadgeState
    extends State<BackgroundActivityBadge>
    with SingleTickerProviderStateMixin, WidgetsBindingObserver {
  late final AnimationController _turn = AnimationController(
      vsync: this, duration: const Duration(milliseconds: 1200));
  late BackgroundActivity _activity;
  Timer? _showTimer;
  Timer? _hideTimer;
  bool _spinning = false;
  DateTime? _shownAt;
  bool _polling = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _attach();
  }

  void _attach() {
    _activity = widget.activity ?? BackgroundActivity.instance;
    _activity.addListener(_changed);
    final lifecycle = WidgetsBinding.instance.lifecycleState;
    if (lifecycle == null || lifecycle == AppLifecycleState.resumed) {
      _startPolling();
    }
    _changed();
  }

  void _detach() {
    _activity.removeListener(_changed);
    _stopPolling();
  }

  void _startPolling() {
    if (_polling) return;
    _polling = true;
    _activity.start();
  }

  void _stopPolling() {
    if (!_polling) return;
    _polling = false;
    _activity.stop();
  }

  @override
  void didUpdateWidget(BackgroundActivityBadge old) {
    super.didUpdateWidget(old);
    if (old.activity != widget.activity) {
      _detach();
      _attach();
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _startPolling();
    } else {
      _stopPolling();
    }
  }

  void _changed() {
    final busy = _activity.value.busy;
    if (busy) {
      _hideTimer?.cancel();
      _hideTimer = null;
      if (!_spinning && _showTimer == null) {
        _showTimer = Timer(widget.showAfter, () {
          _showTimer = null;
          if (!mounted || !_activity.value.busy) return;
          _shownAt = DateTime.now();
          _setSpinning(true);
        });
      }
    } else {
      _showTimer?.cancel();
      _showTimer = null;
      if (_spinning && _hideTimer == null) {
        final shown = DateTime.now().difference(_shownAt ?? DateTime.now());
        final left = widget.minShown - shown;
        if (left <= Duration.zero) {
          _setSpinning(false);
        } else {
          _hideTimer = Timer(left, () {
            _hideTimer = null;
            if (!mounted) return;
            if (_activity.value.busy) return;
            _setSpinning(false);
          });
        }
      }
    }
    if (mounted) setState(() {});
  }

  void _setSpinning(bool on) {
    if (!mounted) return;
    setState(() => _spinning = on);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _showTimer?.cancel();
    _hideTimer?.cancel();
    _detach();
    _turn.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final state = _activity.value;
    final problem = !_spinning && state.problem;
    final visible = _spinning || problem;
    final reduced = MediaQuery.disableAnimationsOf(context);

    final animate = _spinning && !reduced;
    if (animate && !_turn.isAnimating) {
      _turn.repeat();
    } else if (!animate && _turn.isAnimating) {
      _turn.stop();
    }

    final Widget icon;
    if (problem) {
      icon = Icon(Icons.sync_problem,
          key: const Key('background-activity-problem'),
          size: 11,
          color: SyncTone.warning.color(c));
    } else if (reduced) {
      icon = Container(
          key: const Key('background-activity-dot'),
          width: 6,
          height: 6,
          decoration:
              BoxDecoration(color: c.textSecondary, shape: BoxShape.circle));
    } else {
      icon = RotationTransition(
        turns: _turn,
        child: Icon(Icons.sync,
            key: const Key('background-activity-spinner'),
            size: 11,
            color: c.textSecondary),
      );
    }

    return AnimatedOpacity(
      key: const Key('background-activity'),
      opacity: visible ? 1 : 0,
      duration: const Duration(milliseconds: 150),
      child: IgnorePointer(
        child: ExcludeSemantics(
          child: Container(
            width: BackgroundActivityBadge.size,
            height: BackgroundActivityBadge.size,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: c.barSurface,
              border: Border.all(
                  color: widget.ring ?? c.barSurface, width: 2),
            ),
            child: visible ? icon : null,
          ),
        ),
      ),
    );
  }
}
