/// When a failed background sync deserves a notice. Rarely: a hiccup is
/// normal and the app retries on its own, so the notice shows only after
/// several failures in a row, a long time without any success, at most once
/// per session and per [cooldown] (persisted), and never in the background.
class SyncNoticePolicy {
  SyncNoticePolicy({
    DateTime Function()? now,
    this.lastShown,
    this.onShown,
  })  : _now = now ?? DateTime.now,
        _lastSuccess = (now ?? DateTime.now)();

  static const prefsKey = 'sync_notice_last_shown_ms';
  static const minFailures = 3;
  static const minQuietTime = Duration(minutes: 10);
  static const cooldown = Duration(hours: 6);

  final DateTime Function() _now;

  /// When the notice was last shown on this device (persisted).
  DateTime? lastShown;

  /// Called when the notice is raised, to persist [lastShown].
  final void Function(DateTime at)? onShown;

  int _failures = 0;
  DateTime _lastSuccess;
  bool _shownThisSession = false;

  int get failures => _failures;

  /// A sync worked: the streak and the clock start over.
  void succeeded() {
    _failures = 0;
    _lastSuccess = _now();
  }

  /// Signed out or restarted from scratch.
  void reset() {
    _failures = 0;
    _lastSuccess = _now();
  }

  /// A sync failed. True when the notice should be raised now.
  bool failed({required bool inForeground}) {
    _failures++;
    if (!inForeground || _shownThisSession) return false;
    if (_failures < minFailures) return false;
    final now = _now();
    if (now.difference(_lastSuccess) < minQuietTime) return false;
    final shown = lastShown;
    if (shown != null && now.difference(shown) < cooldown) return false;
    _shownThisSession = true;
    lastShown = now;
    onShown?.call(now);
    return true;
  }
}
