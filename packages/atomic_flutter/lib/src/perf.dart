import 'dart:async' show Timer;
import 'dart:developer' show Timeline;

import 'package:flutter/foundation.dart';
import 'package:flutter/scheduler.dart';

/// Start-up and interaction timing marks, `[perf] <name> <ms> ms` in the log
/// (logcat tag `flutter`), in milliseconds since [Perf.start] (the start of
/// `main`). Each mark is also a timeline event (`perf:<name>`) for DevTools.
/// The time before `main` (process start, engine) is not visible from Dart
/// (Android's SELinux denies an app `/proc/uptime`): the perf script takes it
/// from the log's own timestamps.
///
/// Debug and profile builds only: in a release build [mark] does nothing.
/// `flutter/scripts/perf_android.sh` reads these lines.
class Perf {
  Perf._();

  static final Stopwatch _clock = Stopwatch();

  static final Set<String> _seen = {};

  /// Starts the clock; call first thing in `main`.
  static void start() {
    if (kReleaseMode || _clock.isRunning) return;
    _clock.start();
    mark('main');
  }

  /// Milliseconds since [start].
  static int get now => _clock.elapsedMilliseconds;

  /// Logs [name] with the time since [start].
  static void mark(String name) {
    if (kReleaseMode) return;
    if (!_clock.isRunning) start();
    Timeline.instantSync('perf:$name');
    debugPrint('[perf] $name $now ms');
  }

  /// [mark], the first time only.
  static void once(String name) {
    if (kReleaseMode || !_seen.add(name)) return;
    mark(name);
  }

  /// Logs `[perf] <name> <ms> ms` for a span the caller timed.
  static void span(String name, int ms) {
    if (kReleaseMode) return;
    Timeline.instantSync('perf:$name', arguments: {'ms': '$ms'});
    debugPrint('[perf] $name $ms ms (span)');
  }

  static bool _watching = false;
  static final List<FrameTiming> _burst = [];
  static Timer? _quiet;

  /// Logs a summary of each burst of frames (a scroll, an animation, a
  /// streaming reply) once the app has drawn nothing for a while:
  /// `[perf] frames n=.. janky=..% build p50/90/95/99 .. raster ..` (ms). A
  /// frame is janky when its build or its raster took longer than the
  /// display's frame budget, as DevTools counts them. Android's `dumpsys
  /// gfxinfo` does not see Flutter's own surface, hence these.
  static void watchFrames() {
    if (kReleaseMode || _watching) return;
    _watching = true;
    SchedulerBinding.instance.addTimingsCallback((timings) {
      _burst.addAll(timings);
      _quiet?.cancel();
      _quiet = Timer(const Duration(milliseconds: 1500), _reportFrames);
    });
  }

  static void _reportFrames() {
    final frames = List.of(_burst);
    _burst.clear();
    if (frames.length < 10) return;
    final views = SchedulerBinding.instance.platformDispatcher.views;
    final hz = views.isEmpty ? 60.0 : views.first.display.refreshRate;
    final budgetUs = 1e6 / (hz > 0 ? hz : 60.0);
    final build = [for (final f in frames) f.buildDuration.inMicroseconds]
      ..sort();
    final raster = [for (final f in frames) f.rasterDuration.inMicroseconds]
      ..sort();
    final janky = frames
        .where((f) =>
            f.buildDuration.inMicroseconds > budgetUs ||
            f.rasterDuration.inMicroseconds > budgetUs)
        .length;
    String pct(List<int> sorted) => [50, 90, 95, 99].map((p) {
          final i = ((sorted.length - 1) * p / 100).round();
          return (sorted[i] / 1000).toStringAsFixed(1);
        }).join('/');
    debugPrint('[perf] frames n=${frames.length} '
        'janky=${(100 * janky / frames.length).toStringAsFixed(1)}% '
        'budget=${(budgetUs / 1000).toStringAsFixed(1)} '
        'build=${pct(build)} raster=${pct(raster)}');
  }
}
