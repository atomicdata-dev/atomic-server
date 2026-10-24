package place.atomic.app.kotlin

import android.util.Log

/**
 * Start-up and interaction timing marks, the Kotlin twin of Flutter's `Perf`
 * (`packages/atomic_flutter/lib/src/perf.dart`): `[perf] <name> <ms> ms` for a
 * mark, in milliseconds since [start] (the app's `onCreate`), and
 * `[perf] <name> <ms> ms (span)` for a span the caller timed. They go to logcat
 * with tag `flutter` and priority I, the Flutter app's own, so
 * `flutter/scripts/perf_android.sh`'s log reading (`logcat -s flutter:I`, then
 * `grep '\[perf\] home painted'` and so on) works on both apps unchanged.
 *
 * On in debug and benchmark builds (`BuildConfig.PERF_MARKS`), off in release,
 * as Flutter's are in a release build. Names and places are the same as in
 * Flutter, see the README's table.
 */
object Perf {
    const val TAG = "flutter"

    var enabled: Boolean = BuildConfig.PERF_MARKS

    /** Where lines go; tests collect them. */
    var sink: (String) -> Unit = { line ->
        // Plain JVM unit tests have no logcat.
        try { Log.i(TAG, line) } catch (_: RuntimeException) {}
    }

    /** Milliseconds, monotonic; tests drive it by hand. */
    var clock: () -> Long = { System.nanoTime() / 1_000_000 }

    private var startedAt: Long = -1
    private val seen = mutableSetOf<String>()
    private var tapAt: Long? = null
    private var typedAt: Long? = null

    /** Starts the clock; call first thing in `Application.onCreate`. */
    @Synchronized
    fun start() {
        if (!enabled || startedAt >= 0) return
        startedAt = clock()
        mark("main")
    }

    /** Milliseconds since [start]. */
    val now: Long get() = if (startedAt < 0) 0 else clock() - startedAt

    /** Logs [name] with the time since [start]. */
    fun mark(name: String) {
        if (!enabled) return
        if (startedAt < 0) start()
        sink("[perf] $name $now ms")
    }

    /** [mark], the first time only. */
    @Synchronized
    fun once(name: String) {
        if (!enabled || !seen.add(name)) return
        mark(name)
    }

    /** Logs `[perf] <name> <ms> ms (span)` for a span the caller timed. */
    fun span(name: String, ms: Long) {
        if (!enabled) return
        sink("[perf] $name $ms ms (span)")
    }

    /** The last finger lifted, anywhere: the start of [sinceTap]. Called for every touch-up, as Flutter's `watchTaps` does. */
    fun tapped() {
        if (!enabled) return
        tapAt = now
    }

    /** Logs `[perf] <name> since tap <ms> ms`: the time since the last finger lifted, for what a tap started. */
    fun sinceTap(name: String) {
        if (!enabled) return
        val at = tapAt ?: return
        span("$name since tap", now - at)
    }

    /** A key was typed in the search field: the start of [sinceTyped]. */
    fun typed() {
        if (!enabled) return
        typedAt = now
    }

    /** Logs `[perf] <name> <ms> ms (span)` for the time since the last [typed]. */
    fun sinceTyped(name: String) {
        if (!enabled) return
        val at = typedAt ?: return
        span(name, now - at)
    }

    /** A line of the chat's own log (`[chat] +12ms first event`), debug and benchmark only. */
    fun chat(line: String) {
        if (enabled) sink("[chat] $line")
    }

    /** Test hook: forget what [once] saw and the clock. */
    @Synchronized
    fun reset() {
        seen.clear()
        startedAt = -1
        tapAt = null
        typedAt = null
    }
}
