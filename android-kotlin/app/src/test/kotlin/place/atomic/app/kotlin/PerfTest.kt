package place.atomic.app.kotlin

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/** The marks are the Flutter app's: same words, so perf_android.sh's greps work on both. */
class PerfTest {
    private val lines = mutableListOf<String>()
    private var now = 1_000L
    private var wasEnabled = true

    @Before
    fun setUp() {
        wasEnabled = Perf.enabled
        Perf.enabled = true
        Perf.sink = { lines += it }
        Perf.clock = { now }
        Perf.reset()
    }

    @After
    fun tearDown() {
        Perf.enabled = wasEnabled
        Perf.reset()
    }

    @Test
    fun marksAreMillisecondsSinceTheStart() {
        Perf.start()
        now += 250
        Perf.mark("first frame")
        assertEquals(listOf("[perf] main 0 ms", "[perf] first frame 250 ms"), lines)
    }

    @Test
    fun onceMarksOnlyTheFirstTime() {
        Perf.start()
        now += 10
        Perf.once("home data")
        now += 10
        Perf.once("home data")
        assertEquals(listOf("[perf] main 0 ms", "[perf] home data 10 ms"), lines)
    }

    @Test
    fun spansAreMarkedAsSpans() {
        Perf.span("search query", 12)
        assertEquals(listOf("[perf] search query 12 ms (span)"), lines)
    }

    @Test
    fun sinceTapIsTheTimeSinceTheLastFingerLifted() {
        Perf.start()
        Perf.sinceTap("resource painted warm")
        now += 100
        Perf.tapped()
        now += 340
        Perf.sinceTap("resource painted warm")
        Perf.sinceTap("resource revealed warm")
        assertEquals(
            listOf("[perf] main 0 ms", "[perf] resource painted warm since tap 340 ms (span)", "[perf] resource revealed warm since tap 340 ms (span)"),
            lines,
        )
    }

    @Test
    fun keystrokeToResultsIsTimedFromTheLastKey() {
        Perf.start()
        Perf.sinceTyped("search keystroke to results")
        Perf.typed()
        now += 7
        Perf.typed()
        now += 24
        Perf.sinceTyped("search keystroke to results")
        assertEquals(listOf("[perf] main 0 ms", "[perf] search keystroke to results 24 ms (span)"), lines)
    }

    @Test
    fun nothingIsWrittenWhenOff() {
        Perf.enabled = false
        Perf.start()
        Perf.mark("x")
        Perf.span("y", 1)
        Perf.tapped()
        Perf.sinceTap("z")
        Perf.chat("q")
        assertEquals(emptyList<String>(), lines)
    }
}
