package place.atomic.app.kotlin

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import place.atomic.app.kotlin.embed.EmbedBridge
import place.atomic.app.kotlin.embed.EmbedCore
import place.atomic.app.kotlin.embed.EmbedPage

private class FakePage : EmbedPage {
    val scripts = mutableListOf<String>()
    var evaluated: String? = "true"
    override fun run(script: String) {
        scripts += script
    }

    override suspend fun evaluate(script: String): String? = evaluated
}

private class FakeCore(val answer: (String, String) -> String = { _, _ -> "null" }) : EmbedCore {
    val calls = mutableListOf<Pair<String, String>>()
    override suspend fun dispatch(method: String, argsJson: String): String {
        calls += method to argsJson
        return answer(method, argsJson)
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class EmbedBridgeTest {
    private var marks = false

    // The page-watching scripts of the perf marks are tested on their own.
    @org.junit.Before fun marksOff() { marks = Perf.enabled; Perf.enabled = false }
    @org.junit.After fun marksBack() { Perf.enabled = marks }

    private fun TestScope.bridge(core: EmbedCore = FakeCore(), page: FakePage = FakePage(), flushMs: Long = 50) =
        EmbedBridge(this, core, page, flushTimeoutMs = flushMs)

    @Test
    fun aCallGoesToRustAndTheAnswerComesBackUnderItsId() = runTest(StandardTestDispatcher()) {
        val core = FakeCore { m, _ -> if (m == "agent") "\"did:ad:agent:me\"" else "null" }
        val page = FakePage()
        val b = bridge(core, page)
        b.onMessage("""{"id":3,"method":"agent","args":[]}""")
        b.onMessage("""{"id":4,"method":"getResourcesWithSnapshots","args":[["did:ad:x"]]}""")
        advanceUntilIdle()
        assertEquals(listOf("agent" to "[]", "getResourcesWithSnapshots" to """[["did:ad:x"]]"""), core.calls)
        assertTrue(page.scripts.contains("""window.__atomicReply(3,true,"\"did:ad:agent:me\"")"""))
        assertTrue(page.scripts.contains("""window.__atomicReply(4,true,"null")"""))
    }

    @Test
    fun aFailedCallRejectsInThePage() = runTest(StandardTestDispatcher()) {
        val page = FakePage()
        val b = bridge(FakeCore { _, _ -> error("only a commit by this device's agent is signed") }, page)
        b.onMessage("""{"id":9,"method":"sign","args":["x"]}""")
        advanceUntilIdle()
        assertEquals(
            """window.__atomicReply(9,false,"only a commit by this device's agent is signed")""",
            page.scripts.single(),
        )
    }

    @Test
    fun theAppAnswersItsOwnCallsAndFillsInTheDriveForOpened() = runTest(StandardTestDispatcher()) {
        val core = FakeCore { _, _ -> "true" }
        val page = FakePage()
        val themes = mutableListOf<String>()
        val b = EmbedBridge(this, core, page, onTheme = { themes += it })
        b.open("did:ad:doc", "did:ad:drive")
        b.onMessage("""{"id":1,"method":"openNative","args":["chatroom","did:ad:c","Chat"]}""")
        b.onMessage("""{"id":2,"method":"theme","args":["dark"]}""")
        b.onMessage("""{"id":3,"method":"opened","args":["did:ad:doc"]}""")
        advanceUntilIdle()
        assertEquals(listOf("opened" to """["did:ad:doc","did:ad:drive"]"""), core.calls)
        assertEquals(listOf("dark"), themes)
        assertTrue(page.scripts.contains("""window.__atomicReply(1,true,"false")"""))
    }

    @Test
    fun aResourceOpenedBeforeThePageIsUpIsShownWhenItSaysReady() = runTest(StandardTestDispatcher()) {
        val page = FakePage()
        val b = bridge(page = page)
        b.setColorScheme(true)
        b.open("did:ad:doc", "d")
        b.changed(listOf("did:ad:doc"))
        assertTrue(page.scripts.isEmpty())
        b.onMessage("""{"method":"ready"}""")
        assertTrue(b.isReady)
        assertEquals(
            listOf(
                place.atomic.app.kotlin.embed.EmbedProtocol.setColorSchemeScript(true),
                place.atomic.app.kotlin.embed.EmbedProtocol.openScript("did:ad:doc"),
            ),
            page.scripts,
        )
        // From now on a route change is one script, not a page load.
        b.open("did:ad:other", "d")
        assertEquals(place.atomic.app.kotlin.embed.EmbedProtocol.openScript("did:ad:other"), page.scripts.last())
    }

    @Test
    fun aReloadingPageIsNotReadyAgainUntilItSaysSo() = runTest(StandardTestDispatcher()) {
        val page = FakePage()
        val b = bridge(page = page)
        b.onMessage("""{"method":"ready"}""")
        b.pageStarted()
        assertFalse(b.isReady)
        b.open("did:ad:doc", "d")
        assertTrue(page.scripts.isEmpty())
        b.onMessage("""{"method":"ready"}""")
        assertEquals(1, page.scripts.size)
    }

    @Test
    fun backStepsInsideThePageFirst() = runTest(StandardTestDispatcher()) {
        val page = FakePage()
        val b = bridge(page = page)
        assertFalse("not ready: leave", b.back())
        b.onMessage("""{"method":"ready"}""")
        page.evaluated = "true"
        assertTrue(b.back())
        page.evaluated = "false"
        assertFalse(b.back())
    }

    @Test
    fun leavingFlushesPendingEditsBeforeTheRouteIsBlanked() = runTest(StandardTestDispatcher()) {
        val page = FakePage()
        val b = bridge(page = page)
        b.onMessage("""{"method":"ready"}""")
        val leaving = launchLeave(b)
        runCurrent()
        // The flush script went out; the route is not blanked until the page confirms.
        assertEquals(1, page.scripts.size)
        assertTrue(page.scripts[0].contains("flush(true)"))
        b.onMessage("""{"method":"flushed","flush":1}""")
        runCurrent()
        leaving.join()
        assertEquals(place.atomic.app.kotlin.embed.EmbedProtocol.openScript(""), page.scripts.last())
    }

    @Test
    fun aPageThatNeverConfirmsTheFlushDoesNotKeepThePersonWaiting() = runTest(StandardTestDispatcher()) {
        val page = FakePage()
        val b = bridge(page = page, flushMs = 2_000)
        b.onMessage("""{"method":"ready"}""")
        val leaving = launchLeave(b)
        advanceUntilIdle()
        leaving.join()
        assertEquals(place.atomic.app.kotlin.embed.EmbedProtocol.openScript(""), page.scripts.last())
    }

    private fun TestScope.launchLeave(b: EmbedBridge) = this.launch { b.leave() }

    @Test
    fun openNativeOpensTheScreenForAKindTheAppHasAndSaysNoOtherwise() = runTest(StandardTestDispatcher()) {
        val page = FakePage()
        val opened = mutableListOf<Triple<String, String, String>>()
        val b = EmbedBridge(this, FakeCore(), page, onOpenNative = { k, s, t -> opened += Triple(k, s, t); true })
        b.onMessage("""{"id":1,"method":"openNative","args":["chatroom","did:ad:room","Planning"]}""")
        b.onMessage("""{"id":2,"method":"openNative","args":["document","did:ad:doc","Doc"]}""")
        b.onMessage("""{"id":3,"method":"openNative","args":["conversation","","x"]}""")
        advanceUntilIdle()
        assertEquals(listOf(Triple("chatroom", "did:ad:room", "Planning")), opened)
        assertTrue(page.scripts.contains("""window.__atomicReply(1,true,"true")"""))
        assertTrue(page.scripts.contains("""window.__atomicReply(2,true,"false")"""))
        assertTrue(page.scripts.contains("""window.__atomicReply(3,true,"false")"""))
    }

    @Test
    fun theResourceMarksAreTakenFromThePagesPaintedAndRevealedNotifications() = runTest(StandardTestDispatcher()) {
        val lines = mutableListOf<String>()
        val was = Perf.enabled
        Perf.enabled = true
        Perf.sink = { lines += it }
        var now = 5_000L
        Perf.clock = { now }
        Perf.reset()
        try {
            Perf.start()
            val page = FakePage()
            val b = bridge(page = page)
            b.onMessage("""{"method":"ready"}""")
            now += 100
            Perf.tapped()
            now += 20
            b.open("did:ad:doc", "did:ad:drive", "My doc")
            // The page is told to watch for the title and for the view to fill.
            assertTrue(page.scripts.any { it.contains("method:\"painted\"") && it.contains("\"My doc\"") })
            assertTrue(page.scripts.any { it.contains("method:\"revealed\"") })
            now += 300
            b.onMessage("""{"method":"painted","ms":280}""")
            b.onMessage("""{"method":"revealed","ms":310}""")
            assertTrue(lines.contains("[perf] resource painted warm 300 ms (span)"))
            assertTrue(lines.contains("[perf] resource painted warm since tap 320 ms (span)"))
            assertTrue(lines.contains("[perf] resource painted in page warm 280 ms (span)"))
            assertTrue(lines.contains("[perf] resource revealed warm since tap 320 ms (span)"))
            assertTrue(lines.contains("[perf] warm ready 0 ms"))
        } finally {
            Perf.enabled = was
            Perf.sink = { }
            Perf.clock = { System.nanoTime() / 1_000_000 }
            Perf.reset()
        }
    }
}
