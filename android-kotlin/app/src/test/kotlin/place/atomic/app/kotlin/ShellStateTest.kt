package place.atomic.app.kotlin

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import place.atomic.app.kotlin.core.ConnectivityReport
import place.atomic.app.kotlin.shell.BackgroundSync
import place.atomic.app.kotlin.shell.Destination
import place.atomic.app.kotlin.shell.PageStack
import place.atomic.app.kotlin.shell.ToastController

class ToastControllerTest {
    private var now = 0L
    private val toasts = ToastController(maxVisible = 2, cooldownMs = 30_000, now = { now })

    @Test
    fun theSameKeyIsTheSameToastWithAFreshTimer() {
        assertTrue(toasts.show("a", "one"))
        assertTrue(toasts.show("a", "two"))
        val list = toasts.toasts.value
        assertEquals(1, list.size)
        assertEquals("two", list[0].message)
        assertEquals(1, list[0].revision)
    }

    @Test
    fun aDismissedToastStaysQuietForTheCooldownUnlessResolved() {
        toasts.show("a", "one")
        toasts.dismiss("a")
        assertFalse(toasts.show("a", "again"))
        now += 29_999
        assertFalse(toasts.show("a", "again"))
        now += 2
        assertTrue(toasts.show("a", "again"))
        toasts.dismiss("a")
        toasts.resolve("a")
        assertTrue(toasts.show("a", "at once"))
    }

    @Test
    fun atMostMaxVisibleAndTheOldestGoesFirst() {
        toasts.show("a", "1")
        toasts.show("b", "2")
        toasts.show("c", "3")
        assertEquals(listOf("b", "c"), toasts.toasts.value.map { it.key })
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
class BackgroundSyncTest {
    private class Sync(val reports: ArrayDeque<Result<ConnectivityReport>>) : FakeBackend() {
        var syncCalls = 0
        override suspend fun syncNow(): ConnectivityReport {
            syncCalls++
            return reports.removeFirst().getOrThrow()
        }
    }

    private fun report(live: UInt = 0u, imported: Int = 0, message: String = "Could not reach anyone") = ConnectivityReport(imported, live, message)

    @Test
    fun retryWaitsDoubleFrom20SecondsToFiveMinutes() {
        assertEquals(listOf(20L, 40L, 80L, 160L, 300L, 300L), (1..6).map { BackgroundSync.retrySeconds(it) })
    }

    @Test
    fun oneFailureIsQuietTheSecondOneSpeaksAndASuccessTakesItAway() = runTest(StandardTestDispatcher()) {
        val backend = Sync(ArrayDeque(listOf(Result.success(report()), Result.success(report()), Result.success(report(live = 1u)))))
        val toasts = ToastController()
        val sync = BackgroundSync(backend, toasts, TestScope(testScheduler))
        sync.start()
        advanceTimeBy(1)
        assertEquals(1, sync.failures)
        assertTrue(toasts.toasts.value.isEmpty())

        // The retry comes after 20 s.
        advanceTimeBy(20_000)
        assertEquals(2, backend.syncCalls)
        assertEquals(listOf("sync:error"), toasts.toasts.value.map { it.key })
        assertEquals("Retry", toasts.toasts.value[0].actionLabel)

        advanceTimeBy(40_001)
        assertEquals(3, backend.syncCalls)
        assertEquals(0, sync.failures)
        assertTrue(toasts.toasts.value.isEmpty())
    }

    @Test
    fun noOtherDeviceYetIsNotAFailureAndAnExceptionIs() = runTest(StandardTestDispatcher()) {
        val backend = Sync(ArrayDeque(listOf(Result.success(report(message = "No other device found yet. Open the app on it.")), Result.failure(IllegalStateException("boom")))))
        val toasts = ToastController()
        val sync = BackgroundSync(backend, toasts, TestScope(testScheduler))
        sync.start()
        advanceUntilIdle()
        assertEquals(0, sync.failures)
        sync.start()
        advanceTimeBy(1)
        assertEquals(1, sync.failures)
        sync.stop()
        advanceUntilIdle()
        assertEquals(0, sync.failures)
        assertEquals(2, backend.syncCalls)
    }
}

class PageStackTest {
    private val left = mutableListOf<String>()
    private fun page(subject: String, drive: String = "did:ad:d") = Destination(null, subject, subject, drive)
    private val stack = PageStack(mutableListOf()) { left += it.subject }

    @Test
    fun aPageCountsAsVisitedWhenItIsLeftNotWhenItIsOpened() {
        stack.push(page("a"))
        stack.push(page("b"))
        assertEquals(emptyList<String>(), left)
        stack.pop()
        assertEquals(listOf("b"), left)
    }

    @Test
    fun resetLeavesEveryPageTopFirstAndMaybeShowsOne() {
        stack.push(page("a"))
        stack.push(page("b"))
        stack.reset(page("c"))
        assertEquals(listOf("b", "a"), left)
        assertEquals("c", stack.top?.subject)
        stack.reset()
        assertTrue(stack.isEmpty)
        stack.pop()
        assertEquals(listOf("b", "a", "c"), left)
    }

    @Test
    fun aDriveIsItsOwnDriveAndOnlyResourcesAndNativeChatsCountAsVisits() {
        assertTrue(page("did:ad:d").isDrive)
        assertFalse(page("did:ad:x").isDrive)
        assertTrue(Destination("AiChat", "did:ad:chat", "", "did:ad:d").isResource)
        assertFalse(Destination("AiChat", "", "", "").isResource)
        assertFalse(Destination(Destination.Kinds.SETTINGS, "", "", "").isResource)
        assertFalse(Destination(Destination.Kinds.LIST, "Chats", "", "").isResource)
    }
}
