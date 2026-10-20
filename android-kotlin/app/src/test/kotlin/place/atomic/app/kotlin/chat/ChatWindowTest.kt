package place.atomic.app.kotlin.chat

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A chat of ids "m000".."m(n-1)" read the way the core reads it: pages with cursors that are ids. */
private class Chat(var size: Int) {
    val reads = mutableListOf<String>()
    private fun id(i: Int) = "m%03d".format(i)

    suspend fun page(before: String?, limit: Int): ChatPage<String> {
        reads += "before:$before"
        val end = before?.let { it.drop(1).toInt() } ?: size
        val start = maxOf(0, end - limit)
        val items = (start until end).map(::id)
        return ChatPage(items, older = if (start > 0) items.first() else null, newest = items.lastOrNull())
    }

    suspend fun after(after: String, limit: Int): ChatPage<String> {
        reads += "after:$after"
        val start = after.drop(1).toInt() + 1
        val end = minOf(size, start + limit)
        val items = (start until end).map(::id)
        return ChatPage(items, newest = items.lastOrNull(), more = end < size)
    }
}

class ChatWindowTest {
    private fun window(chat: Chat, pageSize: Int = 10, maxItems: Int = 30, older: MutableList<Int> = mutableListOf()) =
        ChatWindow(chat::page, chat::after, { it }, pageSize, maxItems, onOlderPage = { _, n -> older += n })

    @Test
    fun openReadsTheNewestPageAndKnowsThereIsMoreBefore() = runTest {
        val w = window(Chat(95))
        w.open()
        val s = w.state.value
        assertTrue(s.loaded)
        assertEquals((85 until 95).map { "m%03d".format(it) }, s.items)
        assertTrue(s.hasOlder)
    }

    @Test
    fun aShortChatHasNothingOlder() = runTest {
        val w = window(Chat(4))
        w.open()
        assertEquals(4, w.state.value.items.size)
        assertFalse(w.state.value.hasOlder)
        w.loadOlder()
        assertEquals(4, w.state.value.items.size)
    }

    @Test
    fun olderPagesAreAddedBeforeAndReportedWithTheWindowSize() = runTest {
        val sizes = mutableListOf<Int>()
        val w = window(Chat(95), older = sizes)
        w.open()
        w.loadOlder()
        w.loadOlder()
        assertEquals("m065", w.state.value.items.first())
        assertEquals("m094", w.state.value.items.last())
        assertEquals(listOf(20, 30), sizes)
    }

    @Test
    fun theWindowDropsItsOldestPagesNearTheBottomAndFetchesThemAgainOnScroll() = runTest {
        val w = window(Chat(95))
        w.open()
        repeat(4) { w.loadOlder() }
        assertEquals(50, w.state.value.items.size)
        // Whole pages go while at least maxItems (30) are left.
        w.trimOldest()
        assertEquals(30, w.state.value.items.size)
        assertEquals("m065", w.state.value.items.first())
        assertTrue(w.state.value.hasOlder)
        w.loadOlder()
        assertEquals("m055", w.state.value.items.first())
    }

    @Test
    fun farUpTheNewestPagesGoAndComeBackThroughLoadNewer() = runTest {
        val chat = Chat(95)
        val w = window(chat)
        w.open()
        repeat(4) { w.loadOlder() }
        w.trimNewest()
        assertTrue(w.state.value.detached)
        assertEquals("m074", w.state.value.items.last())
        w.loadNewer()
        w.loadNewer()
        assertEquals("m094", w.state.value.items.last())
        assertFalse(w.state.value.detached)
    }

    @Test
    fun jumpToLatestFromADetachedWindowReadsTheNewestPageAgain() = runTest {
        val w = window(Chat(95))
        w.open()
        repeat(4) { w.loadOlder() }
        w.trimNewest()
        w.jumpToLatest()
        assertEquals((85 until 95).map { "m%03d".format(it) }, w.state.value.items)
        assertFalse(w.state.value.detached)
    }

    @Test
    fun pollingAtTheBottomAddsNewMessagesAndScrolledUpOnlyCountsThem() = runTest {
        val chat = Chat(20)
        val w = window(chat)
        w.open()
        chat.size = 22
        w.poll(atBottom = true)
        assertEquals("m021", w.state.value.items.last())
        assertEquals(0, w.state.value.unseen)
        chat.size = 24
        w.poll(atBottom = false)
        assertEquals("m021", w.state.value.items.last())
        assertEquals(2, w.state.value.unseen)
        w.jumpToLatest()
        assertEquals("m023", w.state.value.items.last())
        assertEquals(0, w.state.value.unseen)
    }

    @Test
    fun aMessageReadTwiceIsShownOnce() = runTest {
        val w = ChatWindow(
            readPage = { _, _ -> ChatPage(listOf("a", "b"), newest = "b") },
            readAfter = { _, _ -> ChatPage(listOf("b", "c"), newest = "c") },
            idOf = { it },
        )
        w.open()
        w.poll(true)
        w.poll(true)
        assertEquals(listOf("a", "b", "c"), w.state.value.items)
    }

    @Test
    fun aFailedFirstReadIsAnErrorAndAFailedRefreshKeepsWhatIsShown() = runTest {
        var fail = true
        val w = ChatWindow<String>(
            readPage = { _, _ -> if (fail) error("offline") else ChatPage(listOf("a")) },
            readAfter = null,
            idOf = { it },
        )
        w.open()
        assertEquals("offline", w.state.value.error)
        fail = false
        w.open()
        assertNull(w.state.value.error)
        fail = true
        w.open()
        assertEquals(listOf("a"), w.state.value.items)
        assertNull(w.state.value.error)
    }
}
