package place.atomic.app.kotlin.chat

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * One window of a chat as the core reads it: [items] oldest first, [older] the
 * cursor of the window before (null at the start of the chat), [newest] the
 * cursor of the last item (null when there is none; for reading what came
 * after), [more] when a read of newer items was cut by its limit. Cursors are
 * opaque.
 */
data class ChatPage<T>(
    val items: List<T>,
    val older: String? = null,
    val newest: String? = null,
    val more: Boolean = false,
)

/** What a chat screen shows of its [ChatWindow]. */
data class WindowState<T>(
    /** Everything in the window, oldest first, the screen's own (sent) items last. */
    val items: List<T> = emptyList(),
    val loaded: Boolean = false,
    val error: String? = null,
    /** More before the first item: the top of the list reads the next page. */
    val hasOlder: Boolean = false,
    val loadingOlder: Boolean = false,
    /** The newest items are not in the window (scrolled far up). */
    val detached: Boolean = false,
    /** Items that arrived while scrolled up, not shown yet (at least one when [detached] and news). */
    val unseen: Int = 0,
)

private class Chunk<T>(val items: MutableList<T>, val older: String?, var newest: String?)

/**
 * What a chat screen holds of a chat that may be very long (a channel of
 * 200 000 messages): a bounded window of it, read in pages of [pageSize] as the
 * person scrolls. The Kotlin twin of Flutter's `ChatWindow`
 * (`packages/atomic_chat/lib/src/chat_window.dart`), method for method:
 *
 *  - [open] reads the newest page;
 *  - [loadOlder] adds the page before the first item (scrolled up);
 *  - [poll] reads what arrived after the last item: added at once when the
 *    person is at the bottom, else counted in `unseen` until [jumpToLatest];
 *  - the window keeps at most [maxItems]: near the bottom the oldest pages go
 *    ([trimOldest]), far up the newest go ([trimNewest]) and come back through
 *    [loadNewer]; `detached` tells that the newest items are not in the window;
 *  - [add] puts an item the screen made itself (a sent message) at the end.
 *
 * Items are told apart by [idOf], so a page read twice adds nothing twice.
 * Call it from one coroutine context (the view model's, the main thread).
 */
class ChatWindow<T>(
    private val readPage: suspend (before: String?, limit: Int) -> ChatPage<T>,
    private val readAfter: (suspend (after: String, limit: Int) -> ChatPage<T>)?,
    private val idOf: (T) -> String,
    val pageSize: Int = 50,
    val maxItems: Int = 500,
    /** Told how long each older page took (ms) and how many items the window then holds. */
    private val onOlderPage: (ms: Long, items: Int) -> Unit = { _, _ -> },
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val chunks = mutableListOf<Chunk<T>>()
    private val local = mutableListOf<T>()
    private val waiting = mutableListOf<T>()
    private var latest: String? = null
    private var loaded = false
    private var error: String? = null
    private var loadingOlder = false
    private var loadingNewer = false
    private var detached = false
    private var detachedNews = false

    private val _state = MutableStateFlow(WindowState<T>())
    val state: StateFlow<WindowState<T>> = _state.asStateFlow()

    val items: List<T> get() = _state.value.items
    val maxHeld: Int get() = maxItems

    private fun hasOlder() = chunks.firstOrNull()?.older != null

    private fun publish() {
        val all = buildList {
            chunks.forEach { addAll(it.items) }
            addAll(local)
        }
        _state.value = WindowState(
            items = all,
            loaded = loaded,
            error = error,
            hasOlder = hasOlder(),
            loadingOlder = loadingOlder,
            detached = detached,
            unseen = waiting.size + if (detachedNews) 1 else 0,
        )
    }

    private fun known(): Set<String> = buildSet {
        chunks.forEach { c -> c.items.forEach { add(idOf(it)) } }
        local.forEach { add(idOf(it)) }
    }

    suspend fun open() {
        try {
            val page = readPage(null, pageSize)
            chunks.clear()
            chunks.add(Chunk(page.items.toMutableList(), page.older, page.newest))
            local.clear()
            waiting.clear()
            latest = page.newest
            detached = false
            detachedNews = false
            loaded = true
            error = null
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            // A failed refresh keeps what is shown.
            if (!loaded) {
                error = e.message ?: e.toString()
                loaded = true
            }
        }
        publish()
    }

    suspend fun loadOlder() {
        if (loadingOlder || !hasOlder()) return
        loadingOlder = true
        publish()
        val started = clock()
        try {
            val first = chunks.first()
            val page = readPage(first.older, pageSize)
            if (chunks.firstOrNull() === first) {
                val known = known()
                chunks.add(0, Chunk(page.items.filter { idOf(it) !in known }.toMutableList(), page.older, page.newest))
                onOlderPage(clock() - started, chunks.sumOf { it.items.size } + local.size)
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            // Tried again on the next scroll.
        } finally {
            loadingOlder = false
            publish()
        }
    }

    /** While [WindowState.detached]: the page after the last item, back towards the newest. */
    suspend fun loadNewer() {
        val after = chunks.lastOrNull()?.newest
        val reader = readAfter
        if (!detached || loadingNewer || reader == null || after == null) return
        loadingNewer = true
        try {
            val page = reader(after, pageSize)
            val known = known()
            chunks.add(Chunk(page.items.filter { idOf(it) !in known }.toMutableList(), null, page.newest ?: after))
            if (!page.more) {
                detached = false
                detachedNews = false
                latest = page.newest ?: after
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
        } finally {
            loadingNewer = false
            publish()
        }
    }

    /** Read what arrived after the newest item. With [atBottom] it is shown at once; otherwise it waits. */
    suspend fun poll(atBottom: Boolean) {
        val reader = readAfter ?: return
        val after = latest
        if (after == null) {
            // An empty chat: read the newest page again.
            if (items.isEmpty()) open()
            return
        }
        try {
            val page = reader(after, pageSize)
            latest = page.newest ?: after
            if (page.items.isEmpty()) return
            if (detached) {
                detachedNews = true
                publish()
                return
            }
            val known = known()
            val fresh = page.items.filter { idOf(it) !in known }
            if (atBottom && waiting.isEmpty()) {
                appendRead(fresh, page.newest)
                // A burst longer than a page: the newest page is enough.
                if (page.more) open()
            } else {
                waiting.addAll(fresh)
                if (page.more) detachedNews = true
            }
            publish()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            // A failed poll keeps what is shown.
        }
    }

    private fun appendRead(fresh: List<T>, newest: String?) {
        if (chunks.isEmpty()) chunks.add(Chunk(mutableListOf(), null, null))
        chunks.last().items.addAll(fresh)
        chunks.last().newest = newest ?: chunks.last().newest
    }

    /** Show the newest items: the waiting ones, or the newest page again when the window had left them. */
    suspend fun jumpToLatest() {
        if (detached || detachedNews) {
            open()
            return
        }
        appendRead(waiting.toList(), latest)
        waiting.clear()
        publish()
    }

    /** Add an item the screen made (a message being sent) at the end. */
    fun add(item: T) {
        local.add(item)
        publish()
    }

    /** Replace the screen's own items (sent messages: pending ones go once they are read back). */
    fun setLocal(items: List<T>) {
        local.clear()
        local.addAll(items)
        publish()
    }

    /** Scrolled near the bottom: drop the oldest pages beyond [maxItems]. Nothing on screen moves. */
    fun trimOldest() {
        var n = chunks.sumOf { it.items.size } + local.size
        var dropped = false
        while (chunks.size > 1 && n - chunks.first().items.size >= maxItems) {
            n -= chunks.removeAt(0).items.size
            dropped = true
        }
        if (dropped) publish()
    }

    /** Scrolled far up: drop the newest pages beyond [maxItems]; [loadNewer] or [jumpToLatest] read them again. */
    fun trimNewest() {
        if (local.isNotEmpty() || readAfter == null) return
        var n = chunks.sumOf { it.items.size }
        var dropped = false
        while (chunks.size > 1 && n - chunks.last().items.size >= maxItems && chunks[chunks.size - 2].newest != null) {
            n -= chunks.removeAt(chunks.size - 1).items.size
            dropped = true
        }
        if (dropped) {
            detached = true
            waiting.clear()
            publish()
        }
    }
}
