package place.atomic.app.kotlin.chat

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import place.atomic.app.kotlin.Perf
import place.atomic.app.kotlin.core.ThreadMessage

/** What kind of chat a [ThreadModel] shows; the screen differs in a few places only. */
enum class ThreadKind { Conversation, Room }

data class ThreadState(
    val title: String = "",
    val window: WindowState<ThreadMessage> = WindowState(),
    /** Messages being sent, shown at the bottom until they are read back. */
    val pending: List<ThreadMessage> = emptyList(),
    val error: String? = null,
    /** The text of a message that could not be sent: the field takes it back (then [ThreadModel.unsentTaken]). */
    val unsent: String? = null,
) {
    /** What the list shows, oldest first. */
    val shown get() = window.items + pending
}

/** How often an open thread is read again for messages that arrived through sync. The read is local, so it is cheap. */
const val THREAD_REFRESH_MS = 3_000L

/**
 * A conversation (a DM or group chat, end-to-end encrypted, opened on this
 * device) or the chat of a meeting or chat room: the newest messages in a
 * window, older ones as the list scrolls up, new ones from a poll while the
 * screen is on top, and a field to write one. Twin of Flutter's
 * `ConversationScreen` and `ChatRoomScreen` state, which differ only in the
 * source of their messages.
 */
class ThreadModel(
    private val source: ThreadSource,
    title: String,
    private val scope: CoroutineScope,
    private val now: () -> Long = System::currentTimeMillis,
    /** Renames the thread (a chat room; a conversation has no name of its own). */
    private val renameWith: (suspend (String) -> Unit)? = null,
) {
    private val _ui = MutableStateFlow(ThreadState(title = title))
    val ui: StateFlow<ThreadState> = _ui.asStateFlow()

    private val window = ChatWindow(
        readPage = source::page,
        readAfter = source::after,
        idOf = { it.id },
        onOlderPage = { ms, n -> Perf.span("chat older page $n", ms) },
    )
    private var pendingCount = 0
    private val reading = Mutex()

    /** Sends run one after the other, so messages keep their order. */
    private val sends = Mutex()
    private val opened = now()

    init {
        scope.launch { window.state.collect { w -> _ui.update { it.copy(window = w) } } }
    }

    /** Fetches the thread when this device lacks it (best effort) and reads it. */
    fun start() {
        // With no sync session this fails; what is local is shown anyway.
        scope.launch { if (runCatching { source.follow() }.isSuccess) read() }
        scope.launch {
            read()
            Perf.span("chat data ${window.state.value.items.size}", now() - opened)
        }
    }

    /** For the `chat painted` mark: call after the frame that shows the messages. */
    fun painted() = Perf.span("chat painted ${window.state.value.items.size}", now() - opened)

    /** What arrived since the newest message read; shown at once when at the bottom, otherwise counted on the "Jump to latest" button. */
    suspend fun read(atBottom: Boolean = true) {
        if (!reading.tryLock()) return
        try {
            if (!window.state.value.loaded) window.open() else window.poll(atBottom)
        } finally {
            reading.unlock()
        }
    }

    fun poll(atBottom: Boolean) {
        scope.launch { read(atBottom) }
    }

    fun send(text: String) {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return
        val pending = ThreadMessage(
            id = "pending-${pendingCount++}", author = "", authorName = "", mine = true, text = trimmed,
            createdAt = now(), replyTo = null, isEvent = false, about = null, aboutTitle = "",
        )
        _ui.update { it.copy(pending = it.pending + pending, error = null) }
        scope.launch {
            sends.withLock {
                try {
                    source.send(trimmed)
                    read(atBottom = true)
                    // Your own message shows where you are writing: at the bottom.
                    val w = window.state.value
                    if (w.unseen > 0 || w.detached) window.jumpToLatest()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    _ui.update { it.copy(error = "Couldn't send: ${e.message ?: e}") }
                    _ui.update { it.copy(unsent = trimmed) }
                } finally {
                    _ui.update { it.copy(pending = it.pending - pending) }
                }
            }
        }
    }

    /** A chat room has no page of its own on the phone, so its name is changed here. */
    fun rename(name: String) {
        val trimmed = name.trim()
        val before = _ui.value.title
        if (trimmed.isEmpty() || trimmed == before) return
        _ui.update { it.copy(title = trimmed) }
        scope.launch {
            try {
                renameWith?.invoke(trimmed)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _ui.update { it.copy(title = before, error = "Couldn't rename: ${e.message ?: e}") }
            }
        }
    }

    fun unsentTaken() = _ui.update { it.copy(unsent = null) }

    fun loadOlder() = scope.launch { window.loadOlder() }
    fun loadNewer() = scope.launch { window.loadNewer() }
    fun jumpToLatest() = scope.launch { window.jumpToLatest() }
    fun trimOldest() = window.trimOldest()
    fun trimNewest() = window.trimNewest()
    val maxHeld get() = window.maxHeld
}

/** The model a screen holds, living as long as the screen. */
class ThreadViewModel(model: (CoroutineScope) -> ThreadModel) : androidx.lifecycle.ViewModel() {
    val model: ThreadModel = model(viewModelScope).also { it.start() }
}
