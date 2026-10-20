package place.atomic.app.kotlin.chat

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import place.atomic.app.kotlin.Perf

/** Whether there is an AI to write to, as the chat screen tells it. */
enum class AiStatus {
    /** Being looked up; the field is there, switched off, so nothing moves when the answer lands. */
    Looking,

    /** No account on this device (or the portal knows none): the chat cannot be had. */
    NoAccount,

    /** The account has no included AI. */
    NotAvailable,

    /** The terms are not accepted yet: "Turn on AI". */
    NeedsConsent,
    Ready,
}

data class AiChatState(
    val title: String = "",
    /** The chat's subject; null on a new chat until its first message. */
    val chat: String? = null,
    val window: WindowState<ChatEntry> = WindowState(),
    val ai: AiStatus = AiStatus.Looking,
    /** The answer's parts as they stream in; null when none is coming. */
    val partial: List<ChatPart>? = null,
    val sending: Boolean = false,
    val error: String? = null,
    /** What the person attached as context for the messages of this screen. */
    val attached: List<ContextItem> = emptyList(),
    /** Resources added with the attach button (not one of the pills): their chips show also on an empty chat. */
    val fromDrive: Set<String> = emptySet(),
    /** The pills a new chat offers: two drives, then the latest opened. */
    val options: List<ContextItem> = emptyList(),
    /** The question just sent: the screen puts it at the top. */
    val sentId: String? = null,
) {
    val loaded get() = window.loaded || chat == null
    val messages get() = window.items
}

/** Most characters of one attached resource, and of all of them, sent to the AI. */
private const val MAX_ITEM_CHARS = 4000
private const val MAX_CONTEXT_CHARS = 12000

/** Most pills in the new-chat context picker, and recents offered. */
private const val MAX_PILLS = 5

/** How long a streamed answer waits before it is shown again: about 30 times a second. */
private const val FLUSH_MS = 33L

/**
 * An AI chat: reads it in windows, sends a message and streams the answer,
 * saves both like the web app's chat does, and gives the AI the resources the
 * person attached. Twin of Flutter's `ChatScreen` state (without voice and
 * file attachments). A chat without a subject is new: it is created with the
 * first message, named after it.
 */
class AiChatModel(
    private val backend: ChatBackend,
    private val provider: AiProvider,
    subject: String?,
    title: String,
    private val scope: CoroutineScope,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val _ui = MutableStateFlow(AiChatState(title = title, chat = subject))
    val ui: StateFlow<AiChatState> = _ui.asStateFlow()

    private val window = ChatWindow(
        readPage = { before, limit -> backend.aiPage(chat!!, before, limit) },
        // Only this screen writes the chat while it is open: nothing is polled;
        // this reads the newest pages back after a far scroll up dropped them.
        readAfter = { after, limit -> backend.aiAfter(chat!!, after, limit) },
        idOf = { it.id },
        onOlderPage = { ms, n -> Perf.span("chat older page $n", ms) },
    )
    private val chat get() = _ui.value.chat

    private var ai: HostedAi? = null
    private var localId = 0
    private val attachedText = mutableMapOf<String, String>()
    private val opened = now()

    /** Writes run one after another (the user message before the answer) but never hold up the model request or the screen. */
    private val persist = Mutex()
    private var answerJob: Job? = null
    private var flushJob: Job? = null
    private var pickerRead = false

    init {
        scope.launch { window.state.collect { w -> _ui.update { it.copy(window = w) } } }
    }

    /** Reads the chat (when it exists) and looks up the AI. */
    fun start() {
        scope.launch { readMessages() }
        scope.launch { lookUpAi() }
        if (chat == null) scope.launch { readPicker() }
    }

    private suspend fun readMessages() {
        if (chat == null) return
        window.open()
        val state = window.state.value
        if (state.error != null) return
        Perf.span("chat data ${state.items.size}", now() - opened)
        if (state.items.isEmpty()) readPicker()
    }

    /** For the `chat painted` mark: call after the frame that shows the messages. */
    fun painted() = Perf.span("chat painted ${window.state.value.items.size}", now() - opened)

    private suspend fun lookUpAi() {
        try {
            val found = provider.hostedAi()
            ai = found
            _ui.update { it.copy(ai = statusOf(found)) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            _ui.update { it.copy(ai = AiStatus.NoAccount, error = e.message ?: e.toString()) }
        }
    }

    private fun statusOf(ai: HostedAi?) = when {
        ai == null -> AiStatus.NoAccount
        !ai.available -> AiStatus.NotAvailable
        !ai.consent -> AiStatus.NeedsConsent
        else -> AiStatus.Ready
    }

    fun enableAi() {
        scope.launch {
            val found = ai ?: return@launch
            try {
                found.enable()
                _ui.update { it.copy(ai = statusOf(found), error = null) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _ui.update { it.copy(error = e.message ?: e.toString()) }
            }
        }
    }

    // ── Context ──────────────────────────────────────────────────────────

    /** The drives and the recently opened resources of all of them, for the picker. */
    private suspend fun readPicker() {
        if (pickerRead) return
        pickerRead = true
        val drives = runCatching { backend.drives() }.getOrDefault(emptyList())
        val recent = runCatching { backend.recents(100) }.getOrDefault(emptyList())
        val options = buildList {
            drives.take(2).forEach { add(ContextItem(it.subject, it.name.ifEmpty { "Untitled drive" }, "Drive", it.emoji)) }
            for (r in recent) {
                if (size >= MAX_PILLS) break
                if (any { it.subject == r.subject }) continue
                add(ContextItem(r.subject, r.title.ifEmpty { "Untitled" }, r.className, r.emoji))
            }
        }
        _ui.update { it.copy(options = options) }
    }

    fun toggle(item: ContextItem) = _ui.update { s ->
        val at = s.attached.indexOfFirst { it.subject == item.subject }
        s.copy(attached = if (at >= 0) s.attached - s.attached[at] else s.attached + item)
    }

    /** A resource picked with the attach button. */
    fun attach(item: ContextItem) = _ui.update { s ->
        s.copy(
            fromDrive = s.fromDrive + item.subject,
            attached = if (s.attached.any { it.subject == item.subject }) s.attached else s.attached + item,
        )
    }

    /** The text of what was attached, to go ahead of the history; null when nothing was. */
    private suspend fun contextText(attached: List<ContextItem>): String? {
        val parts = attached.mapNotNull { a ->
            var text = attachedText[a.subject]
            if (text == null) {
                text = try {
                    backend.resourceText(a.subject, MAX_ITEM_CHARS)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    return@mapNotNull null
                }
                attachedText[a.subject] = text
            }
            "${a.title} (${a.className})\n${text.take(MAX_ITEM_CHARS)}"
        }
        if (parts.isEmpty()) return null
        return "The user attached these resources as context:\n\n${parts.joinToString("\n\n")}".take(MAX_CONTEXT_CHARS)
    }

    // ── Sending ──────────────────────────────────────────────────────────

    fun send(text: String) {
        val trimmed = text.trim()
        val ai = ai
        val s = _ui.value
        if (trimmed.isEmpty() || ai == null || s.ai != AiStatus.Ready || s.sending) return
        val user = ChatEntry("local-${localId++}", "user", now(), listOf(ChatPart.Text(trimmed)), context = s.attached)
        window.add(user)
        // What the model reads: the window (the newest messages at least); the AI cuts a long one to its latest part.
        val asked = window.items
        _ui.update { it.copy(sending = true, error = null, partial = emptyList(), sentId = user.id) }
        // The user message is saved in the background; the chat exists from the first message on, named after it.
        scope.launch {
            try {
                persist.withLock {
                    val chat = chat ?: backend.newChat(if (trimmed.length > 40) trimmed.take(40) + "…" else trimmed)
                        .also { created -> _ui.update { it.copy(chat = created) } }
                    backend.addEntry(chat, user)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _ui.update { it.copy(error = e.message ?: e.toString()) }
            }
        }
        answerJob = scope.launch { stream(ai, asked, s.attached) }
    }

    /** Stop writing the reply: the request is cancelled and what came so far stays as the answer (nothing is kept when it is empty). */
    fun stop() {
        answerJob?.cancel()
    }

    private suspend fun stream(ai: HostedAi, asked: List<ChatEntry>, attached: List<ContextItem>) {
        val started = now()
        fun lap(what: String) = Perf.chat("+${now() - started}ms $what")
        // The answer's parts as they arrive: text, and tool calls in between.
        val parts = mutableListOf<ChatPart>()
        try {
            val context = contextText(attached)
            lap("context ready")
            var first = true
            ai.run(asked, context, assistantTools(backend)).collect { event ->
                if (first) {
                    first = false
                    lap("first event")
                }
                when (event) {
                    is AiEvent.TextDelta -> {
                        val last = parts.lastOrNull()
                        if (last is ChatPart.Text) parts[parts.size - 1] = ChatPart.Text(last.text + event.text) else parts.add(ChatPart.Text(event.text))
                        showLater(parts)
                    }
                    is AiEvent.ToolStarted -> {
                        parts.add(event.part)
                        showNow(parts)
                    }
                    is AiEvent.ToolFinished -> {
                        val at = parts.indexOfFirst { it is ChatPart.Tool && it.toolCallId == event.part.toolCallId }
                        if (at < 0) parts.add(event.part) else parts[at] = event.part
                        showNow(parts)
                    }
                }
            }
            lap("stream done")
        } catch (e: CancellationException) {
            lap("stopped")
        } catch (e: Exception) {
            _ui.update { it.copy(error = e.message ?: e.toString()) }
        } finally {
            withContext(NonCancellable) { finish(parts) }
            lap("done")
        }
    }

    private suspend fun finish(parts: MutableList<ChatPart>) {
        flushJob?.cancel()
        flushJob = null
        // A call cut off by Stop (or an error) did not finish.
        for (i in parts.indices) {
            val p = parts[i]
            if (p is ChatPart.Tool && p.state.running) parts[i] = p.failed("Stopped")
        }
        val keep = ChatEntry.textOf(parts).isNotEmpty() || parts.any { it is ChatPart.Tool }
        if (keep) {
            val reply = ChatEntry("local-${localId++}", "assistant", now(), parts.toList())
            window.add(reply)
            try {
                persist.withLock { chat?.let { backend.addEntry(it, reply) } }
            } catch (e: Exception) {
                _ui.update { it.copy(error = e.message ?: e.toString()) }
            }
        }
        _ui.update { it.copy(sending = false, partial = null) }
    }

    /** Shows [parts] as the partial reply at the next tick of a ~30 fps clock: a fast stream redraws (and re-reads its Markdown) less often than it delivers pieces. */
    private fun showLater(parts: List<ChatPart>) {
        if (flushJob != null) return
        // The first piece shows at once: the dots give way to text.
        val wait = if (_ui.value.partial.isNullOrEmpty()) 0L else FLUSH_MS
        flushJob = scope.launch {
            delay(wait)
            flushJob = null
            publish(parts)
        }
    }

    /** Shows [parts] as the partial reply now (a tool call starts or ends). */
    private fun showNow(parts: List<ChatPart>) {
        flushJob?.cancel()
        flushJob = null
        publish(parts)
    }

    private fun publish(parts: List<ChatPart>) {
        if (_ui.value.partial != null) _ui.update { it.copy(partial = parts.toList()) }
    }

    // ── Scrolling ────────────────────────────────────────────────────────

    fun loadOlder() = scope.launch { window.loadOlder() }
    fun loadNewer() = scope.launch { window.loadNewer() }
    fun jumpToLatest() = scope.launch { window.jumpToLatest() }
    fun trimOldest() = window.trimOldest()
    fun trimNewest() = window.trimNewest()
    val maxHeld get() = window.maxHeld
}

/** The model a screen holds, living as long as the screen (and the answer it is streaming). */
class AiChatViewModel(model: (CoroutineScope) -> AiChatModel) : ViewModel() {
    val model: AiChatModel = model(viewModelScope).also { it.start() }
}
