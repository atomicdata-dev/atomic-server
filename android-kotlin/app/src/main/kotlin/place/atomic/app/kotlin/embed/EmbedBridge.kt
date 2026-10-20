package place.atomic.app.kotlin.embed

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** The Rust dispatcher (`embed_dispatch`): one async call per page request. */
fun interface EmbedCore {
    suspend fun dispatch(method: String, argsJson: String): String
}

/** The WebView, as the bridge uses it. Both calls may come from any thread. */
interface EmbedPage {
    /** Runs [script] in the page (fire and forget). */
    fun run(script: String)

    /** Runs [script] and gives its result as JSON text (`true`, `"x"`), null when it failed. */
    suspend fun evaluate(script: String): String?
}

/**
 * The page's end of the channel, without Android in it: answers the page's
 * calls from [core], keeps the pre-loaded page's state (ready, what to open
 * once it is) and builds the host calls (open, changed, back, flush).
 *
 * Calls the app answers itself (the page also asks for them in Flutter):
 * `openNative` is "no" (no native chat screens yet), `theme` is noted and
 * acknowledged, `opened` gets the drive the resource is shown in.
 */
class EmbedBridge(
    private val scope: CoroutineScope,
    private val core: EmbedCore,
    private val page: EmbedPage,
    private val flushTimeoutMs: Long = 2_000,
    private val onTheme: (String) -> Unit = {},
) {
    @Volatile private var ready = false
    @Volatile private var pendingSubject: String? = null
    @Volatile private var drive: String = ""
    @Volatile private var dark: Boolean? = null
    private val flushes = ConcurrentHashMap<Int, CompletableDeferred<Unit>>()
    private val nextFlush = AtomicInteger()

    val isReady get() = ready

    /** A message from `AtomicFlutter.postMessage`. May run on any thread. */
    fun onMessage(message: String) {
        val request = EmbedProtocol.parse(message) ?: return
        val id = request.id
        when {
            id == null -> notification(request)
            else -> scope.launch { answer(id, request) }
        }
    }

    private fun notification(request: EmbedProtocol.Request) {
        when (request.method) {
            "ready" -> {
                ready = true
                dark?.let { page.run(EmbedProtocol.setColorSchemeScript(it)) }
                pendingSubject?.let { page.run(EmbedProtocol.openScript(it)) }
                pendingSubject = null
            }
            "flushed" -> request.flushId?.let { flushes.remove(it)?.complete(Unit) }
        }
    }

    private suspend fun answer(id: Int, request: EmbedProtocol.Request) {
        val (ok, payload) = try {
            true to when (request.method) {
                "openNative" -> "false"
                "theme" -> {
                    onTheme(firstString(request.argsJson))
                    "true"
                }
                "opened" -> core.dispatch("opened", openedArgs(request.argsJson))
                else -> core.dispatch(request.method, request.argsJson)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false to (e.message ?: e.toString())
        }
        page.run(EmbedProtocol.replyScript(id, ok, payload))
    }

    private fun firstString(argsJson: String): String =
        org.json.JSONArray(argsJson).optString(0, "")

    /** `opened(subject)` becomes `opened(subject, drive)`: the drive the app shows it in. */
    private fun openedArgs(argsJson: String): String =
        org.json.JSONArray().put(firstString(argsJson)).put(drive).toString()

    // ── Host calls ─────────────────────────────────────────────────────────

    /** Shows [subject] (in [inDrive]); waits for the page when it is still loading. */
    fun open(subject: String, inDrive: String) {
        drive = inDrive
        if (ready) page.run(EmbedProtocol.openScript(subject)) else pendingSubject = subject
    }

    /** These resources changed in the store. */
    fun changed(subjects: List<String>) {
        if (ready && subjects.isNotEmpty()) page.run(EmbedProtocol.changedScript(subjects))
    }

    /** The app's light/dark mode; remembered for a page that is not up yet. */
    fun setColorScheme(dark: Boolean) {
        this.dark = dark
        if (ready) page.run(EmbedProtocol.setColorSchemeScript(dark))
    }

    /** One step back inside the page; false when it is on its first page (leave then). */
    suspend fun back(): Boolean = ready && page.evaluate(EmbedProtocol.BACK_SCRIPT) == "true"

    /** Hands every pending edit to the app and waits for the page to say so (capped). */
    suspend fun flush(leaving: Boolean) {
        if (!ready) return
        val id = nextFlush.incrementAndGet()
        val done = CompletableDeferred<Unit>()
        flushes[id] = done
        page.run(EmbedProtocol.flushScript(id, leaving))
        withTimeoutOrNull(flushTimeoutMs) { done.await() }
        flushes.remove(id)
    }

    /** The person left the resource: pending edits go, and the page lets go of the view. */
    suspend fun leave() {
        pendingSubject = null
        flush(leaving = true)
        if (ready) page.run(EmbedProtocol.openScript(""))
        drive = ""
    }

    /** The page is (re)loading: it is not ready until it says so. */
    fun pageStarted() {
        ready = false
        flushes.values.forEach { it.complete(Unit) }
        flushes.clear()
    }
}
