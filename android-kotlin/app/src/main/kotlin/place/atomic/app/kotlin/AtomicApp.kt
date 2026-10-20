package place.atomic.app.kotlin

import android.app.Application
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.chat.AccountAi
import place.atomic.app.kotlin.chat.AiProvider
import place.atomic.app.kotlin.core.activeAgent
import place.atomic.app.kotlin.core.signWithAgent
import place.atomic.app.kotlin.embed.CoreEmbed
import place.atomic.app.kotlin.embed.EmbedController
import place.atomic.app.kotlin.session.KeystoreSecretBox
import place.atomic.app.kotlin.session.PrefsKeyValue
import place.atomic.app.kotlin.session.SessionStore

class AtomicApp : Application() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** The one warm WebView of the embedded renderer; created by [startEmbed]. */
    val embed: EmbedController by lazy {
        EmbedController(this, scope, CoreEmbed) { kind, subject, title -> nativeOpener?.invoke(kind, subject, title) ?: false }
    }

    /** Set by the screen that can show native chats: what the page's `openNative` calls. */
    @Volatile var nativeOpener: ((kind: String, subject: String, title: String) -> Boolean)? = null

    /** The agent's secret and routing state; the store does not keep the agent. */
    val session: SessionStore by lazy { SessionStore(PrefsKeyValue(this), KeystoreSecretBox()) }

    /** The AI of the linked account (a scripted one when a debug build asks for it). */
    val aiProvider: AiProvider by lazy {
        DebugAi.provider(this) ?: AccountAi(session, { runCatching { activeAgent()?.subject }.getOrNull() }, { signWithAgent(it) })
    }

    override fun onCreate() {
        super.onCreate()
        Perf.start()
    }

    private var pushing: AutoCloseable? = null

    /**
     * Once the store is open: loads the embed in the background WebView (main
     * thread) and pushes store changes into it. Safe to call again.
     */
    fun startEmbed() {
        embed.warm()
        if (pushing != null) return
        pushing = AutoCloseable { }
        scope.launch {
            pushing = CoreEmbed.pushChanges(embed.bridge::changed)
        }
    }
}
