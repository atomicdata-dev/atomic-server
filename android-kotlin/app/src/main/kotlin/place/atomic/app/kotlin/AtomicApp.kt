package place.atomic.app.kotlin

import android.app.Application
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.embed.CoreEmbed
import place.atomic.app.kotlin.embed.EmbedController

class AtomicApp : Application() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** The one warm WebView of the embedded renderer; created by [startEmbed]. */
    val embed: EmbedController by lazy { EmbedController(this, scope, CoreEmbed) }

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
