package place.atomic.app.kotlin.embed

import place.atomic.app.kotlin.core.EmbedListener
import place.atomic.app.kotlin.core.embedDispatch
import place.atomic.app.kotlin.core.subscribeEmbed

/** The Rust side of the channel: `embed_dispatch` and the store-change push. */
object CoreEmbed : EmbedCore {
    override suspend fun dispatch(method: String, argsJson: String): String = embedDispatch(method, argsJson)

    /**
     * Calls [onChanged] with the resources to read again (a burst of store
     * events, deduplicated, without the page's own writes) until the returned
     * handle is closed.
     */
    suspend fun pushChanges(onChanged: (List<String>) -> Unit): AutoCloseable {
        val subscription = subscribeEmbed(object : EmbedListener {
            override fun onChanged(subjects: List<String>) = onChanged(subjects)
        })
        return AutoCloseable { subscription.cancel() }
    }
}
