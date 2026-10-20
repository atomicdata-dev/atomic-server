package place.atomic.app.kotlin

import android.content.Context
import place.atomic.app.kotlin.chat.AiProvider

/** Release builds carry no scripted AI. */
@Suppress("UNUSED_PARAMETER")
object DebugAi {
    fun provider(context: Context): AiProvider? = null
}
