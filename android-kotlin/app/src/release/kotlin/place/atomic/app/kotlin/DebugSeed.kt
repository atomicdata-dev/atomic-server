package place.atomic.app.kotlin

import android.content.Context

/** Release builds carry no test data. */
@Suppress("UNUSED_PARAMETER")
object DebugSeed {
    suspend fun runIfAsked(context: Context) = Unit
}
