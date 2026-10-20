package place.atomic.app.kotlin.shell

import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.snapshots.SnapshotStateList
import place.atomic.app.kotlin.chat.NativeKind

/**
 * A page opened from the Home: a resource drawn by the web page ([kind] null), a
 * native chat ([kind] a [NativeKind] name) or one of [Kinds]. [nonce] tells new
 * chats apart.
 */
data class Destination(val kind: String?, val subject: String, val title: String, val drive: String, val nonce: Int = 0) {
    /** A resource, or a native screen of one: opening it counts as a visit when it is left. */
    val isResource get() = subject.isNotEmpty() && (kind == null || NativeKind.entries.any { it.name == kind })

    /** The drive page itself (a drive is its own drive). */
    val isDrive get() = kind == null && subject.isNotEmpty() && subject == drive

    val barPage: BarKind
        get() = when (kind) {
            Kinds.SETTINGS -> BarKind.Settings
            Kinds.PROFILE -> BarKind.Profile
            Kinds.ACTION -> BarKind.New
            else -> BarKind.Other
        }

    object Kinds {
        /** A section's full list; [subject] is the section's name. */
        const val LIST = "List"
        const val SETTINGS = "Settings"
        const val PROFILE = "Profile"

        /** A page of the web app, [subject] its path, in a second web view. */
        const val ACTION = "Action"
    }
}

enum class BarKind { Settings, Profile, New, Other }

/** Survives the activity being recreated: the stack as strings. */
val StackSaver = listSaver<SnapshotStateList<Destination>, String>(
    save = { stack -> stack.flatMap { listOf(it.kind.orEmpty(), it.subject, it.title, it.drive, it.nonce.toString()) } },
    restore = { saved ->
        mutableStateListOf<Destination>().apply {
            saved.chunked(5).filter { it.size == 5 }.forEach { add(Destination(it[0].ifEmpty { null }, it[1], it[2], it[3], it[4].toIntOrNull() ?: 0)) }
        }
    },
)

/**
 * The pages opened on top of the Home. A page counts as visited when it is
 * left, not when it is opened ([onLeave]): the Recents and the order of the
 * drives change then, not under the person's finger as they tap. Plain state
 * holder: the shell hands it the stack and what to do on a leave.
 */
class PageStack(val pages: MutableList<Destination>, private val onLeave: (Destination) -> Unit) {
    val top: Destination? get() = pages.lastOrNull()
    val isEmpty get() = pages.isEmpty()

    fun push(d: Destination) {
        pages.add(d)
    }

    /** Back: the page on top is left. */
    fun pop() {
        if (pages.isEmpty()) return
        onLeave(pages.removeAt(pages.lastIndex))
    }

    /** Every page is left, the top one first; [then] (when given) is the only page afterwards. */
    fun reset(then: Destination? = null) {
        while (pages.isNotEmpty()) onLeave(pages.removeAt(pages.lastIndex))
        if (then != null) pages.add(then)
    }
}
