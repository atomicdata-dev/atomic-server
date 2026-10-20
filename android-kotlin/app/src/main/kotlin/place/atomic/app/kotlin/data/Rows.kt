package place.atomic.app.kotlin.data

import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.core.ResourceRow
import place.atomic.app.kotlin.core.SearchHit
import place.atomic.app.kotlin.ui.classLabel
import place.atomic.app.kotlin.ui.timeAgo

/** The sections of the Home screen, in order (Flutter's `HomeSection`). */
enum class Section(val title: String, val empty: String, val hideEmpty: Boolean) {
    Drives("Drives", "No drives yet", false),
    Recents("Recents", "Nothing opened yet", false),
    Chats("AI chats", "No chats yet", false),
    Favorites("Favorites", "No favorites yet", true),
    Messages("Messages", "No messages yet", true),
}

/** One line of any list: what the single row composable draws. */
data class RowItem(
    val subject: String,
    val title: String,
    val detail: String = "",
    val className: String = "",
    val emoji: String? = null,
    val trailing: String = "",
)

/** Rows of a section that hold at most this many on the Home. */
const val HOME_ROWS = 4

private fun preview(text: String): String {
    val flat = text.replace(Regex("\\s+"), " ").trim()
    return if (flat.length > 80) flat.take(79) + "…" else flat
}

fun DriveRow.toItem() = RowItem(
    subject = subject,
    title = name.ifEmpty { "Untitled drive" },
    className = "drive",
    emoji = emoji,
)

/** `<drive> · <class> · <when>`, as the Flutter home writes it. */
fun ResourceRow.toItem(section: Section, driveNames: Map<String, String> = emptyMap(), now: Long = System.currentTimeMillis()): RowItem {
    val title = title.ifEmpty { subject }
    return when (section) {
        Section.Chats -> RowItem(subject, title.ifEmpty { "Untitled chat" }, className = "aichat",
            emoji = emoji, trailing = if (openedAt > 0) timeAgo(openedAt, now) else "")
        Section.Messages -> RowItem(subject, title, detail = preview(detail), className = "conversation",
            emoji = emoji, trailing = if (openedAt > 0) timeAgo(openedAt, now) else "")
        else -> RowItem(
            subject, title,
            detail = listOfNotNull(
                driveNames[drive].takeIf { section == Section.Recents },
                classLabel(className).ifEmpty { null },
                if (openedAt > 0) timeAgo(openedAt, now) else null,
            ).joinToString(" · "),
            className = className, emoji = emoji,
        )
    }
}

fun SearchHit.toItem(driveNames: Map<String, String> = emptyMap()) = RowItem(
    subject = subject,
    title = title.ifEmpty { subject },
    detail = listOfNotNull(driveNames[drive], classLabel(className).ifEmpty { null }).joinToString(" · "),
    className = className,
    emoji = emoji,
)
