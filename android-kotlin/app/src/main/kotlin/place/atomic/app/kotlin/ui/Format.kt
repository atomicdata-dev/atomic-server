package place.atomic.app.kotlin.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.BookmarkBorder
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.DataObject
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.automirrored.outlined.InsertDriveFile
import androidx.compose.material.icons.outlined.Sell
import androidx.compose.material.icons.automirrored.outlined.ShowChart
import androidx.compose.material.icons.outlined.TableChart
import androidx.compose.material.icons.outlined.Videocam
import androidx.compose.ui.graphics.vector.ImageVector
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

/** Class shortname or URL -> comparable key (`document-v2` -> `documentv2`). */
private fun classKey(className: String): String =
    className.trim().split('/', '#').lastOrNull { it.isNotEmpty() }.orEmpty()
        .lowercase().replace(Regex("[^a-z0-9]"), "")

/** Icon of a class, as `iconForClass` of the Flutter app. */
fun iconForClass(className: String): ImageVector = when (classKey(className)) {
    "folder", "drive" -> Icons.Outlined.Folder
    "table" -> Icons.Outlined.TableChart
    "aichat", "conversation", "chatroom" -> Icons.Outlined.ChatBubbleOutline
    "meeting" -> Icons.Outlined.Videocam
    "class", "property", "ontology" -> Icons.Outlined.DataObject
    "bookmark" -> Icons.Outlined.BookmarkBorder
    "file" -> Icons.AutoMirrored.Outlined.InsertDriveFile
    "dashboard" -> Icons.AutoMirrored.Outlined.ShowChart
    "tag" -> Icons.Outlined.Sell
    else -> Icons.Outlined.Description
}

private val classLabels = mapOf(
    "document" to "Document", "documentv2" to "Document", "table" to "Table", "folder" to "Folder",
    "drive" to "Drive", "chatroom" to "Chat", "conversation" to "Chat", "meeting" to "Meeting",
    "aichat" to "AI chat", "chatlog" to "AI chat", "canvas" to "Canvas", "bookmark" to "Bookmark",
    "file" to "File", "dashboard" to "Dashboard", "tag" to "Tag", "class" to "Class",
    "property" to "Property", "ontology" to "Ontology", "formfield" to "Form field",
    "form" to "Form", "message" to "Message", "article" to "Article", "agent" to "Agent",
)

/**
 * A class as a person reads it: a known class gets its label (`Document`), any
 * other the shortname without a version suffix, hyphens as spaces and a
 * capital (`web-page-v3` -> `Web page`). Same as `classLabel` in Flutter.
 */
fun classLabel(className: String): String {
    var name = className.trim().split(Regex("[/#]")).lastOrNull { it.isNotEmpty() }.orEmpty()
    if (name.isEmpty()) return ""
    classLabels[classKey(name)]?.let { return it }
    name = name
        .replace(Regex("[-_ ]?v\\d+$", RegexOption.IGNORE_CASE), "")
        .replace(Regex("[-_]+"), " ")
        .replace(Regex("([a-z0-9])([A-Z])"), "$1 $2")
        .trim().lowercase()
    return name.replaceFirstChar { it.uppercase() }
}

/** "just now", "5 min ago", "3 h ago", "2 d ago", then the date. */
fun timeAgo(ms: Long, now: Long = System.currentTimeMillis(), zone: ZoneId = ZoneId.systemDefault()): String {
    val minutes = (now - ms) / 60_000
    return when {
        minutes < 1 -> "just now"
        minutes < 60 -> "$minutes min ago"
        minutes < 60 * 24 -> "${minutes / 60} h ago"
        minutes < 60 * 24 * 7 -> "${minutes / (60 * 24)} d ago"
        else -> LocalDate.ofInstant(Instant.ofEpochMilli(ms), zone).toString()
    }
}

private val MONTHS = listOf(
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December",
)

private fun dayOf(ms: Long, zone: ZoneId) = Instant.ofEpochMilli(ms).atZone(zone).toLocalDate()

/** "Today", "Yesterday" or the date, for a separator above the first message of a day. */
fun dayLabel(ms: Long, now: Long = System.currentTimeMillis(), zone: ZoneId = ZoneId.systemDefault()): String {
    val day = dayOf(ms, zone)
    val today = dayOf(now, zone)
    val diff = java.time.temporal.ChronoUnit.DAYS.between(day, today)
    if (diff == 0L) return "Today"
    if (diff == 1L) return "Yesterday"
    val date = "${day.dayOfMonth} ${MONTHS[day.monthValue - 1]}"
    return if (day.year == today.year) date else "$date ${day.year}"
}

/** Whether two times (ms) are on different days. */
fun otherDay(a: Long, b: Long, zone: ZoneId = ZoneId.systemDefault()) = dayOf(a, zone) != dayOf(b, zone)

/** "14:05" for today, "3 Oct 14:05" for another day this year, with the year for an older one. */
fun messageTime(ms: Long, now: Long = System.currentTimeMillis(), zone: ZoneId = ZoneId.systemDefault()): String {
    val at = Instant.ofEpochMilli(ms).atZone(zone)
    val today = dayOf(now, zone)
    val clock = "%02d:%02d".format(at.hour, at.minute)
    if (at.toLocalDate() == today) return clock
    val date = "${at.dayOfMonth} ${MONTHS[at.monthValue - 1].take(3)}"
    return if (at.year == today.year) "$date $clock" else "$date ${at.year} $clock"
}
