package place.atomic.app.kotlin

import org.junit.Assert.assertEquals
import org.junit.Test
import place.atomic.app.kotlin.ui.classLabel
import place.atomic.app.kotlin.ui.timeAgo
import java.time.ZoneOffset

class FormatTest {
    @Test
    fun knownClassesGetTheirLabel() {
        assertEquals("Document", classLabel("DocumentV2"))
        assertEquals("Document", classLabel("https://atomicdata.dev/classes/DocumentV2"))
        assertEquals("AI chat", classLabel("AiChat"))
        assertEquals("Folder", classLabel("folder"))
    }

    @Test
    fun otherClassesLoseTheirVersionAndHyphens() {
        assertEquals("Web page", classLabel("web-page-v3"))
        assertEquals("Meeting note", classLabel("MeetingNote"))
        assertEquals("", classLabel(""))
    }

    @Test
    fun timeAgoReadsLikeTheFlutterApp() {
        val now = 1_760_000_000_000L
        assertEquals("just now", timeAgo(now - 30_000, now))
        assertEquals("5 min ago", timeAgo(now - 5 * 60_000, now))
        assertEquals("3 h ago", timeAgo(now - 3 * 3_600_000, now))
        assertEquals("2 d ago", timeAgo(now - 2 * 86_400_000, now))
        assertEquals("2025-09-29", timeAgo(now - 10 * 86_400_000, now, ZoneOffset.UTC))
    }
}
