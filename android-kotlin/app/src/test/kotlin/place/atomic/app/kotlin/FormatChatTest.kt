package place.atomic.app.kotlin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import place.atomic.app.kotlin.ui.dayLabel
import place.atomic.app.kotlin.ui.messageTime
import place.atomic.app.kotlin.ui.otherDay
import java.time.ZoneId
import java.time.ZonedDateTime

class FormatChatTest {
    private val utc = ZoneId.of("UTC")
    private fun at(y: Int, m: Int, d: Int, h: Int = 12, min: Int = 5) = ZonedDateTime.of(y, m, d, h, min, 0, 0, utc).toInstant().toEpochMilli()
    private val now = at(2026, 10, 20)

    @Test
    fun daysAreLabelledForSeparators() {
        assertEquals("Today", dayLabel(at(2026, 10, 20, 1), now, utc))
        assertEquals("Yesterday", dayLabel(at(2026, 10, 19, 23), now, utc))
        assertEquals("3 March", dayLabel(at(2026, 3, 3), now, utc))
        assertEquals("3 March 2025", dayLabel(at(2025, 3, 3), now, utc))
    }

    @Test
    fun timesShowTheDateOnlyWhenNotToday() {
        assertEquals("14:05", messageTime(at(2026, 10, 20, 14), now, utc))
        assertEquals("3 Oct 14:05", messageTime(at(2026, 10, 3, 14), now, utc))
        assertEquals("3 Oct 2025 14:05", messageTime(at(2025, 10, 3, 14), now, utc))
    }

    @Test
    fun otherDayComparesCalendarDays() {
        assertFalse(otherDay(at(2026, 10, 20, 0, 1), at(2026, 10, 20, 23, 59), utc))
        assertTrue(otherDay(at(2026, 10, 20, 23, 59), at(2026, 10, 21, 0, 1), utc))
    }
}
