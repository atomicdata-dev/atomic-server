package place.atomic.app.kotlin

import org.junit.Assert.assertEquals
import org.junit.Test
import place.atomic.app.kotlin.data.RowItem
import place.atomic.app.kotlin.ui.groupChatsByAge
import place.atomic.app.kotlin.ui.revealDelta
import java.time.ZoneOffset

class HomeListLogicTest {
    private val day = 24 * 60 * 60 * 1000L
    private val now = 1_760_000_000_000L
    private fun chat(i: Int, ago: Long) = RowItem("c$i", "Chat $i", className = "aichat", at = if (ago < 0) 0 else now - ago)

    @Test
    fun chatsAreGroupedByAgeAndOnlyAgesWithChatsGetAHeading() {
        val rows = listOf(chat(1, 1_000), chat(2, day), chat(3, 3 * day), chat(4, 20 * day), chat(5, 90 * day), chat(6, -1))
        val groups = groupChatsByAge(rows, now, ZoneOffset.UTC)
        assertEquals(listOf("Today", "Yesterday", "This week", "This month", "Earlier"), groups.map { it.first })
        assertEquals(listOf("c5", "c6"), groups.last().second.map { it.subject })
        assertEquals(emptyList<String>(), groupChatsByAge(emptyList(), now).map { it.first })
        assertEquals(listOf("Today"), groupChatsByAge(listOf(chat(1, 10)), now, ZoneOffset.UTC).map { it.first })
    }

    @Test
    fun revealDoesNothingWhenTheSectionFitsAlready() {
        assertEquals(0f, revealDelta(headingTop = 100f, height = 300f, viewport = 800f), 0f)
    }

    @Test
    fun revealScrollsJustEnoughToShowTheEndOfASectionThatFits() {
        assertEquals(150f, revealDelta(headingTop = 650f, height = 300f, viewport = 800f), 0f)
    }

    @Test
    fun revealBringsTheHeadingToTheTopWhenTheSectionIsTallerOrAboveTheView() {
        assertEquals(120f, revealDelta(headingTop = 120f, height = 900f, viewport = 800f), 0f)
        assertEquals(-40f, revealDelta(headingTop = -40f, height = 200f, viewport = 800f), 0f)
    }
}
