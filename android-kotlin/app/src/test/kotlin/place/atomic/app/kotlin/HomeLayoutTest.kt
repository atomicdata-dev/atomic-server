package place.atomic.app.kotlin

import org.junit.Assert.assertEquals
import org.junit.Test
import place.atomic.app.kotlin.data.HomeLayout
import place.atomic.app.kotlin.data.Section

class HomeLayoutTest {
    @Test
    fun theDefaultShowsEveryoneInOrderAndNothingIsFolded() {
        val layout = HomeLayout()
        assertEquals(listOf(Section.Drives, Section.Activity, Section.Chats, Section.Favorites, Section.Messages), layout.visible)
        assertEquals(emptySet<Section>(), layout.collapsed)
    }

    @Test
    fun hiddenSectionsKeepTheirPlaceAndComeBackThere() {
        val hidden = HomeLayout().setHidden(Section.Activity, true)
        assertEquals(listOf(Section.Drives, Section.Chats, Section.Favorites, Section.Messages), hidden.visible)
        assertEquals(Section.entries, hidden.order)
        assertEquals(HomeLayout().visible, hidden.setHidden(Section.Activity, false).visible)
    }

    @Test
    fun reorderMovesTheRowToTheIndexItEndsAt() {
        val moved = HomeLayout().reorder(0, 2)
        assertEquals(listOf(Section.Activity, Section.Chats, Section.Drives, Section.Favorites, Section.Messages), moved.order)
        assertEquals(moved, moved.reorder(2, 2))
        assertEquals(moved, moved.reorder(-1, 2))
        assertEquals(moved, moved.reorder(0, 9))
    }

    @Test
    fun resetPutsTheDefaultBackButKeepsTheFolds() {
        val changed = HomeLayout().reorder(0, 4).setHidden(Section.Chats, true).toggleCollapsed(Section.Drives)
        val reset = changed.reset()
        assertEquals(Section.entries, reset.order)
        assertEquals(emptySet<Section>(), reset.hidden)
        assertEquals(setOf(Section.Drives), reset.collapsed)
    }

    @Test
    fun savedAndLoadedAgain() {
        val kv = MapKeyValue()
        val layout = HomeLayout().reorder(4, 0).setHidden(Section.Favorites, true).toggleCollapsed(Section.Chats)
        layout.save(kv)
        assertEquals(layout, HomeLayout.load(kv))
        assertEquals(HomeLayout(), HomeLayout.load(MapKeyValue()))
    }

    @Test
    fun unknownNamesAreDroppedAndAMissingSectionComesInAtItsDefaultPlace() {
        // An older build stored Recents, and knew no Activity.
        val layout = HomeLayout.fromNames(
            order = listOf("Messages", "Recents", "Drives", "Chats", "Favorites"),
            hidden = listOf("Recents", "Favorites"),
            collapsed = listOf("Recents"),
        )
        assertEquals(listOf(Section.Messages, Section.Drives, Section.Activity, Section.Chats, Section.Favorites), layout.order)
        assertEquals(setOf(Section.Favorites), layout.hidden)
        assertEquals(emptySet<Section>(), layout.collapsed)
    }
}
