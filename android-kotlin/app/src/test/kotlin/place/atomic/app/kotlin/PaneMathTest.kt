package place.atomic.app.kotlin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import place.atomic.app.kotlin.ui.DragEnd
import place.atomic.app.kotlin.ui.MIN_LIST_DP
import place.atomic.app.kotlin.ui.OVERSHOOT_LIMIT_DP
import place.atomic.app.kotlin.ui.dragEnd
import place.atomic.app.kotlin.ui.isWide
import place.atomic.app.kotlin.ui.listPaneMax
import place.atomic.app.kotlin.ui.listPaneWidth
import place.atomic.app.kotlin.ui.rubberBand
import place.atomic.app.kotlin.ui.rubberBandInverse
import place.atomic.app.kotlin.ui.rubberBandSlope
import place.atomic.app.kotlin.ui.snapPaneWidth

class PaneMathTest {
    @Test
    fun theSplitStartsAt600dpSoATabletInPortraitHasIt() {
        assertFalse(isWide(599))
        assertTrue(isWide(600))
        // A Galaxy Tab S9+ in portrait is about 800 dp wide.
        assertTrue(isWide(800))
        assertFalse(isWide(411))
    }

    @Test
    fun theSidebarIsTwoFifthsOfTheRoomBetween320And400() {
        assertEquals(320f, listPaneWidth(700f), 0.01f)
        assertEquals(400f, listPaneWidth(1280f), 0.01f)
        assertEquals(380f, listPaneWidth(950f), 0.01f)
    }

    @Test
    fun aDraggedWidthIsKeptWithinBoundsAndThePagesKeep280() {
        assertEquals(304f, listPaneWidth(1000f, 100f), 0.01f)
        assertEquals(520f, listPaneWidth(1280f, 900f), 0.01f)
        assertEquals(1000f - 280f, listPaneWidth(1000f, 900f), 0.01f)
        assertEquals(listPaneMax(700f), 420f, 0.01f)
    }

    @Test
    fun theRubberBandIsOneToOneInsideAndBoundedOutside() {
        assertEquals(350f, rubberBand(350f, 0f, 520f), 0.001f)
        assertTrue(rubberBand(560f, 0f, 520f) in 520f..520f + OVERSHOOT_LIMIT_DP)
        assertTrue(rubberBand(5000f, 0f, 520f) <= 520f + OVERSHOOT_LIMIT_DP)
        // Pulling to the left past zero stretches too, up to the limit.
        assertTrue(rubberBand(-300f, 0f, 520f) >= -OVERSHOOT_LIMIT_DP)
        // The band is the identity's tangent at the bound.
        assertEquals(1f, rubberBandSlope(520f, 0f, 520f), 0.001f)
        assertTrue(rubberBandSlope(700f, 0f, 520f) < 0.2f)
    }

    @Test
    fun theInverseFindsTheFingerThatShowsAWidth() {
        for (raw in listOf(100f, 520f, 540f, 600f, 900f)) {
            assertEquals(raw, rubberBandInverse(rubberBand(raw, 0f, 520f), 0f, 520f), raw * 0.01f)
        }
    }

    @Test
    fun letGoOfTheDividerSettlesFoldsOrOpens() {
        // Unfolded.
        assertEquals(DragEnd.Settle, dragEnd(false, 400f, 400f, 380f, 0f))
        assertEquals(DragEnd.Fold, dragEnd(false, 100f, 100f, 380f, 0f))
        assertEquals(DragEnd.Fold, dragEnd(false, 300f, 300f, 380f, -400f))
        assertEquals(DragEnd.Settle, dragEnd(false, 300f, 300f, 380f, -100f))
        // Just under 60% of the narrowest width still folds, just over does not.
        assertEquals(DragEnd.Fold, dragEnd(false, 180f, MIN_LIST_DP * 0.59f, 380f, 0f))
        assertEquals(DragEnd.Settle, dragEnd(false, 190f, MIN_LIST_DP * 0.61f, 380f, 0f))
        // Folded, pulled out from the edge.
        assertEquals(DragEnd.Open, dragEnd(true, 200f, 200f, 380f, 0f))
        assertEquals(DragEnd.BackToFolded, dragEnd(true, 50f, 50f, 380f, 0f))
        assertEquals(DragEnd.Open, dragEnd(true, 50f, 50f, 380f, 500f))
    }

    @Test
    fun theWidthSnapsToAWholePixel() {
        // width + the 1 dp divider lands on a physical pixel.
        val density = 2.625f
        val snapped = snapPaneWidth(380.3f, density)
        assertEquals(0f, ((snapped + 1) * density) % 1f, 0.001f)
        assertEquals(0f, snapPaneWidth(0f, density), 0f)
    }
}
