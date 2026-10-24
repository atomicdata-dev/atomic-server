package place.atomic.app.kotlin

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.down
import androidx.compose.ui.test.moveBy
import androidx.compose.ui.test.up
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.unit.dp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import place.atomic.app.kotlin.ui.AtomicTheme
import place.atomic.app.kotlin.ui.HOLD_DELAY_MS
import place.atomic.app.kotlin.ui.HoldItem
import place.atomic.app.kotlin.ui.HoldMenu

/** The one gesture of Home, Search and New: a tap, a hold of 150 ms or a swipe of 8 dp. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
class HoldMenuTest {
    @get:Rule
    val compose = createComposeRule()

    private var taps = 0
    private var picked: Int? = null

    private fun set(tapOpensMenu: Boolean = false) {
        compose.setContent {
            AtomicTheme {
                HoldMenu(listOf(HoldItem("One", 1), HoldItem("Two", 2)), { picked = it }, onTap = { taps++ }, tapOpensMenu = tapOpensMenu) {
                    Box(Modifier.size(48.dp).testTag("button"))
                }
            }
        }
    }

    @Test
    fun aQuickTapIsTheButtonsOwnAction() {
        set()
        compose.onNodeWithTag("button").performTouchInput { down(center); up() }
        compose.waitForIdle()
        assertEquals(1, taps)
        compose.onNodeWithText("One").assertDoesNotExist()
    }

    @Test
    fun aFingerHeldStillOpensTheMenuAfter150msAndItsLiftLeavesItOpen() {
        set()
        compose.onNodeWithTag("button").performTouchInput { down(center) }
        compose.mainClock.advanceTimeBy(HOLD_DELAY_MS + 50)
        compose.onNodeWithTag("button").performTouchInput { up() }
        compose.waitForIdle()
        compose.onNodeWithText("One").assertExists()
        assertEquals(0, taps)
        compose.onNodeWithText("Two").performClick()
        compose.waitForIdle()
        assertEquals(2, picked)
    }

    @Test
    fun aSwipeOfMoreThan8dpOpensTheMenuAtOnce() {
        set()
        compose.onNodeWithTag("button").performTouchInput { down(center); moveBy(Offset(0f, -40f)) }
        compose.waitForIdle()
        compose.onNodeWithText("One").assertExists()
        assertNull(picked)
        compose.onNodeWithTag("button").performTouchInput { up() }
    }

    @Test
    fun newOpensItsMenuOnATap() {
        set(tapOpensMenu = true)
        compose.onNodeWithTag("button").performTouchInput { down(center); up() }
        compose.waitForIdle()
        compose.onNodeWithText("One").assertExists()
        assertEquals(0, taps)
    }
}
