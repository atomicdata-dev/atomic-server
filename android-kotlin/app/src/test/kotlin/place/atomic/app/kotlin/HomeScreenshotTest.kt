package place.atomic.app.kotlin

import androidx.compose.runtime.Composable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.RobolectricDeviceQualifiers
import com.github.takahirom.roborazzi.captureRoboImage
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import place.atomic.app.kotlin.data.HomeState
import place.atomic.app.kotlin.data.Section
import place.atomic.app.kotlin.data.toItem
import place.atomic.app.kotlin.core.SearchHit
import place.atomic.app.kotlin.ui.AtomicTheme
import place.atomic.app.kotlin.ui.HomeScreen
import java.io.File

/**
 * Screenshots of the real Home composables with fake data (no emulator in the
 * cloud container). Written to `$SHOTS_DIR` (default `build/shots`), never into
 * the repo: `SHOTS_DIR=/tmp/claude-0/kotlin-shots ./gradlew testDebugUnitTest
 * -Proborazzi.test.record=true`.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class HomeScreenshotTest {
    @get:Rule
    val compose = createComposeRule()

    private val dir = File(System.getenv("SHOTS_DIR") ?: "build/shots")

    private fun shot(name: String, dark: Boolean, wide: Boolean = false, state: HomeState = fakeHomeState()) {
        compose.setContent { Screen(state, dark, wide) }
        compose.onRoot().captureRoboImage(File(dir, "$name.png").path)
    }

    @Composable
    private fun Screen(state: HomeState, dark: Boolean, wide: Boolean) = AtomicTheme(dark) {
        HomeScreen(state, onQuery = {}, onShowAll = {}, onOpen = {}, onSettings = {}, wide = wide)
    }

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneLight() = shot("home-phone-light", dark = false)

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneDark() = shot("home-phone-dark", dark = true)

    @Test
    @Config(qualifiers = "w1280dp-h800dp-land-xhdpi")
    fun tabletLight() = shot("home-tablet-light", dark = false, wide = true)

    @Test
    @Config(qualifiers = "w1280dp-h800dp-land-xhdpi")
    fun tabletDark() = shot("home-tablet-dark", dark = true, wide = true)

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneShowAll() = shot("home-phone-show-all-recents", dark = false, state = fakeHomeState().copy(showAll = Section.Recents))

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneSearch() {
        val hits = listOf(
            SearchHit("did:ad:res1", "Quarterly planning", "DocumentV2", null, "did:ad:home", 3.0),
            SearchHit("did:ad:res9", "Plan the offsite", "AiChat", null, "did:ad:ontola", 2.0),
        )
        val state = fakeHomeState().copy(query = "plan", results = hits.map { it.toItem(mapOf("did:ad:home" to "Joep's Drive", "did:ad:ontola" to "Ontola")) })
        shot("home-phone-search", dark = false, state = state)
    }
}
