package place.atomic.app.kotlin

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.unit.dp
import com.github.takahirom.roborazzi.captureRoboImage
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import place.atomic.app.kotlin.core.SearchHit
import place.atomic.app.kotlin.data.HomeLayout
import place.atomic.app.kotlin.data.HomeState
import place.atomic.app.kotlin.data.Identity
import place.atomic.app.kotlin.data.RowItem
import place.atomic.app.kotlin.data.SearchItem
import place.atomic.app.kotlin.data.SearchState
import place.atomic.app.kotlin.data.Section
import place.atomic.app.kotlin.shell.ToastController
import place.atomic.app.kotlin.ui.ActivityPane
import place.atomic.app.kotlin.ui.AtomicTheme
import place.atomic.app.kotlin.ui.BarActions
import place.atomic.app.kotlin.ui.BarPage
import place.atomic.app.kotlin.ui.BottomBar
import place.atomic.app.kotlin.ui.HoldItem
import place.atomic.app.kotlin.ui.HoldMenu
import place.atomic.app.kotlin.ui.HomeActions
import place.atomic.app.kotlin.ui.HomeScreen
import place.atomic.app.kotlin.ui.ListPage
import place.atomic.app.kotlin.ui.SearchActions
import place.atomic.app.kotlin.ui.SearchPanel
import place.atomic.app.kotlin.ui.SectionsContent
import place.atomic.app.kotlin.ui.SplitPanes
import place.atomic.app.kotlin.ui.ToastHost
import place.atomic.app.kotlin.ui.newItems
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
    private val identity = Identity("Joep", "🦊", null)
    private val noActions = HomeActions({}, {}, {}, {}, {})
    private val noBar = BarActions({}, {}, {}, {}, {}, {}, {}, {})

    private fun shot(name: String, dark: Boolean, content: @Composable () -> Unit) {
        compose.setContent { AtomicTheme(dark) { content() } }
        compose.onRoot().captureRoboImage(File(dir, "$name.png").path)
    }

    @Composable
    private fun Phone(state: HomeState, current: BarPage = BarPage.Home) = Column(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f)) { HomeScreen(state, noActions) }
        BottomBar(false, current, state.layout.visible, fakeDrives, identity, noBar)
    }

    @Composable
    private fun Tablet(state: HomeState, pane: @Composable () -> Unit = {
        ActivityPane(state.sections[Section.Activity], state.showMine, {}, {})
    }) = SplitPanes(
        folded = false, onFolded = {}, listWidth = null, onListWidth = {},
        list = { HomeScreen(state, noActions, split = true) },
        bar = { BottomBar(true, BarPage.Home, state.layout.visible, fakeDrives, identity, noBar) },
        detail = pane,
    )

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneLight() = shot("home-phone-light", false) { Phone(fakeHomeState()) }

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneDark() = shot("home-phone-dark", true) { Phone(fakeHomeState()) }

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneFolded() = shot("home-phone-folded", false) {
        Phone(fakeHomeState().copy(layout = HomeLayout().toggleCollapsed(Section.Drives).toggleCollapsed(Section.Activity)))
    }

    @Test
    @Config(qualifiers = "w1280dp-h800dp-land-xhdpi")
    fun tabletLandscapeLight() = shot("home-tablet-light", false) { Tablet(fakeHomeState()) }

    @Test
    @Config(qualifiers = "w1280dp-h800dp-land-xhdpi")
    fun tabletLandscapeDark() = shot("home-tablet-dark", true) { Tablet(fakeHomeState(showMine = true)) }

    /** A Galaxy Tab S9+ in portrait: about 800 dp wide, which is a split. */
    @Test
    @Config(qualifiers = "w800dp-h1280dp-port-xhdpi")
    fun tabletPortraitLight() = shot("home-tablet-portrait-light", false) { Tablet(fakeHomeState()) }

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneAllChats() = shot("home-phone-all-chats", false) {
        val chats = (1..40).map { RowItem("c$it", "Chat number $it", className = "aichat", at = NOW - it * 3_000_000L, trailing = "${it}h") }
        ListPage(Section.Chats, fakeHomeState().copy(showAll = Section.Chats, allChats = place.atomic.app.kotlin.data.AllChats(chats, done = false)), {}, {}, {}, now = NOW)
    }

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneHoldMenuNew() = shot("bar-phone-hold-new", false) {
        Column(Modifier.fillMaxSize()) {
            Box(Modifier.weight(1f))
            Box(Modifier.padding(start = 150.dp)) { HoldMenu(newItems, {}, startOpen = true) { Box(Modifier.padding(16.dp)) { androidx.compose.material3.Text("+") } } }
        }
    }

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneSections() = shot("home-phone-sections", false) {
        Box(Modifier.fillMaxSize(), Alignment.BottomCenter) {
            Surface(shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp), color = MaterialTheme.colorScheme.surface) {
                SectionsContent(HomeLayout().setHidden(Section.Messages, true), {}, {})
            }
        }
    }

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneSearch() {
        val hits = listOf(
            SearchItem("did:ad:res1", "Quarterly planning", "DocumentV2", "did:ad:home", shown = "did:ad:home"),
            SearchItem("did:ad:ontola", "Ontola", "Drive", "did:ad:ontola", shown = "did:ad:ontola"),
            SearchItem("did:ad:res9", "Plan the offsite", "AiChat", "did:ad:ontola", shown = "did:ad:ontola"),
        )
        val state = SearchState(query = "pla", hits = hits, hitsFor = "pla", drives = fakeDrives)
        shot("search-phone", false) { SearchPanel(state, SearchActions({}, {}, {}, {}, {}), palette = false, initialText = "pla") }
    }

    @Test
    @Config(qualifiers = "w1280dp-h800dp-land-xhdpi")
    fun tabletSearchCard() {
        val hits = listOf(
            SearchItem("did:ad:res1", "Quarterly planning", "DocumentV2", "did:ad:home", shown = "did:ad:home"),
            SearchItem("did:ad:ontola", "Ontola", "Drive", "did:ad:ontola", shown = "did:ad:ontola"),
            SearchItem("did:ad:res9", "Plan the offsite", "AiChat", "did:ad:ontola", shown = "did:ad:ontola"),
        )
        val state = SearchState(query = "pla", hits = hits, hitsFor = "pla", drives = fakeDrives)
        shot("search-tablet-card", false) {
            Box { Tablet(fakeHomeState()) }
            Box(Modifier.fillMaxSize().padding(top = 72.dp), Alignment.TopCenter) {
                Surface(Modifier.widthIn(max = 640.dp), shape = RoundedCornerShape(16.dp), shadowElevation = 12.dp) {
                    SearchPanel(state, SearchActions({}, {}, {}, {}, {}), palette = true, initialText = "pla")
                }
            }
        }
    }

    @Test
    @Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
    fun phoneToast() {
        val toasts = ToastController()
        toasts.show("sync:error", "Could not look for devices: timed out", "Retry")
        shot("toast-phone", false) { Box { Phone(fakeHomeState()) }; ToastHost(toasts) }
    }

    @Test
    @Config(qualifiers = "w1280dp-h800dp-land-xhdpi")
    fun tabletToast() {
        val toasts = ToastController()
        toasts.show("sync:error", "Could not look for devices: timed out", "Retry")
        shot("toast-tablet", false) { Box { Tablet(fakeHomeState()) }; ToastHost(toasts) }
    }
}
