package place.atomic.app.kotlin

import androidx.compose.runtime.Composable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.captureRoboImage
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import place.atomic.app.kotlin.core.PeerRow
import place.atomic.app.kotlin.core.ServerInfo
import place.atomic.app.kotlin.core.StoreRecovery
import place.atomic.app.kotlin.data.PairState
import place.atomic.app.kotlin.data.ServerRow
import place.atomic.app.kotlin.data.SettingsState
import place.atomic.app.kotlin.core.DriveUsage
import place.atomic.app.kotlin.ui.AtomicTheme
import place.atomic.app.kotlin.ui.EditProfileScreen
import place.atomic.app.kotlin.ui.LoginActions
import place.atomic.app.kotlin.ui.LoginScreen
import place.atomic.app.kotlin.ui.PairScreen
import place.atomic.app.kotlin.ui.SettingsActions
import place.atomic.app.kotlin.ui.SettingsScreen
import place.atomic.app.kotlin.ui.StartupFailedScreen
import place.atomic.app.kotlin.ui.StoreRecoveryScreen
import java.io.File

/**
 * Screenshots of the sign-in, settings, pairing, profile and recovery screens
 * with fake data, into `$SHOTS_DIR` (never the repo):
 * `SHOTS_DIR=/tmp/claude-0/kotlin-shots ./gradlew testDebugUnitTest -Proborazzi.test.record=true`.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
class AccountScreenshotTest {
    @get:Rule
    val compose = createComposeRule()
    private val dir = File(System.getenv("SHOTS_DIR") ?: "build/shots")

    private fun shot(name: String, dark: Boolean = false, content: @Composable () -> Unit) {
        compose.setContent { AtomicTheme(dark) { content() } }
        compose.onRoot().captureRoboImage(File(dir, "$name.png").path)
    }

    private val login = LoginActions({}, {}, {}, {}, {}, { null }, {})
    private val id = "ab".repeat(32)

    @Test fun welcome() = shot("login-welcome") { LoginScreen(AppState.Login, LoginUi(), login) }
    @Test fun welcomeDark() = shot("login-welcome-dark", dark = true) { LoginScreen(AppState.Login, LoginUi(), login) }
    @Test fun secret() = shot("login-secret") { LoginScreen(AppState.ShowSecret("kQ7x-secret-0123456789abcdef"), LoginUi(), login) }
    @Test fun needsSync() = shot("login-needs-sync") {
        LoginScreen(AppState.NeedsSync, LoginUi(error = "https://node.example: HTTP 404\nNo peers online. Open the other device or pair with QR."), login)
    }

    private val settings = SettingsState(
        loading = false,
        profile = place.atomic.app.kotlin.core.OwnProfile("did:ad:agent:" + "x".repeat(40), "Joep", "", null, null),
        deviceName = "Pixel 9",
        peerId = id,
        serverConnected = true,
        drives = fakeDrives,
        activeDrive = "did:ad:home",
        servers = listOf(
            ServerRow("https://node1.example.org", true, ServerInfo(null, "0.41.0", false, null), DriveUsage("Joep's Drive", 128u, 2_000_000u, 600_000u)),
            ServerRow("http://192.168.1.4:9883", false),
        ),
        peers = listOf(PeerRow(id, "Laptop", NOW.toULong(), true), PeerRow("cd".repeat(32), "", null, false)),
    )
    private val noActions = SettingsActions({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, { null }, {})

    @Test fun settings() = shot("settings") { SettingsScreen(settings, noActions) }
    @Test fun settingsDark() = shot("settings-dark", dark = true) { SettingsScreen(settings, noActions) }
    @Test fun settingsEmpty() = shot("settings-empty") { SettingsScreen(settings.copy(servers = emptyList(), peers = emptyList(), serverConnected = false, peerId = null), noActions) }
    @Test fun profile() = shot("profile") { EditProfileScreen(settings.profile!!, { _, _ -> }, {}) }

    @Test fun pairCode() = shot("pair-code") {
        PairScreen(PairState.ShowCode("atomic:node:$id:Pixel", "Pixel 9"), { true }, {}, {}, scanner = {})
    }
    @Test fun pairDone() = shot("pair-done") { PairScreen(PairState.Done("Laptop", "Synced with Laptop — sent 1, received 2"), { true }, {}, {}) }
    @Test fun pairFailed() = shot("pair-failed") { PairScreen(PairState.Failed("Sync timed out after 25s. Keep both devices open on Wi‑Fi and try again."), { true }, {}, {}) }

    @Test fun recovery() = shot("store-recovery") { StoreRecoveryScreen(StoreRecovery("/data/atomic.redb.corrupt-1", "redb could not read the file", true), {}) }
    @Test fun startupFailed() = shot("startup-failed") { StartupFailedScreen("Call open_store() first.", {}) }
}
