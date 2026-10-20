package place.atomic.app.kotlin

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import place.atomic.app.kotlin.data.CoreBackend
import place.atomic.app.kotlin.data.PairModel
import place.atomic.app.kotlin.ui.EditProfileScreen
import place.atomic.app.kotlin.ui.LoginActions
import place.atomic.app.kotlin.ui.LoginScreen
import place.atomic.app.kotlin.ui.PairScreen
import place.atomic.app.kotlin.ui.SettingsActions
import place.atomic.app.kotlin.ui.SettingsScreen
import place.atomic.app.kotlin.ui.StartupFailedScreen
import place.atomic.app.kotlin.ui.StoreOpenFailedScreen
import place.atomic.app.kotlin.ui.StoreRecoveryScreen
import place.atomic.app.kotlin.core.noteResourceOpened
import place.atomic.app.kotlin.data.RowItem
import place.atomic.app.kotlin.ui.OpenResource
import place.atomic.app.kotlin.ui.ResourceScreen
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import place.atomic.app.kotlin.data.CoreHomeRepository
import place.atomic.app.kotlin.data.HomeViewModel
import place.atomic.app.kotlin.ui.AtomicTheme
import place.atomic.app.kotlin.ui.HomeScreen
import place.atomic.app.kotlin.ui.isWide

class MainActivity : ComponentActivity() {
    private val app: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AtomicTheme {
                val state by app.state.collectAsStateWithLifecycle()
                val ui by app.ui.collectAsStateWithLifecycle()
                // Pairing can start from the sign-in screens and from settings.
                var pairing by rememberSaveable { mutableStateOf<String?>(null) }
                var pairRequested by rememberSaveable { mutableStateOf(false) }
                if (pairRequested) {
                    Pairing(initialNodeId = pairing, onClose = {
                        pairRequested = false
                        pairing = null
                        if (state == AppState.NeedsSync) app.pairedCheck()
                    })
                    return@AtomicTheme
                }
                when (val s = state) {
                    AppState.Opening -> Box(Modifier.fillMaxSize(), Alignment.Center) { CircularProgressIndicator() }
                    is AppState.StoreFailed -> StoreOpenFailedScreen(s.message, app::retryStart)
                    is AppState.StartupFailed -> StartupFailedScreen(s.message, app::retryStart)
                    is AppState.Recovery -> StoreRecoveryScreen(s.notice, app::continueAfterRecovery)
                    AppState.Login, is AppState.ShowSecret, AppState.NeedsSync -> LoginScreen(
                        state = s,
                        ui = ui,
                        actions = LoginActions(
                            onCreate = app::createAccount,
                            onSignIn = app::signIn,
                            onSecretSaved = app::secretSaved,
                            onFindDrive = app::findDrive,
                            onPair = { nodeId -> pairing = nodeId; pairRequested = true },
                            nodeIdOf = { CoreBackend.parseCode(it)?.nodeId },
                            onBack = app::backToLogin,
                        ),
                    )
                    AppState.Ready -> Ready(onPair = { pairing = null; pairRequested = true })
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        // Android may kill a backgrounded app without warning.
        app.flush()
    }

    @Composable
    private fun Pairing(initialNodeId: String?, onClose: () -> Unit) {
        val atomic = application as AtomicApp
        val scope = rememberCoroutineScope()
        val model = remember { PairModel(CoreBackend, atomic.session, scope) }
        val state by model.state.collectAsStateWithLifecycle()
        LaunchedEffect(Unit) { model.start(initialNodeId) }
        BackHandler(onBack = onClose)
        PairScreen(state, onCode = model::onCode, onRetry = model::retry, onClose = onClose)
    }

    /** Home, or what was opened from it: a resource, settings, the profile editor. */
    @Composable
    private fun Ready(onPair: () -> Unit) {
        val atomic = application as AtomicApp
        var open by rememberSaveable(stateSaver = OpenResourceSaver) { mutableStateOf<OpenResource?>(null) }
        var screen by rememberSaveable { mutableStateOf(Screen.Home) }
        val dark = isSystemInDarkTheme()
        LaunchedEffect(Unit) { atomic.startEmbed() }
        LaunchedEffect(dark) { atomic.embed.bridge.setColorScheme(dark) }
        val target = open
        when {
            target != null -> ResourceScreen(target, atomic.embed, onClose = { open = null })
            screen == Screen.Home -> Home(
                onOpen = { row ->
                    // Drives are their own drive; rows from search or lists name theirs.
                    val drive = row.drive.ifEmpty { row.subject }
                    // A tap on a drive makes it the active one, as in Flutter.
                    if (row.className == "drive") app.activateDrive(row.subject)
                    runCatching { noteResourceOpened(drive, row.subject) }
                    open = OpenResource(row.subject, row.title, drive)
                },
                onSettings = { screen = Screen.Settings },
            )
            else -> Settings(
                profile = screen == Screen.Profile,
                onScreen = { screen = it },
                onPair = onPair,
            )
        }
    }

    @Composable
    private fun Settings(profile: Boolean, onScreen: (Screen) -> Unit, onPair: () -> Unit) {
        val model = app.settings
        val state by model.state.collectAsStateWithLifecycle()
        LaunchedEffect(Unit) { model.load() }
        // Devices coming and going, while this screen is up.
        LaunchedEffect(Unit) { CoreBackend.syncEvents().collect { model.refreshLive() } }
        val back = { onScreen(if (profile) Screen.Settings else Screen.Home) }
        BackHandler(onBack = back)
        val loaded = state.profile
        if (profile && loaded != null) {
            EditProfileScreen(loaded, save = model::saveProfile, onDone = { model.load(); back() })
            return
        }
        SettingsScreen(
            state,
            SettingsActions(
                onBack = { onScreen(Screen.Home) },
                onEditProfile = { onScreen(Screen.Profile) },
                onRename = model::rename,
                onNewWorkspace = model::newWorkspace,
                onSwitchDrive = model::switchDrive,
                onSwitchServer = model::switchServer,
                onAddServer = model::addServer,
                onRemoveServer = model::removeServer,
                onPush = model::pushWorkspace,
                onRemovePeer = model::removePeer,
                onPair = onPair,
                onMessageShown = model::messageShown,
                secret = model::secret,
                onSignOut = app::signOut,
            ),
        )
    }

    @Composable
    private fun Home(onOpen: (RowItem) -> Unit, onSettings: () -> Unit) {
        val vm: HomeViewModel = viewModel(factory = viewModelFactory { initializer { HomeViewModel(CoreHomeRepository()) } })
        val state by vm.state.collectAsStateWithLifecycle()
        HomeScreen(
            state = state,
            onQuery = vm::setQuery,
            onShowAll = vm::showAll,
            onOpen = onOpen,
            onSettings = onSettings,
            wide = isWide(LocalConfiguration.current.screenWidthDp),
        )
    }
}

private enum class Screen { Home, Settings, Profile }

/** Survives the activity being recreated: the opened resource as three strings. */
private val OpenResourceSaver = listSaver<OpenResource?, String>(
    save = { it?.let { r -> listOf(r.subject, r.title, r.drive) } ?: emptyList() },
    restore = { if (it.size == 3) OpenResource(it[0], it[1], it[2]) else null },
)
