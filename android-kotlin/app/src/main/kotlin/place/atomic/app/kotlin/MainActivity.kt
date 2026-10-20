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
import android.content.Intent
import android.net.Uri
import place.atomic.app.kotlin.chat.AiChatModel
import place.atomic.app.kotlin.chat.AiChatViewModel
import place.atomic.app.kotlin.chat.ChatEntry
import place.atomic.app.kotlin.chat.ContextItem
import place.atomic.app.kotlin.chat.CoreChatBackend
import place.atomic.app.kotlin.chat.NativeKind
import place.atomic.app.kotlin.chat.ThreadKind
import place.atomic.app.kotlin.chat.ThreadModel
import place.atomic.app.kotlin.chat.ThreadViewModel
import place.atomic.app.kotlin.ui.AiChatActions
import place.atomic.app.kotlin.ui.AiChatScreen
import place.atomic.app.kotlin.ui.ChatListActions
import place.atomic.app.kotlin.ui.ThreadActions
import place.atomic.app.kotlin.ui.ThreadScreen
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.platform.LocalView
import androidx.compose.runtime.withFrameNanos
import android.view.MotionEvent
import place.atomic.app.kotlin.ui.AtomicTheme
import place.atomic.app.kotlin.ui.HomeScreen
import place.atomic.app.kotlin.ui.isWide

class MainActivity : ComponentActivity() {
    private val app: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // The first frame the window draws (Flutter's `first frame`).
        window.decorView.viewTreeObserver.addOnDrawListener(object : android.view.ViewTreeObserver.OnDrawListener {
            override fun onDraw() {
                Perf.once("first frame")
                window.decorView.post { window.decorView.viewTreeObserver.removeOnDrawListener(this) }
            }
        })
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

    /** Every finger lifted starts the "since tap" marks, as Flutter's `watchTaps` does. */
    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (ev.actionMasked == MotionEvent.ACTION_UP) Perf.tapped()
        return super.dispatchTouchEvent(ev)
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

    /** Home, or what was opened from it: a resource, a native chat, settings, the profile editor. */
    @Composable
    private fun Ready(onPair: () -> Unit) {
        val atomic = application as AtomicApp
        // Opened screens, the top one shown; back pops. A resource's chat opens on top of it.
        val stack = rememberSaveable(saver = StackSaver) { mutableStateListOf<Destination>() }
        var screen by rememberSaveable { mutableStateOf(Screen.Home) }
        var changed by remember { mutableStateOf<List<String>>(emptyList()) }
        val dark = isSystemInDarkTheme()
        LaunchedEffect(Unit) { atomic.startEmbed() }
        LaunchedEffect(dark) { atomic.embed.bridge.setColorScheme(dark) }
        // The page asks for a native screen (a meeting's chat room): open it when the app has one.
        DisposableEffect(Unit) {
            atomic.nativeOpener = { kind, subject, title ->
                val native = NativeKind.of(kind)
                if (native != null) {
                    val drive = (stack.lastOrNull { it.kind == null })?.drive.orEmpty()
                    runCatching { noteResourceOpened(drive, subject) }
                    stack.add(Destination(native.name, subject, title, drive))
                }
                native != null
            }
            onDispose { atomic.nativeOpener = null }
        }
        val openLink: (String) -> Unit = { link ->
            if (link.startsWith("did:")) {
                stack.add(Destination(null, link, "", stack.lastOrNull()?.drive.orEmpty()))
            } else {
                runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link))) }
            }
        }
        val top = stack.lastOrNull()
        val close: () -> Unit = {
            val closed = stack.removeAt(stack.lastIndex)
            // The native screen can have changed it (a renamed chat room, a new message): the page reads it again.
            if (closed.kind != null && closed.subject.isNotEmpty()) atomic.embed.bridge.changed(listOf(closed.subject))
        }
        when {
            top != null && top.kind == null -> ResourceScreen(
                OpenResource(top.subject, top.title, top.drive),
                atomic.embed,
                onClose = close,
            )
            top != null -> when (NativeKind.valueOf(top.kind!!)) {
                NativeKind.AiChat -> AiChatHost(top, onBack = close, onOpenLink = openLink)
                NativeKind.Conversation -> ThreadHost(top, ThreadKind.Conversation, onBack = close, onOpen = openLink)
                NativeKind.Room -> ThreadHost(top, ThreadKind.Room, onBack = close, onOpen = openLink)
            }
            screen == Screen.Home -> Home(
                onOpen = { row ->
                    // Drives are their own drive; rows from search or lists name theirs.
                    val drive = row.drive.ifEmpty { row.subject }
                    // A tap on a drive makes it the active one, as in Flutter.
                    if (row.className == "drive") app.activateDrive(row.subject)
                    runCatching { noteResourceOpened(drive, row.subject) }
                    stack.add(Destination(NativeKind.of(row.className)?.name, row.subject, row.title, drive))
                },
                onSettings = { screen = Screen.Settings },
                onNewChat = { stack.add(Destination(NativeKind.AiChat.name, "", "", "", newChatKey++)) },
            )
            else -> Settings(
                profile = screen == Screen.Profile,
                onScreen = { screen = it },
                onPair = onPair,
            )
        }
    }

    private var newChatKey = 0

    @Composable
    private fun AiChatHost(dest: Destination, onBack: () -> Unit, onOpenLink: (String) -> Unit) {
        val atomic = application as AtomicApp
        val vm: AiChatViewModel = viewModel(
            key = "ai-${dest.subject}-${dest.nonce}",
            factory = viewModelFactory {
                initializer {
                    AiChatViewModel { scope ->
                        AiChatModel(CoreChatBackend, atomic.aiProvider, dest.subject.ifEmpty { null }, dest.title, scope)
                    }
                }
            },
        )
        val model = vm.model
        val state by model.ui.collectAsStateWithLifecycle()
        BackHandler(onBack = onBack)
        AiChatScreen(
            state,
            AiChatActions(
                onBack = onBack,
                onSend = model::send,
                onStop = model::stop,
                onEnableAi = model::enableAi,
                onToggle = model::toggle,
                onAttach = model::attach,
                onOpenLink = onOpenLink,
                search = { q -> CoreChatBackend.search(q, 12).map { ContextItem(it.subject, it.title.ifEmpty { "Untitled" }, it.className) } },
                list = ChatListActions(
                    loadOlder = { model.loadOlder() },
                    loadNewer = { model.loadNewer() },
                    trimOldest = model::trimOldest,
                    trimNewest = model::trimNewest,
                    jumpToLatest = { model.jumpToLatest() },
                    maxHeld = model.maxHeld,
                ),
                onPainted = model::painted,
            ),
        )
    }

    @Composable
    private fun ThreadHost(dest: Destination, kind: ThreadKind, onBack: () -> Unit, onOpen: (String) -> Unit) {
        val vm: ThreadViewModel = viewModel(
            key = "thread-${dest.subject}",
            factory = viewModelFactory {
                initializer {
                    ThreadViewModel { scope ->
                        if (kind == ThreadKind.Room) {
                            ThreadModel(
                                CoreChatBackend.room(dest.subject), dest.title, scope,
                                renameWith = { CoreChatBackend.rename(dest.subject, it) },
                            )
                        } else {
                            ThreadModel(CoreChatBackend.conversation(dest.subject), dest.title, scope)
                        }
                    }
                }
            },
        )
        val model = vm.model
        val state by model.ui.collectAsStateWithLifecycle()
        BackHandler(onBack = onBack)
        ThreadScreen(
            if (kind == ThreadKind.Room) NativeKind.Room else NativeKind.Conversation,
            state,
            ThreadActions(
                onBack = onBack,
                onSend = model::send,
                list = ChatListActions(
                    loadOlder = { model.loadOlder() },
                    loadNewer = { model.loadNewer() },
                    trimOldest = model::trimOldest,
                    trimNewest = model::trimNewest,
                    jumpToLatest = { model.jumpToLatest() },
                    maxHeld = model.maxHeld,
                ),
                onOpenAbout = { subject, _ -> onOpen(subject) },
                onRename = model::rename,
                onUnsentTaken = model::unsentTaken,
                onPainted = model::painted,
            ),
        )
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
    private fun Home(onOpen: (RowItem) -> Unit, onSettings: () -> Unit, onNewChat: () -> Unit) {
        val vm: HomeViewModel = viewModel(factory = viewModelFactory { initializer { HomeViewModel(CoreHomeRepository()) } })
        val state by vm.state.collectAsStateWithLifecycle()
        // Flutter's `home painted`: the frame after every list is in.
        val loaded = state.sections.size == place.atomic.app.kotlin.data.Section.entries.size
        LaunchedEffect(loaded) {
            if (loaded) {
                withFrameNanos { }
                Perf.once("home painted")
            }
        }
        // Flutter's `search keystroke to results`: the frame after results for the typed text.
        LaunchedEffect(state.results) {
            if (state.results != null) {
                withFrameNanos { }
                Perf.sinceTyped("search keystroke to results")
            }
        }
        HomeScreen(
            state = state,
            onQuery = vm::setQuery,
            onShowAll = vm::showAll,
            onOpen = onOpen,
            onSettings = onSettings,
            onNewChat = onNewChat,
            wide = isWide(LocalConfiguration.current.screenWidthDp),
        )
    }
}

private enum class Screen { Home, Settings, Profile }

/**
 * A screen opened from Home: a resource drawn by the page ([kind] null) or a
 * native chat ([kind] a [NativeKind] name). [nonce] tells new chats apart.
 */
private data class Destination(val kind: String?, val subject: String, val title: String, val drive: String, val nonce: Int = 0)

/** Survives the activity being recreated: the stack as strings. */
private val StackSaver = listSaver<SnapshotStateList<Destination>, String>(
    save = { stack -> stack.flatMap { listOf(it.kind.orEmpty(), it.subject, it.title, it.drive, it.nonce.toString()) } },
    restore = { saved ->
        mutableStateListOf<Destination>().apply {
            saved.chunked(5).filter { it.size == 5 }.forEach { add(Destination(it[0].ifEmpty { null }, it[1], it[2], it[3], it[4].toIntOrNull() ?: 0)) }
        }
    },
)
