package place.atomic.app.kotlin.shell

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import place.atomic.app.kotlin.AppViewModel
import place.atomic.app.kotlin.AtomicApp
import place.atomic.app.kotlin.chat.AiChatModel
import place.atomic.app.kotlin.chat.AiChatViewModel
import place.atomic.app.kotlin.chat.ContextItem
import place.atomic.app.kotlin.chat.CoreChatBackend
import place.atomic.app.kotlin.chat.NativeKind
import place.atomic.app.kotlin.chat.ThreadKind
import place.atomic.app.kotlin.chat.ThreadModel
import place.atomic.app.kotlin.chat.ThreadViewModel
import place.atomic.app.kotlin.data.CoreBackend
import place.atomic.app.kotlin.ui.AiChatActions
import place.atomic.app.kotlin.ui.AiChatScreen
import place.atomic.app.kotlin.ui.ChatListActions
import place.atomic.app.kotlin.ui.EditProfileScreen
import place.atomic.app.kotlin.ui.SettingsActions
import place.atomic.app.kotlin.ui.SettingsScreen
import place.atomic.app.kotlin.ui.ThreadActions
import place.atomic.app.kotlin.ui.ThreadScreen

/** The native screens the shell shows in its page area, one composable each. */

@Composable
fun AiChatHost(atomic: AtomicApp, dest: Destination, onBack: () -> Unit, onOpenLink: (String) -> Unit) {
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
fun ThreadHost(dest: Destination, kind: ThreadKind, onBack: () -> Unit, onOpen: (String) -> Unit) {
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

/** Settings, or (with [profile]) the profile editor on top of it. */
@Composable
fun SettingsHost(app: AppViewModel, profile: Boolean, onEditProfile: () -> Unit, onBack: () -> Unit, onPair: () -> Unit) {
    val model = app.settings
    val state by model.state.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { model.load() }
    // Devices coming and going, while this screen is up.
    LaunchedEffect(Unit) { CoreBackend.syncEvents().collect { model.refreshLive() } }
    BackHandler(onBack = onBack)
    val loaded = state.profile
    if (profile && loaded != null) {
        EditProfileScreen(loaded, image = state.profileImage, save = model::saveProfile, onDone = { model.load(); onBack() })
        return
    }
    SettingsScreen(
        state,
        SettingsActions(
            onBack = onBack,
            onEditProfile = onEditProfile,
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
