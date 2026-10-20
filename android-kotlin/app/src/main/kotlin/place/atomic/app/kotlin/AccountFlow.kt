package place.atomic.app.kotlin

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import place.atomic.app.kotlin.core.ResumeStatus
import place.atomic.app.kotlin.core.StoreRecovery
import place.atomic.app.kotlin.data.Backend
import place.atomic.app.kotlin.session.SessionStore

sealed interface AppState {
    data object Opening : AppState

    /** The local data could not be opened at all (Flutter's `StoreOpenFailedScreen`). */
    data class StoreFailed(val message: String) : AppState

    /** Anything else that stopped start-up (Flutter's `StartupFailedScreen`). */
    data class StartupFailed(val message: String) : AppState

    /** A damaged store was set aside; said once before anything else. */
    data class Recovery(val notice: StoreRecovery) : AppState

    /** No agent on this device (or a secret that no longer works): the sign-in screens. */
    data object Login : AppState

    /** An agent was just made: its secret is shown once to save. */
    data class ShowSecret(val secret: String) : AppState

    /** Signed in, but the drive is not on this device yet. */
    data object NeedsSync : AppState
    data object Ready : AppState
}

/** What the login screens show beside the step: busy, an error, what the sync step is doing. */
data class LoginUi(val busy: Boolean = false, val error: String? = null, val status: String? = null)

/**
 * Start-up and sign-in, the logic of Flutter's `LoginScreen` apart from its
 * widgets. The store keeps the active drive but not the agent, so a restarted
 * process signs in again from the secret in [SessionStore] before anything
 * else; skipping that made every start a first run with a new agent.
 */
class AccountFlow(
    private val backend: Backend,
    private val session: SessionStore,
    private val openStore: suspend () -> Unit,
    private val recovery: () -> StoreRecovery?,
) {
    private val _state = MutableStateFlow<AppState>(AppState.Opening)
    val state: StateFlow<AppState> = _state.asStateFlow()
    private val _ui = MutableStateFlow(LoginUi())
    val ui: StateFlow<LoginUi> = _ui.asStateFlow()

    /** What the last drive lookup did, for the error text. */
    private var lookup = ""

    suspend fun start() {
        _state.value = AppState.Opening
        try {
            openStore()
        } catch (e: Exception) {
            _state.value = AppState.StoreFailed(errorText(e))
            return
        }
        recovery()?.let {
            _state.value = AppState.Recovery(it)
            return
        }
        proceed()
    }

    /** After the recovery notice (or without one): sign in again, or ask who this is. */
    suspend fun proceed() {
        _state.value = try {
            startSignedIn()
        } catch (e: Exception) {
            AppState.StartupFailed(errorText(e))
        }
    }

    private suspend fun startSignedIn(): AppState {
        if (backend.agent() != null) return AppState.Ready // the process is alive: the activity was recreated
        val saved = session.load() ?: return AppState.Login
        val status = try {
            backend.resume(saved.serverUrl, saved.secret, saved.drive)
        } catch (e: Exception) {
            // A secret that no longer loads: the sign-in screen, not a dead end.
            _ui.value = LoginUi(error = signInError(e))
            return AppState.Login
        }
        backend.activeDrive()?.let(session::saveDrive)
        return if (status == ResumeStatus.READY && backend.driveReady()) AppState.Ready else AppState.NeedsSync
    }

    suspend fun createAccount(name: String) {
        val trimmed = name.trim()
        if (trimmed.isEmpty()) {
            _ui.value = LoginUi(error = "Enter a name")
            return
        }
        _ui.value = LoginUi(busy = true)
        try {
            val made = backend.createAccount(trimmed)
            // No server asked for: a new identity has no data anywhere to go and find.
            session.save(made.agent.secret, drive = made.driveSubject)
            _ui.value = LoginUi()
            _state.value = AppState.ShowSecret(made.agent.secret)
        } catch (e: Exception) {
            _ui.value = LoginUi(error = errorText(e))
        }
    }

    fun secretSaved() {
        _state.value = AppState.Ready
    }

    /** "I have a secret": restores who you are; where your data is, is the next screen's question. */
    suspend fun signIn(input: String) {
        val secret = input.trim()
        if (secret.isEmpty()) {
            _ui.value = LoginUi(error = "Paste your secret")
            return
        }
        _ui.value = LoginUi(busy = true)
        try {
            val status = backend.resume("", secret, null)
            session.save(secret)
            backend.activeDrive()?.let(session::saveDrive)
            _ui.value = LoginUi()
            _state.value =
                if (status == ResumeStatus.READY && backend.driveReady()) AppState.Ready else AppState.NeedsSync
        } catch (e: Exception) {
            _ui.value = LoginUi(error = signInError(e))
        }
    }

    /**
     * Look for the workspace on the other devices, the slow part sign-in does
     * not wait for: first the server its pkarr record names (one HTTPS round
     * trip), then Iroh with paired devices and discovery.
     */
    suspend fun findDrive() {
        _ui.value = LoginUi(busy = true)
        try {
            val wanted = backend.activeDrive()
            if (wanted != null && !backend.driveReady()) {
                _ui.update { it.copy(status = "Looking for the server your drive lives on…") }
                val found = try {
                    backend.discoverHomeServer(wanted)
                } catch (e: Exception) {
                    null
                }
                lookup = found?.log?.joinToString("\n").orEmpty()
                found?.origin?.let { origin ->
                    // Remember where it lives, so the next start reconnects there.
                    session.setActiveServer(origin)
                    session.saveDrive(wanted)
                    if (backend.driveReady()) return arrived()
                }
            }
            _ui.update { it.copy(status = "Looking for your devices…") }
            val report = backend.syncNow()
            backend.activeDrive()?.let(session::saveDrive)
            if (backend.driveReady()) return arrived()
            val said = if (report.imported > 0 || report.livePeers > 0u) {
                "Synced, but your workspace isn’t here yet — try again"
            } else {
                report.message
            }
            _ui.value = LoginUi(error = listOf(lookup, said).filter { it.isNotEmpty() }.joinToString("\n"))
        } catch (e: Exception) {
            _ui.value = LoginUi(error = errorText(e))
        }
    }

    /** Back from pairing: continue when the drive arrived. */
    suspend fun pairedCheck() {
        backend.activeDrive()?.let(session::saveDrive)
        if (backend.driveReady()) arrived() else _ui.value = LoginUi(error = "Drive not synced yet — try again")
    }

    private fun arrived() {
        _ui.value = LoginUi()
        _state.value = AppState.Ready
    }

    fun backToLogin() {
        _ui.value = LoginUi()
        _state.value = AppState.Login
    }

    suspend fun signOut() {
        runCatching { backend.closeServer() }
        backend.clearAgent()
        session.clear()
        backToLogin()
    }
}

/**
 * What a failed sign-in says: a secret that is not one (cut short, a word,
 * something else on the clipboard) gets a sentence a person can act on, not
 * the decoder's "Not valid Base64"; anything else as it came.
 */
fun signInError(error: Throwable): String {
    val text = errorText(error)
    val notASecret = Regex("Invalid key|Base64|base64|Invalid secret|decode", RegexOption.IGNORE_CASE).containsMatchIn(text)
    return if (notASecret) {
        "That is not a secret. A secret is the long code you saved when you made your identity; " +
            "on a device that is signed in, Sync → Copy secret key gives it."
    } else {
        text
    }
}

/** The text of an error: the Rust core's message as it is (the generated class prefixes it with `msg=`). */
fun errorText(error: Throwable): String =
    (error as? place.atomic.app.kotlin.core.CoreException.Message)?.msg ?: error.message ?: error.toString()
