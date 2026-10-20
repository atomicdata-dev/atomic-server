package place.atomic.app.kotlin

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.core.flushStore
import place.atomic.app.kotlin.core.openStore
import place.atomic.app.kotlin.core.storeRecovery
import place.atomic.app.kotlin.data.CoreBackend
import place.atomic.app.kotlin.data.IdentityModel
import place.atomic.app.kotlin.data.SettingsModel
import place.atomic.app.kotlin.session.KeyValue
import place.atomic.app.kotlin.session.PrefsKeyValue
import place.atomic.app.kotlin.shell.BackgroundSync
import place.atomic.app.kotlin.shell.ToastController
import kotlinx.coroutines.flow.collectLatest

/**
 * Process start-up: opens the store (idempotent, Android recreates the
 * activity in the same process), signs in again from the saved secret and
 * leads to the Home or to the sign-in screens ([AccountFlow]).
 */
class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val atomic = app as AtomicApp
    val flow = AccountFlow(
        backend = CoreBackend,
        session = atomic.session,
        openStore = { openStore(app.filesDir.resolve("atomic").absolutePath).also { Perf.mark("db open") } },
        recovery = { storeRecovery() },
    )
    /** The settings screen's model, living as long as the app does. */
    val settings by lazy { SettingsModel(CoreBackend, atomic.session, viewModelScope) }
    /** Layout, list width and the like: what the person arranged, per device. */
    val uiPrefs: KeyValue by lazy { PrefsKeyValue(app, "atomic_ui") }
    /** Who the bottom bar's profile button shows. */
    val identity by lazy { IdentityModel(CoreBackend, viewModelScope) }
    val toasts = ToastController()
    /** The sync with other devices after sign-in and on every resume; failures are quiet. */
    val sync by lazy { BackgroundSync(CoreBackend, toasts, viewModelScope, log = { android.util.Log.d("atomic", it) }) }
    val state get() = flow.state
    val ui get() = flow.ui

    init {
        viewModelScope.launch {
            flow.state.collectLatest { if (it == AppState.Ready) sync.start() else sync.stop() }
        }
        launch {
            flow.start()
            if (flow.state.value == AppState.Ready) {
                Perf.mark("session restored")
                seed()
            }
        }
    }

    /** Runs [block] in the view model's scope and, when it ends at the Home, fills debug data. */
    fun launch(block: suspend () -> Unit) {
        viewModelScope.launch { block() }
    }

    /** A tap on a drive makes it the active one, as in Flutter. */
    fun activateDrive(subject: String) = launch {
        runCatching {
            CoreBackend.activateDrive(subject)
            atomic.session.saveDrive(subject)
        }
    }

    fun retryStart() = launch { flow.start() }
    fun continueAfterRecovery() = launch { flow.proceed() }
    fun createAccount(name: String) = launch { flow.createAccount(name) }
    fun secretSaved() = flow.secretSaved().also { launch { seed() } }
    fun signIn(secret: String) = launch { flow.signIn(secret) }
    fun findDrive() = launch { flow.findDrive() }
    fun pairedCheck() = launch { flow.pairedCheck() }
    fun backToLogin() = flow.backToLogin()
    fun signOut() = launch { flow.signOut() }

    /** Debug builds fill the store when asked to; release builds do nothing. */
    private suspend fun seed() = DebugSeed.runIfAsked(getApplication())

    /** Back in the foreground: look for the other devices again, and read the profile again. */
    fun resumed() {
        if (flow.state.value == AppState.Ready) {
            sync.start()
            identity.refresh()
        }
    }

    fun flush() {
        runCatching { flushStore() }
    }
}
