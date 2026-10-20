package place.atomic.app.kotlin

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.core.activeAgent
import place.atomic.app.kotlin.core.createAgentAndDrive
import place.atomic.app.kotlin.core.flushStore
import place.atomic.app.kotlin.core.openStore
import place.atomic.app.kotlin.core.resumeAgent

sealed interface AppState {
    data object Opening : AppState

    /** No agent on this device yet: first run. */
    data object Welcome : AppState
    data object Ready : AppState
    data class Failed(val message: String) : AppState
}

/**
 * Process start-up: opens the store (idempotent, Android recreates the
 * activity in the same process), then either shows first run or the Home.
 */
class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val _state = MutableStateFlow<AppState>(AppState.Opening)
    val state: StateFlow<AppState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            _state.value = try {
                openStore(getApplication<Application>().filesDir.resolve("atomic").absolutePath)
                resumeSession()
                if (activeAgent() == null) AppState.Welcome else AppState.Ready.also { seed() }
            } catch (e: Exception) {
                AppState.Failed(e.message ?: e.toString())
            }
        }
    }

    private val session get() = getApplication<AtomicApp>().session

    /**
     * The store keeps the active drive but not the agent (it lives in memory),
     * so a restarted process has none until the kept secret is loaded. Skipping
     * this made every start a first run with a new agent.
     */
    private suspend fun resumeSession() {
        if (activeAgent() != null) return // the process is alive: the activity was recreated
        val saved = session.load() ?: return
        resumeAgent(saved.secret, saved.drive)
    }

    /** First run: an agent and its private drive, so the Home has something to show. */
    fun createAccount(name: String) {
        viewModelScope.launch {
            _state.value = try {
                val made = createAgentAndDrive(name.trim().ifEmpty { "Me" })
                session.save(made.agent.secret, drive = made.driveSubject)
                seed()
                AppState.Ready
            } catch (e: Exception) {
                AppState.Failed(e.message ?: e.toString())
            }
        }
    }

    /** Debug builds fill the store when asked to; release builds do nothing. */
    private suspend fun seed() = DebugSeed.runIfAsked(getApplication())

    fun flush() {
        runCatching { flushStore() }
    }
}
