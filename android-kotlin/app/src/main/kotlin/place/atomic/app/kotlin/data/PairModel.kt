package place.atomic.app.kotlin.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import place.atomic.app.kotlin.core.PeerSyncOutcome
import place.atomic.app.kotlin.errorText
import place.atomic.app.kotlin.session.SessionStore

sealed interface PairState {
    data object Loading : PairState

    /** Showing this device's code; ready to scan or take a pasted one. */
    data class ShowCode(val code: String, val deviceName: String) : PairState
    data class Syncing(val label: String) : PairState
    data class Done(val label: String, val summary: String) : PairState
    data class Failed(val message: String) : PairState
}

/** What a sync with one device did, as a person would say it (Flutter's `PeerSyncResult.describe`). */
fun describeSync(outcome: PeerSyncOutcome, fallbackName: String? = null): String {
    val name = outcome.peerName?.takeIf { it.isNotEmpty() } ?: fallbackName?.takeIf { it.isNotEmpty() }
    val with = if (name == null) "" else " with $name"
    fun resources(n: Int) = "$n ${if (n == 1) "resource" else "resources"}"
    return when {
        outcome.imported > 0 && outcome.pushed > 0 -> "Synced$with — sent ${outcome.pushed}, received ${outcome.imported}"
        outcome.pushed > 0 -> "Sent ${resources(outcome.pushed)}$with"
        outcome.imported > 0 -> "Received ${resources(outcome.imported)}$with"
        outcome.inSync -> "Already in sync$with"
        else -> "Nothing to sync$with"
    }
}

/** Pairing: show this device's code, take one scanned or pasted, sync with that device (Flutter's `PairScreen`). */
class PairModel(
    private val backend: Backend,
    private val session: SessionStore,
    private val scope: CoroutineScope,
    private val syncTimeoutMs: Long = 25_000,
) {
    private val _state = MutableStateFlow<PairState>(PairState.Loading)
    val state: StateFlow<PairState> = _state.asStateFlow()
    private var scanned: Pair<String, String>? = null
    private var handled = false

    fun start(initialNodeId: String? = null) {
        scope.launch {
            try {
                val nodeId = backend.peerId() ?: backend.startPeer()
                _state.value = PairState.ShowCode(backend.formatCode(nodeId, backend.deviceName()), backend.deviceName())
                if (initialNodeId != null) sync(initialNodeId, "")
            } catch (e: Exception) {
                _state.value = PairState.Failed("Failed to start peer: ${errorText(e)}")
            }
        }
    }

    /** A scanned or pasted code. `false` when it is not a pairing code, so the caller can say so. */
    fun onCode(raw: String): Boolean {
        if (handled) return true
        val peer = backend.parseCode(raw) ?: return false
        handled = true
        peer.serverUrl?.takeIf { it.isNotEmpty() }?.let(session::addKnownServer)
        scope.launch {
            // A code that names a workspace is adopted when this device has none yet.
            val named = peer.drives.firstOrNull()
            if (named != null && backend.activeDrive() == null) {
                try {
                    backend.activateDrive(named)
                    session.saveDrive(named)
                } catch (e: Exception) {
                    _state.value = PairState.Failed("Could not open the workspace that code names: ${errorText(e)}")
                    return@launch
                }
            }
            sync(peer.nodeId, peer.name)
        }
        return true
    }

    private suspend fun sync(nodeId: String, name: String) {
        scanned = nodeId to name
        _state.value = PairState.Syncing(name.ifEmpty { nodeId.take(12) + "..." })
        try {
            val outcome = withTimeout(syncTimeoutMs) { backend.pairWith(nodeId, name) }
            _state.value = PairState.Done(name.ifEmpty { "device" }, describeSync(outcome, name))
        } catch (e: TimeoutCancellationException) {
            _state.value = PairState.Failed("Sync timed out after ${syncTimeoutMs / 1000}s. Keep both devices open on Wi‑Fi and try again.")
        } catch (e: Exception) {
            _state.value = PairState.Failed(errorText(e))
        }
    }

    /** Try the same device again, or go back to the code when nothing was scanned. */
    fun retry() {
        val last = scanned
        if (last != null) {
            scope.launch { sync(last.first, last.second) }
        } else {
            handled = false
            start()
        }
    }
}
