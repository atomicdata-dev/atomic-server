package place.atomic.app.kotlin.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.core.DriveUsage
import place.atomic.app.kotlin.core.OwnProfile
import place.atomic.app.kotlin.core.PeerRow
import place.atomic.app.kotlin.core.ServerInfo
import place.atomic.app.kotlin.errorText
import place.atomic.app.kotlin.session.SessionStore
import place.atomic.app.kotlin.session.normalizeServerUrl
import place.atomic.app.kotlin.session.sameOrigin
import place.atomic.app.kotlin.session.serverLabel

/** A server the device knows; the active one carries what it said about itself. */
data class ServerRow(
    val url: String,
    val active: Boolean,
    val info: ServerInfo? = null,
    val usage: DriveUsage? = null,
)

/** What the settings screen shows (Flutter's `SyncScreen` and `ServerSettingsSection`). */
data class SettingsState(
    val loading: Boolean = true,
    val error: String? = null,
    val profile: OwnProfile? = null,
    val deviceName: String = "",
    val peerId: String? = null,
    val serverConnected: Boolean = false,
    val drives: List<DriveRow> = emptyList(),
    val activeDrive: String? = null,
    val servers: List<ServerRow> = emptyList(),
    val peers: List<PeerRow> = emptyList(),
    /** An action is running (switching server, pushing the workspace). */
    val busy: Boolean = false,
    /** A line to say once (a snackbar), then [SettingsModel.messageShown]. */
    val message: String? = null,
) {
    val livePeers get() = peers.count { it.live }
}

/**
 * Whether a paired device *is* this server: the same always-on device reached
 * two ways, over https and over Iroh. Pairing with a server's code names the
 * peer after it, and the active server reports its own node id, so one device
 * is listed once.
 */
fun isServerPeer(server: ServerRow, peer: PeerRow): Boolean {
    val host = serverLabel(server.url).substringBefore(':').lowercase()
    if (host.isNotEmpty() && peer.name.lowercase().contains(host)) return true
    val id = server.info?.nodeId ?: return false
    return server.active && normalizeNodeId(id) == normalizeNodeId(peer.nodeId)
}

/** The canonical 64-char hex node id. */
fun normalizeNodeId(id: String): String {
    var s = id.trim()
    for (prefix in listOf("atomic:node:", "did:ad:node:")) {
        if (s.startsWith(prefix)) {
            s = s.removePrefix(prefix)
            if (s.length > 64 && s[64] == ':') s = s.substring(0, 64)
            break
        }
    }
    return s.removePrefix("iroh:").lowercase()
}

/** "12 resources · 1.4 MB", as Flutter's server card says it. */
fun usageLine(usage: DriveUsage): String =
    "${usage.resourceCount} resources · ${formatBytes((usage.blobBytes + usage.loroBytes).toLong())}"

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = listOf("KB", "MB", "GB", "TB")
    var value = bytes / 1024.0
    var unit = 0
    while (value >= 1024 && unit < units.lastIndex) {
        value /= 1024
        unit++
    }
    return "%.${if (value < 10) 1 else 0}f %s".format(java.util.Locale.ROOT, value, units[unit])
}

class SettingsModel(
    private val backend: Backend,
    private val session: SessionStore,
    private val scope: CoroutineScope,
) {
    private val _state = MutableStateFlow(SettingsState())
    val state: StateFlow<SettingsState> = _state.asStateFlow()

    /** Reads everything; the screen shows as soon as the first part is in. */
    fun load() {
        scope.launch {
            try {
                val profile = runCatching { backend.ownProfile() }.getOrNull()
                _state.update {
                    it.copy(
                        loading = false,
                        error = null,
                        profile = profile,
                        deviceName = backend.deviceName(),
                        peerId = backend.peerId(),
                        serverConnected = backend.serverConnected(),
                        activeDrive = backend.activeDrive(),
                        peers = backend.peers(),
                        servers = serverRows(it.servers),
                    )
                }
                // Listing drives reads each one: after the screen is up.
                _state.update { it.copy(drives = backend.drives()) }
                loadActiveDetails()
            } catch (e: Exception) {
                _state.update { it.copy(loading = false, error = errorText(e)) }
            }
        }
    }

    private fun serverRows(previous: List<ServerRow>): List<ServerRow> {
        val active = session.activeServer()
        return session.knownServers().map { url ->
            val before = previous.firstOrNull { it.url == url }
            ServerRow(url, sameOrigin(url, active), before?.info, before?.usage)
        }
    }

    /** The active server's own account of itself and what the drive costs there; best effort. */
    private suspend fun loadActiveDetails() {
        val active = _state.value.servers.firstOrNull { it.active } ?: return
        val info = withTimeoutOrNull(6_000) { backend.serverInfo(active.url) }
        updateServer(active.url) { it.copy(info = info) }
        val drive = backend.activeDrive() ?: return
        val usage = withTimeoutOrNull(8_000) { backend.driveUsage(active.url, drive) }
        updateServer(active.url) { it.copy(usage = usage) }
    }

    private fun updateServer(url: String, change: (ServerRow) -> ServerRow) =
        _state.update { s -> s.copy(servers = s.servers.map { if (it.url == url) change(it) else it }) }

    /** Peers and the connection light, on a sync event. */
    fun refreshLive() = _state.update {
        it.copy(peers = backend.peers(), serverConnected = backend.serverConnected(), peerId = backend.peerId())
    }

    fun messageShown() = _state.update { it.copy(message = null) }

    private fun say(text: String) = _state.update { it.copy(message = text) }

    private fun fail(what: String, e: Throwable) = say("$what: ${errorText(e)}")

    private fun busy(on: Boolean) = _state.update { it.copy(busy = on) }

    fun rename(name: String) {
        val trimmed = name.trim()
        if (trimmed.isEmpty()) return
        backend.setDeviceName(trimmed)
        _state.update { it.copy(deviceName = trimmed) }
    }

    fun newWorkspace(name: String) {
        val trimmed = name.trim()
        if (trimmed.isEmpty()) return
        scope.launch {
            try {
                backend.createDrive(trimmed)
                load()
            } catch (e: Exception) {
                fail("Could not create the workspace", e)
            }
        }
    }

    /** Makes a drive the active one (a tap on it, here or on the Home). */
    fun switchDrive(subject: String) {
        scope.launch {
            try {
                backend.activateDrive(subject)
                session.saveDrive(subject)
                load()
            } catch (e: Exception) {
                fail("Could not switch workspace", e)
            }
        }
    }

    // ── Servers ──

    /** The server stays selected when connecting fails: it is what the session now points at. */
    fun switchServer(url: String) {
        scope.launch {
            busy(true)
            _state.update { s -> s.copy(error = null, servers = s.servers.map { it.copy(info = null, usage = null) }) }
            try {
                backend.closeServer()
                session.setActiveServer(url)
                _state.update { it.copy(servers = serverRows(it.servers)) }
                backend.openServer(normalizeServerUrl(url))
                _state.update { it.copy(serverConnected = backend.serverConnected()) }
                loadActiveDetails()
            } catch (e: Exception) {
                _state.update { it.copy(error = "Could not connect: ${errorText(e)}", serverConnected = false) }
            } finally {
                busy(false)
            }
        }
    }

    fun addServer(input: String) {
        val url = normalizeServerUrl(input)
        if (url.isEmpty()) return
        session.addKnownServer(url)
        _state.update { it.copy(servers = serverRows(it.servers)) }
        // The first server added is the one to use: nothing to choose between.
        if (session.activeServer() == null) switchServer(url)
    }

    fun removeServer(url: String) {
        scope.launch {
            if (sameOrigin(url, session.activeServer())) runCatching { backend.closeServer() }
            session.removeKnownServer(url)
            _state.update { it.copy(servers = serverRows(it.servers), serverConnected = backend.serverConnected()) }
        }
    }

    /**
     * Offer this device's workspace to the active server. Connecting alone does
     * not do this: a drive made here before any server was connected has never
     * been pushed, so it exists nowhere else.
     */
    fun pushWorkspace() {
        val active = _state.value.servers.firstOrNull { it.active } ?: return
        if (_state.value.busy) return
        scope.launch {
            busy(true)
            _state.update { it.copy(error = null) }
            try {
                val pushed = backend.pushWorkspace(active.url)
                say(
                    if (pushed == 0) "Already up to date"
                    else "Synced $pushed ${if (pushed == 1) "resource" else "resources"} to ${serverLabel(active.url)}",
                )
                loadActiveDetails()
            } catch (e: Exception) {
                _state.update { it.copy(error = errorText(e)) }
            } finally {
                busy(false)
            }
        }
    }

    fun removePeer(nodeId: String) {
        backend.removePeer(nodeId)
        _state.update { s -> s.copy(peers = s.peers.filterNot { it.nodeId == nodeId }) }
    }

    /** Names of drives as the switcher shows them: named ones, and the active one. */
    fun driveLabel(subject: String): String =
        _state.value.drives.firstOrNull { it.subject == subject }?.name?.ifEmpty { null } ?: "Workspace"

    suspend fun saveProfile(name: String, description: String) {
        backend.setOwnProfile(name.trim(), description.trim())
        _state.update { it.copy(profile = runCatching { backend.ownProfile() }.getOrNull() ?: it.profile) }
    }

    /** The backup secret, only when asked for. */
    fun secret(): String? = backend.agent()?.secret
}
