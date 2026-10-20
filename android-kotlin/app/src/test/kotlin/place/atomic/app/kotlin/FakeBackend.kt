package place.atomic.app.kotlin

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import place.atomic.app.kotlin.core.AgentInfo
import place.atomic.app.kotlin.core.ConnectivityReport
import place.atomic.app.kotlin.core.DiscoveryResult
import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.core.DriveUsage
import place.atomic.app.kotlin.core.OwnProfile
import place.atomic.app.kotlin.core.PairingCode
import place.atomic.app.kotlin.core.PeerRow
import place.atomic.app.kotlin.core.PeerSyncOutcome
import place.atomic.app.kotlin.core.ResumeStatus
import place.atomic.app.kotlin.core.ServerInfo
import place.atomic.app.kotlin.core.SetupResult
import place.atomic.app.kotlin.core.SyncEvent
import place.atomic.app.kotlin.data.Backend
import place.atomic.app.kotlin.session.KeyValue
import place.atomic.app.kotlin.session.SecretBox
import place.atomic.app.kotlin.session.SessionStore

/** In-memory storage, so a "restart" is a new [SessionStore] over the same map. */
class MapKeyValue(val map: MutableMap<String, String> = mutableMapOf()) : KeyValue {
    override fun getString(key: String) = map[key]
    override fun putString(key: String, value: String?) {
        if (value == null) map.remove(key) else map[key] = value
    }
}

/** Not secure, only reversible: proves the secret is not stored as it is. */
class ReverseBox : SecretBox {
    override fun seal(plain: String) = plain.reversed()
    override fun open(sealed: String): String? = sealed.reversed()
}

fun newSession(kv: MapKeyValue = MapKeyValue()) = SessionStore(kv, ReverseBox())

const val SECRET = "secret-of-pelican"
const val HOME = "did:ad:home"

/**
 * The Rust core as the screens see it. Like the real store, it knows no agent
 * after a "restart" (a new instance) until [resume] loads one from a secret.
 */
class FakeBackend : Backend {
    var agent: AgentInfo? = null
    var driveHere = true
    var activeDrive: String? = null
    var resumeStatus = ResumeStatus.READY
    var resumeError: Exception? = null
    var drivesList = listOf(DriveRow(HOME, "Pelican's Drive", null), DriveRow("did:ad:other", "Ontola", null))
    var profile = OwnProfile("did:ad:agent:pelican", "Pelican", "Likes reeds", null, null)
    var peersList = listOf<PeerRow>()
    var info = ServerInfo(null, "0.41.0", false, null)
    var usage: DriveUsage? = DriveUsage("Pelican's Drive", 12u, 2048u, 4096u)
    var discovery = DiscoveryResult(null, emptyList())
    var connectivity = ConnectivityReport(0, 0u, "No peers online. Open the other device or pair with QR.")
    var pushResult = 3
    var pairOutcome = PeerSyncOutcome(2, 1, false, "Pixel")
    var pairDelay = false
    var serverOpen = false
    var codeDrives = emptyList<String>()
    var codeServer: String? = null
    var name = ""
    val calls = mutableListOf<String>()
    val events = MutableSharedFlow<SyncEvent>(extraBufferCapacity = 8)

    override fun agent() = agent
    override suspend fun createAccount(name: String): SetupResult {
        calls += "create:$name"
        val made = AgentInfo(SECRET, "did:ad:agent:pelican", "pk", name)
        agent = made
        activeDrive = HOME
        return SetupResult(made, HOME)
    }

    override suspend fun resume(server: String, secret: String, drive: String?): ResumeStatus {
        calls += "resume:$server:$secret:$drive"
        resumeError?.let { throw it }
        agent = AgentInfo(secret, "did:ad:agent:pelican", "pk", "Pelican")
        activeDrive = drive ?: HOME
        return resumeStatus
    }

    override suspend fun driveReady() = driveHere
    override fun clearAgent() {
        calls += "clearAgent"
        agent = null
    }

    override suspend fun drives() = drivesList
    override fun activeDrive() = activeDrive
    override suspend fun activateDrive(subject: String) {
        calls += "activate:$subject"
        activeDrive = subject
    }

    override suspend fun createDrive(name: String): String {
        calls += "createDrive:$name"
        drivesList = drivesList + DriveRow("did:ad:new", name, null)
        return "did:ad:new"
    }

    override suspend fun ownProfile() = profile
    override suspend fun setOwnProfile(name: String, description: String) {
        calls += "profile:$name:$description"
        profile = profile.copy(name = name, description = description)
    }

    override suspend fun openServer(origin: String) {
        calls += "open:$origin"
        serverOpen = true
    }

    override suspend fun closeServer() {
        calls += "close"
        serverOpen = false
    }

    override fun serverConnected() = serverOpen
    override suspend fun serverInfo(origin: String) = info
    override suspend fun driveUsage(origin: String, drive: String) = usage
    override suspend fun pushWorkspace(origin: String): Int {
        calls += "push:$origin"
        return pushResult
    }

    override suspend fun discoverHomeServer(drive: String): DiscoveryResult {
        calls += "discover:$drive"
        if (discovery.origin != null) driveHere = true
        return discovery
    }

    override suspend fun startPeer() = "a".repeat(64)
    override fun peerId(): String? = "a".repeat(64)
    override fun deviceName() = name
    override fun setDeviceName(name: String) {
        this.name = name
    }

    override fun peers() = peersList
    override fun removePeer(nodeId: String) {
        peersList = peersList.filterNot { it.nodeId == nodeId }
    }

    override suspend fun pairWith(nodeId: String, name: String): PeerSyncOutcome {
        calls += "pair:$nodeId"
        if (pairDelay) kotlinx.coroutines.awaitCancellation()
        return pairOutcome
    }

    override suspend fun syncNow(): ConnectivityReport {
        calls += "syncNow"
        return connectivity
    }

    override fun parseCode(text: String): PairingCode? =
        text.trim().takeIf { it.length == 64 }?.let { PairingCode(it, "", codeServer, codeDrives) }

    override fun formatCode(nodeId: String, deviceName: String) = "atomic:node:$nodeId:$deviceName"
    override fun syncEvents(): Flow<SyncEvent> = events
}
