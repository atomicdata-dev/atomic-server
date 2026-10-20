package place.atomic.app.kotlin.data

import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
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
import place.atomic.app.kotlin.core.SyncListener
import place.atomic.app.kotlin.core.AgentInfo

/**
 * Everything the account, settings and pairing screens ask of the Rust core.
 * The real one is [CoreBackend]; the JVM tests use a fake, since the native
 * library does not load on the host.
 */
interface Backend {
    // Agent and drives
    fun agent(): AgentInfo?
    suspend fun createAccount(name: String): SetupResult

    /** Signs in with the secret and opens the server session; throws on a secret that is not one. */
    suspend fun resume(server: String, secret: String, drive: String?): ResumeStatus
    suspend fun driveReady(): Boolean
    fun clearAgent()
    suspend fun drives(): List<DriveRow>
    fun activeDrive(): String?
    suspend fun activateDrive(subject: String)
    suspend fun createDrive(name: String): String
    suspend fun ownProfile(): OwnProfile
    suspend fun setOwnProfile(name: String, description: String)

    /** The bytes of a File resource (a profile picture) when this device holds them. */
    suspend fun readFileBytes(file: String): ByteArray? = null

    // Servers
    suspend fun openServer(origin: String)
    suspend fun closeServer()
    fun serverConnected(): Boolean
    suspend fun serverInfo(origin: String): ServerInfo
    suspend fun driveUsage(origin: String, drive: String): DriveUsage?
    suspend fun pushWorkspace(origin: String): Int
    suspend fun discoverHomeServer(drive: String): DiscoveryResult

    // Devices
    suspend fun startPeer(): String
    fun peerId(): String?
    fun deviceName(): String
    fun setDeviceName(name: String)
    fun peers(): List<PeerRow>
    fun removePeer(nodeId: String)
    suspend fun pairWith(nodeId: String, name: String): PeerSyncOutcome
    suspend fun syncNow(): ConnectivityReport
    fun parseCode(text: String): PairingCode?
    fun formatCode(nodeId: String, deviceName: String): String

    /** Emits for every sync event (device connected, left, resources received). */
    fun syncEvents(): Flow<SyncEvent>
}

object CoreBackend : Backend {
    override fun agent() = place.atomic.app.kotlin.core.activeAgent()
    override suspend fun createAccount(name: String) = place.atomic.app.kotlin.core.createAgentAndDrive(name)
    override suspend fun resume(server: String, secret: String, drive: String?) =
        place.atomic.app.kotlin.core.resumeSession(server, secret, drive)

    override suspend fun driveReady() = place.atomic.app.kotlin.core.driveReady()
    override fun clearAgent() = place.atomic.app.kotlin.core.clearAgent()
    override suspend fun drives(): List<DriveRow> = place.atomic.app.kotlin.core.listDrives()
    override fun activeDrive() = place.atomic.app.kotlin.core.activeDrive()
    override suspend fun activateDrive(subject: String) = place.atomic.app.kotlin.core.activateDrive(subject)
    override suspend fun createDrive(name: String) = place.atomic.app.kotlin.core.createDrive(name)
    override suspend fun ownProfile() = place.atomic.app.kotlin.core.ownProfile()
    override suspend fun setOwnProfile(name: String, description: String) =
        place.atomic.app.kotlin.core.setOwnProfile(name, description)
    override suspend fun readFileBytes(file: String) = place.atomic.app.kotlin.core.readFileBytes(file)

    override suspend fun openServer(origin: String) = place.atomic.app.kotlin.core.openWsSync(origin)
    override suspend fun closeServer() = place.atomic.app.kotlin.core.closeWsSync()
    override fun serverConnected() = place.atomic.app.kotlin.core.serverConnected()
    override suspend fun serverInfo(origin: String) = place.atomic.app.kotlin.core.serverInfo(origin)
    override suspend fun driveUsage(origin: String, drive: String) = place.atomic.app.kotlin.core.driveUsage(origin, drive)
    override suspend fun pushWorkspace(origin: String) = place.atomic.app.kotlin.core.syncDriveToServer(origin).toInt()
    override suspend fun discoverHomeServer(drive: String) = place.atomic.app.kotlin.core.discoverHomeServer(drive)

    override suspend fun startPeer() = place.atomic.app.kotlin.core.startPeer()
    override fun peerId() = place.atomic.app.kotlin.core.peerId()
    override fun deviceName() = place.atomic.app.kotlin.core.deviceName()
    override fun setDeviceName(name: String) = place.atomic.app.kotlin.core.setDeviceName(name)
    override fun peers(): List<PeerRow> = place.atomic.app.kotlin.core.knownPeers()
    override fun removePeer(nodeId: String) = place.atomic.app.kotlin.core.removeKnownPeer(nodeId)
    override suspend fun pairWith(nodeId: String, name: String) = place.atomic.app.kotlin.core.pairWith(nodeId, name)
    override suspend fun syncNow() = place.atomic.app.kotlin.core.syncConnectivityNow()
    override fun parseCode(text: String) = place.atomic.app.kotlin.core.parsePairingCode(text)
    override fun formatCode(nodeId: String, deviceName: String) =
        place.atomic.app.kotlin.core.formatPairingCode(nodeId, deviceName)

    override fun syncEvents(): Flow<SyncEvent> = callbackFlow {
        val subscription = place.atomic.app.kotlin.core.subscribeSyncEvents(object : SyncListener {
            override fun onEvent(event: SyncEvent) {
                trySend(event)
            }
        })
        awaitClose { subscription.cancel() }
    }
}
