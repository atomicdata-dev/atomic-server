package place.atomic.app.kotlin

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import place.atomic.app.kotlin.core.PeerRow
import place.atomic.app.kotlin.core.ServerInfo
import place.atomic.app.kotlin.data.PairModel
import place.atomic.app.kotlin.data.PairState
import place.atomic.app.kotlin.data.ServerRow
import place.atomic.app.kotlin.data.SettingsModel
import place.atomic.app.kotlin.data.describeSync
import place.atomic.app.kotlin.data.formatBytes
import place.atomic.app.kotlin.data.isServerPeer
import place.atomic.app.kotlin.data.normalizeNodeId
import place.atomic.app.kotlin.core.PeerSyncOutcome

@OptIn(ExperimentalCoroutinesApi::class)
class SettingsModelTest {
    private val ID = "ab".repeat(32)

    private fun TestScope.model(backend: FakeBackend, kv: MapKeyValue = MapKeyValue()): Pair<SettingsModel, SessionHolder> {
        val session = newSession(kv)
        return SettingsModel(backend, session, this as CoroutineScope) to SessionHolder(session)
    }

    class SessionHolder(val session: place.atomic.app.kotlin.session.SessionStore)

    @Test
    fun load_reads_the_profile_device_workspace_servers_and_devices() = runTest {
        val backend = FakeBackend().apply {
            activeDrive = HOME
            name = "Pixel"
            peersList = listOf(PeerRow(ID, "Laptop", 1_000_000u, true))
        }
        val (m, s) = model(backend)
        s.session.setActiveServer("localhost:9883")
        m.load()
        advanceUntilIdle()
        val st = m.state.value
        assertFalse(st.loading)
        assertEquals("Pelican", st.profile?.name)
        assertEquals("Pixel", st.deviceName)
        assertEquals(HOME, st.activeDrive)
        assertEquals(2, st.drives.size)
        assertEquals(1, st.livePeers)
        val server = st.servers.single()
        assertTrue(server.active)
        assertEquals("http://localhost:9883", server.url)
        assertEquals("0.41.0", server.info?.version)
        assertEquals(12uL, server.usage?.resourceCount)
    }

    @Test
    fun the_first_server_added_is_used_and_connected() = runTest {
        val backend = FakeBackend().apply { activeDrive = HOME }
        val (m, s) = model(backend)
        m.load(); advanceUntilIdle()
        m.addServer("node.example")
        advanceUntilIdle()
        assertEquals("https://node.example", s.session.activeServer())
        assertTrue("open:https://node.example" in backend.calls)
        assertTrue(m.state.value.serverConnected)
        assertFalse(m.state.value.busy)
    }

    @Test
    fun a_second_server_is_only_remembered_until_switched_to() = runTest {
        val backend = FakeBackend().apply { activeDrive = HOME }
        val (m, s) = model(backend)
        s.session.setActiveServer("https://one.example")
        m.load(); advanceUntilIdle()
        m.addServer("two.example")
        advanceUntilIdle()
        assertEquals("https://one.example", s.session.activeServer())
        assertEquals(2, m.state.value.servers.size)
        m.switchServer("https://two.example")
        advanceUntilIdle()
        assertEquals("https://two.example", s.session.activeServer())
        assertEquals(listOf("close", "open:https://two.example"), backend.calls.filter { it == "close" || it.startsWith("open") })
        m.removeServer("https://two.example")
        advanceUntilIdle()
        assertNull(s.session.activeServer())
        assertEquals(1, m.state.value.servers.size)
    }

    @Test
    fun a_server_that_cannot_be_reached_stays_selected_and_says_so() = runTest {
        val backend = object : place.atomic.app.kotlin.data.Backend by FakeBackend() {
            override suspend fun openServer(origin: String) = error("connection refused")
            override fun activeDrive() = HOME
            override suspend fun drives() = emptyList<place.atomic.app.kotlin.core.DriveRow>()
        }
        val s = newSession()
        val m = SettingsModel(backend, s, this)
        m.switchServer("https://down.example")
        advanceUntilIdle()
        assertEquals("https://down.example", s.activeServer())
        assertEquals("Could not connect: connection refused", m.state.value.error)
    }

    @Test
    fun pushing_the_workspace_reports_what_moved() = runTest {
        val backend = FakeBackend().apply { activeDrive = HOME }
        val (m, s) = model(backend)
        s.session.setActiveServer("https://node.example")
        m.load(); advanceUntilIdle()
        m.pushWorkspace(); advanceUntilIdle()
        assertEquals("Synced 3 resources to node.example", m.state.value.message)
        m.messageShown()
        backend.pushResult = 0
        m.pushWorkspace(); advanceUntilIdle()
        assertEquals("Already up to date", m.state.value.message)
    }

    @Test
    fun rename_switch_drive_new_workspace_and_profile_go_through_to_the_core() = runTest {
        val backend = FakeBackend().apply { activeDrive = HOME }
        val (m, s) = model(backend)
        m.load(); advanceUntilIdle()
        m.rename("  Tablet ")
        assertEquals("Tablet", backend.name)
        m.switchDrive("did:ad:other"); advanceUntilIdle()
        assertEquals("did:ad:other", backend.activeDrive)
        m.newWorkspace("Garden"); advanceUntilIdle()
        assertTrue(m.state.value.drives.any { it.name == "Garden" })
        m.saveProfile(" Heron ", " hi ")
        assertEquals("Heron", m.state.value.profile?.name)
        assertEquals("hi", m.state.value.profile?.description)
    }

    @Test
    fun removing_a_device_drops_it_and_secret_is_only_given_on_request() = runTest {
        val backend = FakeBackend().apply {
            agent = place.atomic.app.kotlin.core.AgentInfo("s3", "a", "p", "n")
            peersList = listOf(PeerRow(ID, "Laptop", null, false))
        }
        val (m, _) = model(backend)
        m.load(); advanceUntilIdle()
        m.removePeer(ID)
        assertTrue(m.state.value.peers.isEmpty())
        assertEquals("s3", m.secret())
    }

    @Test
    fun a_paired_device_that_is_a_listed_server_is_shown_once() {
        val server = ServerRow("https://node1.example.org", true, ServerInfo(ID, "0.41", false, null))
        assertTrue(isServerPeer(server, PeerRow("ff".repeat(32), "atomic.place (node1.example.org)", null, false)))
        assertTrue(isServerPeer(server, PeerRow("did:ad:node:$ID", "x", null, false)))
        assertFalse(isServerPeer(server, PeerRow("cd".repeat(32), "Laptop", null, false)))
        assertEquals(ID, normalizeNodeId("atomic:node:${ID.uppercase()}:Name"))
    }

    @Test
    fun bytes_read_like_a_person_says_them() {
        assertEquals("512 B", formatBytes(512))
        assertEquals("1.5 KB", formatBytes(1536))
        assertEquals("12 MB", formatBytes(12L * 1024 * 1024))
    }

    // ── Pairing ──

    private fun TestScope.pair(backend: FakeBackend, timeoutMs: Long = 25_000): Triple<PairModel, SessionHolder, FakeBackend> {
        val s = newSession()
        return Triple(PairModel(backend, s, this, timeoutMs), SessionHolder(s), backend)
    }

    @Test
    fun pairing_shows_this_devices_code_then_syncs_with_a_scanned_one() = runTest {
        val backend = FakeBackend().apply { name = "Pixel" }
        val (p, _, _) = pair(backend)
        p.start(); advanceUntilIdle()
        assertEquals(PairState.ShowCode("atomic:node:${"a".repeat(64)}:Pixel", "Pixel"), p.state.value)
        assertFalse("not a pairing code", p.onCode("hello"))
        assertTrue(p.onCode(ID)); advanceUntilIdle()
        assertEquals(PairState.Done("device", "Synced with Pixel — sent 1, received 2"), p.state.value)
        assertTrue("pair:$ID" in backend.calls)
    }

    @Test
    fun a_code_naming_a_workspace_and_a_server_is_adopted_when_this_device_has_none() = runTest {
        val backend = FakeBackend().apply { codeDrives = listOf("did:ad:theirs"); codeServer = "https://node.example" }
        val (p, s, _) = pair(backend)
        p.start(); advanceUntilIdle()
        p.onCode(ID); advanceUntilIdle()
        assertEquals("did:ad:theirs", backend.activeDrive)
        assertEquals(listOf("https://node.example"), s.session.knownServers())
    }

    @Test
    fun a_sync_that_takes_too_long_fails_with_advice_and_retry_tries_the_same_device() = runTest {
        val backend = FakeBackend().apply { pairDelay = true }
        val (p, _, _) = pair(backend, timeoutMs = 1_000)
        p.start(); advanceUntilIdle()
        p.onCode(ID); advanceUntilIdle()
        val failed = p.state.value as PairState.Failed
        assertTrue(failed.message.startsWith("Sync timed out after 1s"))
        backend.pairDelay = false
        p.retry(); advanceUntilIdle()
        assertTrue(p.state.value is PairState.Done)
    }

    @Test
    fun a_sync_is_described_in_both_directions() {
        fun d(i: Int, p: Int, inSync: Boolean = false, name: String? = null) = describeSync(PeerSyncOutcome(i, p, inSync, name), "Fallback")
        assertEquals("Synced with Fallback — sent 2, received 3", d(3, 2))
        assertEquals("Sent 1 resource with Fallback", d(0, 1))
        assertEquals("Received 5 resources with X", d(5, 0, name = "X"))
        assertEquals("Already in sync with Fallback", d(0, 0, true))
        assertEquals("Nothing to sync with Fallback", d(0, 0))
    }
}
