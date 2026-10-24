package place.atomic.app.kotlin

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import place.atomic.app.kotlin.core.ConnectivityReport
import place.atomic.app.kotlin.core.DiscoveryResult
import place.atomic.app.kotlin.core.ResumeStatus
import place.atomic.app.kotlin.core.StoreRecovery
import place.atomic.app.kotlin.data.Backend

@OptIn(ExperimentalCoroutinesApi::class)
class AccountFlowTest {
    private fun flow(
        backend: FakeBackend = FakeBackend(),
        kv: MapKeyValue = MapKeyValue(),
        open: suspend () -> Unit = {},
        recovery: StoreRecovery? = null,
    ) = AccountFlow(backend, newSession(kv), open, { recovery })

    @Test
    fun no_saved_session_asks_who_this_is() = runTest {
        val f = flow()
        f.start()
        assertEquals(AppState.Login, f.state.value)
    }

    /** The bug found on the phone: a restart must bring back the same agent, not make a new one. */
    @Test
    fun a_restart_signs_in_with_the_saved_secret_instead_of_making_a_new_agent() = runTest {
        val kv = MapKeyValue()
        val first = FakeBackend()
        val f1 = flow(first, kv)
        f1.start()
        f1.createAccount("Pelican")
        assertEquals(AppState.ShowSecret(SECRET), f1.state.value)
        f1.secretSaved()
        assertEquals(AppState.Ready, f1.state.value)

        // Force-stop and start again: a new process has no agent in memory, same storage.
        val second = FakeBackend().apply { activeDrive = HOME }
        val f2 = flow(second, kv)
        f2.start()
        assertEquals(AppState.Ready, f2.state.value)
        assertTrue("signed in again with the kept secret and drive", "resume::$SECRET:$HOME" in second.calls)
        assertTrue("no second agent is made", second.calls.none { it.startsWith("create") })
        assertEquals(SECRET, second.agent()?.secret)
    }

    @Test
    fun an_activity_recreated_in_the_same_process_keeps_the_running_agent() = runTest {
        val backend = FakeBackend().apply { agent = place.atomic.app.kotlin.core.AgentInfo(SECRET, "s", "p", "P") }
        val f = flow(backend)
        f.start()
        assertEquals(AppState.Ready, f.state.value)
        assertTrue(backend.calls.isEmpty())
    }

    @Test
    fun a_saved_drive_that_is_not_on_the_device_leads_to_the_sync_screen() = runTest {
        val kv = MapKeyValue()
        newSession(kv).save(SECRET, drive = HOME)
        val backend = FakeBackend().apply { driveHere = false; resumeStatus = ResumeStatus.NEEDS_SYNC }
        val f = flow(backend, kv)
        f.start()
        assertEquals(AppState.NeedsSync, f.state.value)
    }

    @Test
    fun a_saved_secret_that_no_longer_loads_goes_to_sign_in_with_a_sentence() = runTest {
        val kv = MapKeyValue()
        newSession(kv).save("broken")
        val backend = FakeBackend().apply { resumeError = IllegalStateException("Not valid Base64.") }
        val f = flow(backend, kv)
        f.start()
        assertEquals(AppState.Login, f.state.value)
        assertTrue(f.ui.value.error!!.startsWith("That is not a secret."))
    }

    @Test
    fun the_store_failing_to_open_and_a_recovery_notice_have_their_own_screens() = runTest {
        val failing = flow(open = { error("disk full") })
        failing.start()
        assertEquals(AppState.StoreFailed("disk full"), failing.state.value)

        val notice = StoreRecovery("/files/atomic.redb.corrupt-1", "damaged", true)
        val recovered = flow(recovery = notice)
        recovered.start()
        assertEquals(AppState.Recovery(notice), recovered.state.value)
        recovered.proceed()
        assertEquals(AppState.Login, recovered.state.value)
    }

    @Test
    fun a_failure_after_the_store_opened_is_a_startup_failure() = runTest {
        val kv = MapKeyValue()
        newSession(kv).save(SECRET)
        val backend = object : Backend by FakeBackend() {
            override suspend fun driveReady(): Boolean = error("boom")
            override fun agent() = null
            override suspend fun resume(server: String, secret: String, drive: String?) = ResumeStatus.READY
        }
        val f = AccountFlow(backend, newSession(kv), {}, { null })
        f.start()
        assertEquals(AppState.StartupFailed("boom"), f.state.value)
    }

    @Test
    fun creating_an_account_needs_a_name_and_saves_the_session() = runTest {
        val kv = MapKeyValue()
        val f = flow(kv = kv)
        f.createAccount("   ")
        assertEquals("Enter a name", f.ui.value.error)
        f.createAccount(" Pelican ")
        assertEquals(AppState.ShowSecret(SECRET), f.state.value)
        assertEquals(SECRET, newSession(kv).load()?.secret)
        assertEquals(HOME, newSession(kv).load()?.drive)
    }

    @Test
    fun signing_in_with_a_secret_restores_the_identity_and_remembers_it() = runTest {
        val kv = MapKeyValue()
        val f = flow(kv = kv)
        f.signIn("  ")
        assertEquals("Paste your secret", f.ui.value.error)
        f.signIn("  $SECRET ")
        assertEquals(AppState.Ready, f.state.value)
        assertEquals(SECRET, newSession(kv).load()?.secret)
    }

    @Test
    fun signing_in_where_the_drive_is_elsewhere_goes_to_the_sync_screen() = runTest {
        val f = flow(FakeBackend().apply { driveHere = false; resumeStatus = ResumeStatus.NEEDS_SYNC })
        f.signIn(SECRET)
        assertEquals(AppState.NeedsSync, f.state.value)
    }

    @Test
    fun a_secret_that_is_not_one_says_so_in_words() = runTest {
        val f = flow(FakeBackend().apply { resumeError = IllegalStateException("Invalid key length") })
        f.start()
        f.signIn("hello")
        assertEquals(AppState.Login, f.state.value)
        assertTrue(f.ui.value.error!!.contains("Copy secret key"))
        assertFalse(f.ui.value.busy)
    }

    @Test
    fun finding_the_drive_tries_the_server_its_record_names_first_and_remembers_it() = runTest {
        val kv = MapKeyValue()
        val backend = FakeBackend().apply {
            driveHere = false
            discovery = DiscoveryResult("https://node.example", listOf("https://node.example: certificate verified, connecting"))
        }
        val f = flow(backend, kv)
        f.signIn(SECRET)
        f.findDrive()
        assertEquals(AppState.Ready, f.state.value)
        assertEquals("https://node.example", newSession(kv).activeServer())
        assertFalse("devices are not searched when the server had it", "syncNow" in backend.calls)
    }

    @Test
    fun finding_the_drive_falls_back_to_devices_and_explains_when_nothing_answers() = runTest {
        val backend = FakeBackend().apply {
            driveHere = false
            discovery = DiscoveryResult(null, listOf("https://a.example: HTTP 404"))
        }
        val f = flow(backend)
        f.signIn(SECRET)
        f.findDrive()
        assertEquals(AppState.NeedsSync, f.state.value)
        val error = f.ui.value.error!!
        assertTrue(error.contains("https://a.example: HTTP 404"))
        assertTrue(error.contains("No peers online"))
        assertFalse(f.ui.value.busy)

        backend.connectivity = ConnectivityReport(4, 1u, "Connected to Pixel")
        f.findDrive()
        assertTrue(f.ui.value.error!!.contains("isn’t here yet"))
        backend.driveHere = true
        f.pairedCheck()
        assertEquals(AppState.Ready, f.state.value)
    }

    @Test
    fun signing_out_forgets_the_secret_but_not_the_data() = runTest {
        val kv = MapKeyValue()
        val backend = FakeBackend()
        val f = flow(backend, kv)
        f.signIn(SECRET)
        f.signOut()
        assertEquals(AppState.Login, f.state.value)
        assertNull(newSession(kv).load())
        assertNull(backend.agent())
        assertNotNull(backend.drivesList)
    }
}
