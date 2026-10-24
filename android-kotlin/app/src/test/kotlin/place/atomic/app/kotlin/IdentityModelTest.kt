package place.atomic.app.kotlin

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import place.atomic.app.kotlin.data.IdentityModel

@OptIn(ExperimentalCoroutinesApi::class)
class IdentityModelTest {
    private val bytes = byteArrayOf(1, 2, 3)

    @Test
    fun theProfilePictureIsReadFromTheFileResourceBytes() = runTest(StandardTestDispatcher()) {
        val backend = FakeBackend()
        backend.profile = backend.profile.copy(iconFile = "did:ad:file1")
        backend.files["did:ad:file1"] = bytes
        val model = IdentityModel(backend, TestScope(testScheduler))
        model.refresh()
        advanceUntilIdle()
        val identity = model.state.value!!
        assertEquals("Pelican", identity.name)
        assertArrayEquals(bytes, identity.image)
        assertFalse(identity.pending)
    }

    @Test
    fun aPictureThatHasNotSyncedYetIsPendingAndTriedAgain() = runTest(StandardTestDispatcher()) {
        val backend = FakeBackend()
        backend.profile = backend.profile.copy(iconFile = "did:ad:file1")
        val model = IdentityModel(backend, TestScope(testScheduler), retryAfterMs = 1_000, maxRetries = 3)
        model.refresh()
        advanceTimeBy(1)
        assertTrue(model.state.value!!.pending)
        assertNull(model.state.value!!.image)

        backend.files["did:ad:file1"] = bytes
        advanceTimeBy(1_001)
        assertArrayEquals(bytes, model.state.value!!.image)
        assertFalse(model.state.value!!.pending)
    }

    @Test
    fun withoutAPictureThereIsNothingToWaitFor() = runTest(StandardTestDispatcher()) {
        val model = IdentityModel(FakeBackend(), TestScope(testScheduler))
        model.refresh()
        advanceUntilIdle()
        assertFalse(model.state.value!!.pending)
        assertNull(model.state.value!!.image)
    }
}
