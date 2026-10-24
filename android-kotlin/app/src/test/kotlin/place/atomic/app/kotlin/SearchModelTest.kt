package place.atomic.app.kotlin

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
import place.atomic.app.kotlin.core.SearchHit
import place.atomic.app.kotlin.data.SearchKind
import place.atomic.app.kotlin.data.SearchModel

@OptIn(ExperimentalCoroutinesApi::class)
class SearchModelTest {
    private val hits = listOf(
        SearchHit("did:ad:res1", "Quarterly planning", "DocumentV2", null, "did:ad:home", 3.0),
        SearchHit("did:ad:ontola", "Ontola", "Drive", null, "did:ad:ontola", 2.5),
        SearchHit("did:ad:res9", "Plan the offsite", "AiChat", null, "did:ad:ontola", 2.0),
    )

    private fun TestScope.model(repo: FakeRepository, scopeDrive: String? = null, kind: SearchKind = SearchKind.Any) =
        SearchModel(repo, this, scopeDrive, kind)

    @Test
    fun beforeAnythingIsTypedTheListShowsWhatWasOpenedLately() = runTest(StandardTestDispatcher()) {
        val repo = FakeRepository(lists = mapOf(place.atomic.app.kotlin.core.HomeList.RECENTS to fakeRecents))
        val m = model(repo)
        advanceUntilIdle()
        assertEquals(6, m.state.value.items.size)
        assertTrue(m.state.value.showsRecent)
        // The drive is named in the detail of every row.
        assertEquals("Document · Joep's Drive", m.state.value.detail(m.state.value.items[0]))
    }

    @Test
    fun everyKeystrokeSearchesAndATypedTextHasItsOwnResults() = runTest(StandardTestDispatcher()) {
        val repo = FakeRepository(hits = hits)
        val m = model(repo)
        advanceUntilIdle()
        for (t in listOf("p", "pl", "pla")) {
            m.setQuery(t)
            advanceUntilIdle()
        }
        assertEquals(listOf("p", "pl", "pla"), repo.queries)
        assertEquals("pla", m.state.value.hitsFor)
        assertEquals(listOf("Quarterly planning", "Plan the offsite"), m.state.value.items.map { it.title })
        m.setQuery("")
        assertTrue(m.state.value.showsRecent)
        assertFalse(m.state.value.nothingFound)
        m.setQuery("zzz")
        advanceUntilIdle()
        assertTrue(m.state.value.nothingFound)
    }

    @Test
    fun anOlderAnswerNeverReplacesANewerText() = runTest(StandardTestDispatcher()) {
        val repo = FakeRepository(hits = hits)
        val m = model(repo)
        advanceUntilIdle()
        m.setQuery("pla")
        m.setQuery("plan")
        advanceUntilIdle()
        assertEquals("plan", m.state.value.hitsFor)
    }

    @Test
    fun aDriveInTheResultsOpensAsADriveAndTheIconSearchesInsideIt() = runTest(StandardTestDispatcher()) {
        val repo = FakeRepository(hits = hits)
        val m = model(repo)
        advanceUntilIdle()
        m.setQuery("o")
        advanceUntilIdle()
        val drive = m.state.value.items.first { it.title == "Ontola" }
        assertTrue(m.state.value.isDrive(drive))

        m.searchInDrive(drive.subject)
        advanceUntilIdle()
        // The scope is the drive, the query is searched again inside it.
        assertEquals("did:ad:ontola", m.state.value.scope)
        assertEquals("Ontola", m.state.value.scopeName())
        assertEquals(Triple("o", "did:ad:ontola", emptyList<String>()), repo.searches.last())
        // The drive itself is not a result of its own search.
        assertTrue(m.state.value.items.none { it.title == "Ontola" })

        m.clearScope()
        advanceUntilIdle()
        assertNull(m.state.value.scope)
        assertEquals(null, repo.searches.last().second)
    }

    @Test
    fun aKindFiltersByClassBeforeTheLimitAndClearingItSearchesAgain() = runTest(StandardTestDispatcher()) {
        val repo = FakeRepository(hits = hits)
        val m = model(repo, kind = SearchKind.Chats)
        advanceUntilIdle()
        m.setQuery("pla")
        advanceUntilIdle()
        assertEquals(listOf("aichat"), repo.searches.last().third)
        assertEquals(listOf("Plan the offsite"), m.state.value.items.map { it.title })
        m.clearKind()
        advanceUntilIdle()
        assertEquals(emptyList<String>(), repo.searches.last().third)
        assertEquals(2, m.state.value.items.size)
    }

    @Test
    fun kindsKnowTheirClasses() {
        assertTrue(SearchKind.Drives.matches("Drive"))
        assertTrue(SearchKind.Chats.matches("https://atomicdata.dev/classes/AiChat"))
        assertTrue(SearchKind.Messages.matches("chatroom"))
        assertTrue(SearchKind.Messages.matches("conversation"))
        assertFalse(SearchKind.Messages.matches("DocumentV2"))
        assertTrue(SearchKind.Any.matches("anything"))
    }
}
