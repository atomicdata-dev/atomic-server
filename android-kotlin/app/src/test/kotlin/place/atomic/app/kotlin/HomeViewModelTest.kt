package place.atomic.app.kotlin

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import place.atomic.app.kotlin.core.SearchHit
import place.atomic.app.kotlin.data.HOME_ROWS
import place.atomic.app.kotlin.data.HomeViewModel
import place.atomic.app.kotlin.data.Section

@OptIn(ExperimentalCoroutinesApi::class)
class HomeViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @Before
    fun setUp() = Dispatchers.setMain(dispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    @Test
    fun everySectionLoadsAndRecentsNameTheirDrive() = runTest(dispatcher) {
        val vm = HomeViewModel(FakeRepository())
        advanceUntilIdle()
        val s = vm.state.value
        assertEquals("Joep", s.agentName)
        assertEquals(Section.entries.toSet(), s.sections.keys)
        assertEquals(3, s.sections[Section.Drives]!!.size)
        assertEquals(6, s.sections[Section.Recents]!!.size)
        assertTrue(s.sections[Section.Recents]!![1].detail.startsWith("Ontola · Folder"))
        assertEquals("Anna", s.sections[Section.Messages]!![0].title)
    }

    @Test
    fun aSectionWithMoreThanFourRowsKeepsAllOfThemForShowAll() = runTest(dispatcher) {
        val vm = HomeViewModel(FakeRepository())
        advanceUntilIdle()
        assertTrue(vm.state.value.sections[Section.Recents]!!.size > HOME_ROWS)
        vm.showAll(Section.Recents)
        assertEquals(Section.Recents, vm.state.value.showAll)
        vm.showAll(null)
        assertNull(vm.state.value.showAll)
    }

    @Test
    fun searchRunsOnEveryKeystrokeAndBlankClearsIt() = runTest(dispatcher) {
        val repo = FakeRepository(hits = listOf(SearchHit("s1", "Pasta al limone", "DocumentV2", null, "did:ad:recipes", 1.0)))
        val vm = HomeViewModel(repo)
        advanceUntilIdle()
        for (typed in listOf("p", "pa", "pas")) {
            vm.setQuery(typed)
            advanceUntilIdle()
        }
        assertEquals(listOf("p", "pa", "pas"), repo.queries)
        val results = vm.state.value.results!!
        assertEquals("Pasta al limone", results.single().title)
        assertEquals("Recipes · Document", results.single().detail)

        vm.setQuery("  ")
        advanceUntilIdle()
        assertNull(vm.state.value.results)
        assertEquals(3, repo.queries.size) // a blank query is not searched
    }

    @Test
    fun aStoreChangeReloadsTheListsOnce() = runTest(dispatcher) {
        val repo = FakeRepository()
        val vm = HomeViewModel(repo)
        advanceUntilIdle()
        repeat(5) { repo.changes.emit(Unit) }
        advanceTimeBy(500)
        advanceUntilIdle()
        assertTrue(vm.state.value.sections[Section.Drives] != null)
    }
}
