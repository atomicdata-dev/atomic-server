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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import place.atomic.app.kotlin.data.CHATS_PAGE
import place.atomic.app.kotlin.data.HOME_ROWS
import place.atomic.app.kotlin.data.HomeLayout
import place.atomic.app.kotlin.data.HomeViewModel
import place.atomic.app.kotlin.data.Section

@OptIn(ExperimentalCoroutinesApi::class)
class HomeViewModelTest {
    private val dispatcher = StandardTestDispatcher()
    private val lines = mutableListOf<String>()
    private var wasEnabled = true

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
        wasEnabled = Perf.enabled
        Perf.enabled = true
        Perf.sink = { lines += it }
        Perf.reset()
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        Perf.enabled = wasEnabled
        Perf.reset()
    }

    @Test
    fun everySectionLoadsAndRowsNameTheirDrive() = runTest(dispatcher) {
        val vm = HomeViewModel(FakeRepository())
        advanceUntilIdle()
        val s = vm.state.value
        assertEquals("Joep", s.agentName)
        assertEquals(Section.entries.toSet(), s.sections.keys)
        assertEquals(3, s.sections[Section.Drives]!!.size)
        assertEquals(3, s.drives.size)
        assertTrue(s.sections[Section.Favorites]!![1].detail.startsWith("Ontola · Table"))
        assertEquals("Anna", s.sections[Section.Messages]!![0].title)
    }

    @Test
    fun theActivityFeedHidesTheOwnChangesUntilShowMineIsOn() = runTest(dispatcher) {
        val repo = FakeRepository()
        val vm = HomeViewModel(repo)
        advanceUntilIdle()
        val others = vm.state.value.sections[Section.Activity]!!
        assertEquals(listOf("Quarterly planning", "Customer interviews", "Old draft"), others.map { it.title })
        assertEquals("Anna edited · 4 min ago", others[0].detail)
        // A deleted resource is listed, but there is nothing to open.
        assertFalse(others[2].openable)

        vm.setShowMine(true)
        advanceUntilIdle()
        assertTrue(vm.state.value.showMine)
        assertEquals(4, vm.state.value.sections[Section.Activity]!!.size)
        assertEquals(true, repo.activityCalls.last())
    }

    @Test
    fun layoutAndShowMineAreKeptAndComeBack() = runTest(dispatcher) {
        val prefs = MapKeyValue()
        val vm = HomeViewModel(FakeRepository(), prefs)
        advanceUntilIdle()
        vm.setLayout(vm.state.value.layout.setHidden(Section.Messages, true).toggleCollapsed(Section.Drives).reorder(0, 2))
        vm.setShowMine(true)
        advanceUntilIdle()

        val again = HomeViewModel(FakeRepository(), prefs)
        val s = again.state.value
        assertEquals(listOf(Section.Activity, Section.Chats, Section.Drives, Section.Favorites), s.layout.visible)
        assertEquals(setOf(Section.Drives), s.layout.collapsed)
        assertTrue(s.showMine)
        assertEquals(HomeLayout(), HomeViewModel(FakeRepository(), MapKeyValue()).state.value.layout)
    }

    @Test
    fun aSectionWithMoreThanFourRowsKeepsAllOfThemForShowAll() = runTest(dispatcher) {
        val vm = HomeViewModel(FakeRepository(chats = (1..6).map { fakeResource(it, "Chat $it", "AiChat") }))
        advanceUntilIdle()
        assertTrue(vm.state.value.sections[Section.Chats]!!.size > HOME_ROWS)
        vm.showAll(Section.Chats)
        assertEquals(Section.Chats, vm.state.value.showAll)
        assertEquals(6, vm.state.value.allChats.rows.size)
        assertTrue(vm.state.value.allChats.done)
        vm.showAll(null)
        assertNull(vm.state.value.showAll)
    }

    @Test
    fun theAiChatsComePagedByOffsetAndTheNextPageIsOnlyReadOnce() = runTest(dispatcher) {
        val all = (1..CHATS_PAGE + 20).map { fakeResource(it, "Chat $it", "AiChat", ago = it * 1_000L) }
        val repo = FakeRepository(chats = all)
        val vm = HomeViewModel(repo)
        advanceUntilIdle()
        assertEquals(listOf(0 to CHATS_PAGE), repo.chatPages)
        vm.showAll(Section.Chats)
        assertFalse(vm.state.value.allChats.done)
        assertEquals(CHATS_PAGE, vm.state.value.allChats.rows.size)

        // Asked for twice while the page is on its way: one read.
        vm.loadMoreChats()
        vm.loadMoreChats()
        advanceUntilIdle()
        assertEquals(listOf(0 to CHATS_PAGE, CHATS_PAGE to CHATS_PAGE), repo.chatPages)
        val rows = vm.state.value.allChats
        assertEquals(CHATS_PAGE + 20, rows.rows.size)
        assertTrue(rows.done)
        assertEquals(rows.rows.size, rows.rows.map { it.subject }.toSet().size)
        // Nothing more to read once the last page was short.
        vm.loadMoreChats()
        advanceUntilIdle()
        assertEquals(2, repo.chatPages.size)
        assertTrue(lines.any { it.startsWith("[perf] chats page $CHATS_PAGE+20 ") })
    }

    @Test
    fun theHomeListsAreTimedLikeFluttersAndHomeDataComesOnce() = runTest(dispatcher) {
        HomeViewModel(FakeRepository())
        advanceUntilIdle()
        val names = lines.map { it.removePrefix("[perf] ").substringBefore(" ms").substringBeforeLast(' ') }
        for (n in listOf("home drives", "home activity", "home chats", "home favorites", "home conversations", "home data")) {
            assertTrue("$n in $names", n in names)
        }
        assertEquals(1, names.count { it == "home data" })
    }

    @Test
    fun warmSearchReadsTheIndexOnce() = runTest(dispatcher) {
        val repo = FakeRepository()
        val vm = HomeViewModel(repo)
        advanceUntilIdle()
        vm.warmSearch()
        advanceUntilIdle()
        assertEquals(1, repo.warmed)
    }

    @Test
    fun aStoreChangeReloadsTheListsOnce() = runTest(dispatcher) {
        val repo = FakeRepository()
        val vm = HomeViewModel(repo)
        advanceUntilIdle()
        val before = repo.chatPages.size
        repeat(5) { repo.changes.emit(Unit) }
        advanceTimeBy(500)
        advanceUntilIdle()
        assertEquals(before + 1, repo.chatPages.size)
    }
}
