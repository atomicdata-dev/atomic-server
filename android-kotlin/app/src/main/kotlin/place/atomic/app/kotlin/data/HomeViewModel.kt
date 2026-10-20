package place.atomic.app.kotlin.data

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.updateAndGet
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.Perf
import place.atomic.app.kotlin.core.HomeList
import place.atomic.app.kotlin.session.KeyValue

/** The AI chats' full list: pages from the host, the next one read near the end of the list. */
data class AllChats(
    val rows: List<RowItem> = emptyList(),
    /** No more pages: the last one was short, or reading one failed. */
    val done: Boolean = false,
    val loading: Boolean = false,
)

/** What the Home screen shows. A `null` list is still loading. */
data class HomeState(
    val agentName: String = "",
    val sections: Map<Section, List<RowItem>?> = emptyMap(),
    /** Which sections show, in which order, and which are folded (per device). */
    val layout: HomeLayout = HomeLayout(),
    /** The activity feed lists the person's own changes too. */
    val showMine: Boolean = false,
    /** The section opened as a full list. */
    val showAll: Section? = null,
    val allChats: AllChats = AllChats(),
    /** The drives, for the Search button's list. */
    val drives: List<place.atomic.app.kotlin.core.DriveRow> = emptyList(),
)

/** Rows a section reads for the Home; the AI chats are a page (Flutter: `chatsPageSize`). */
const val CHATS_PAGE = 50
private const val ALL_ROWS = 100
private const val MAX_ACTIVITY = 100

/** The name a Home list is timed under in `[perf] home <name>` (Flutter's). */
private fun perfName(section: Section) = if (section == Section.Messages) "conversations" else section.name.lowercase()

class HomeViewModel(
    private val repo: HomeRepository,
    /** The layout and the "Show mine" switch are kept here (per device). */
    private val prefs: KeyValue? = null,
) : ViewModel() {
    private val _state = MutableStateFlow(
        HomeState(
            agentName = repo.agent()?.name.orEmpty(),
            layout = prefs?.let(HomeLayout::load) ?: HomeLayout(),
            showMine = prefs?.getString(SHOW_MINE_KEY) == "true",
        ),
    )
    val state: StateFlow<HomeState> = _state.asStateFlow()

    private var driveNames: Map<String, String> = emptyMap()
    private val startedAt = Perf.clock()

    init {
        Perf.mark("home start")
        reload()
        viewModelScope.launch {
            // Bursts of writes (a sync, a seed) are one reload.
            repo.changes().conflate().debounce(150).collect { reload() }
        }
    }

    /** Read every list again; each section shows as soon as its data is in. */
    fun reload() {
        viewModelScope.launch {
            coroutineScope {
                launch {
                    val drives = runCatching { repo.drives() }.getOrDefault(emptyList())
                    driveNames = drives.associate { it.subject to it.name }
                    _state.update { it.copy(drives = drives) }
                    put(Section.Drives, drives.map { it.toItem() })
                }
                launch { put(Section.Activity, load { repo.activity(MAX_ACTIVITY, _state.value.showMine) }.map { it.toItem() }) }
                launch { put(Section.Chats, load { repo.chats(0, CHATS_PAGE) }.map { it.toItem(Section.Chats) }) }
                launch { put(Section.Favorites, load { repo.list(HomeList.FAVORITES, ALL_ROWS) }.map { it.toItem(Section.Favorites) }) }
                launch { put(Section.Messages, load { repo.list(HomeList.MESSAGES, ALL_ROWS) }.map { it.toItem(Section.Messages) }) }
            }
        }
    }

    private suspend fun <T> load(read: suspend () -> List<T>): List<T> = runCatching { read() }.getOrDefault(emptyList())

    private fun put(section: Section, rows: List<RowItem>) {
        // Flutter's `home <list>` spans, and `home data` once every list is in.
        Perf.span("home ${perfName(section)}", Perf.clock() - startedAt)
        val all = _state.updateAndGet { it.copy(sections = it.sections + (section to rows)) }
        if (all.sections.size == Section.entries.size) Perf.once("home data")
    }

    // ── Layout ─────────────────────────────────────────────────────────────

    fun setLayout(layout: HomeLayout) {
        _state.update { it.copy(layout = layout) }
        prefs?.let(layout::save)
    }

    fun toggleCollapsed(section: Section) = setLayout(_state.value.layout.toggleCollapsed(section))

    /** The activity feed's "Show mine" chip; reads the feed again. */
    fun setShowMine(mine: Boolean) {
        if (mine == _state.value.showMine) return
        _state.update { it.copy(showMine = mine) }
        prefs?.putString(SHOW_MINE_KEY, mine.toString())
        viewModelScope.launch {
            put(Section.Activity, load { repo.activity(MAX_ACTIVITY, mine) }.map { it.toItem() })
        }
    }

    // ── Full lists ─────────────────────────────────────────────────────────

    /** Opens a section's full list; the AI chats start with the page the Home has. */
    fun showAll(section: Section?) {
        _state.update {
            it.copy(
                showAll = section,
                allChats = if (section == Section.Chats) {
                    val first = it.sections[Section.Chats].orEmpty()
                    AllChats(first, done = first.size < CHATS_PAGE)
                } else it.allChats,
            )
        }
    }

    /** Reads the next page of AI chats (the list asks near its end); one at a time. */
    fun loadMoreChats() {
        val current = _state.value.allChats
        if (current.loading || current.done) return
        _state.update { it.copy(allChats = it.allChats.copy(loading = true)) }
        viewModelScope.launch {
            val began = Perf.clock()
            val offset = current.rows.size
            val page = runCatching { repo.chats(offset, CHATS_PAGE) }
            Perf.span("chats page $offset+${page.getOrNull()?.size ?: 0}", Perf.clock() - began)
            _state.update {
                val now = it.allChats
                val known = now.rows.mapTo(HashSet()) { r -> r.subject }
                val more = page.getOrNull().orEmpty().map { r -> r.toItem(Section.Chats) }.filter { r -> known.add(r.subject) }
                it.copy(allChats = AllChats(now.rows + more, done = page.isFailure || (page.getOrNull()?.size ?: 0) < CHATS_PAGE, loading = false))
            }
        }
    }

    /** Reads the search index once the first screen is drawn, so the first keystroke is not cold. */
    fun warmSearch() {
        viewModelScope.launch { runCatching { repo.warmSearch() } }
    }

    /** Drive names, for rows that name theirs. */
    fun driveName(drive: String) = driveNames[drive]

    companion object {
        const val SHOW_MINE_KEY = "activity_show_mine"
    }
}
