package place.atomic.app.kotlin.data

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.core.HomeList

/** What the Home screen shows. A `null` list is still loading. */
data class HomeState(
    val agentName: String = "",
    val sections: Map<Section, List<RowItem>?> = emptyMap(),
    val query: String = "",
    /** `null` while the query is blank. */
    val results: List<RowItem>? = null,
    /** The section opened as a full-height list. */
    val showAll: Section? = null,
) {
    val searching get() = query.isNotBlank()
}

/** Most rows a "Show all" list reads (Flutter: 100). */
private const val ALL_ROWS = 100
private const val SEARCH_ROWS = 50

class HomeViewModel(private val repo: HomeRepository) : ViewModel() {
    private val _state = MutableStateFlow(HomeState(agentName = repo.agent()?.name.orEmpty()))
    val state: StateFlow<HomeState> = _state.asStateFlow()

    private var driveNames: Map<String, String> = emptyMap()
    private var search: Job? = null

    init {
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
                    put(Section.Drives, drives.map { it.toItem() })
                    // Recents and search name the drive; read them with the names.
                    put(Section.Recents, load { repo.list(HomeList.RECENTS, ALL_ROWS) }.map { it.toItem(Section.Recents, driveNames) })
                    if (_state.value.searching) runSearch(_state.value.query)
                }
                for ((list, section) in listOf(
                    HomeList.AI_CHATS to Section.Chats,
                    HomeList.FAVORITES to Section.Favorites,
                    HomeList.MESSAGES to Section.Messages,
                )) {
                    launch { put(section, load { repo.list(list, ALL_ROWS) }.map { it.toItem(section) }) }
                }
            }
        }
    }

    private suspend fun <T> load(read: suspend () -> List<T>): List<T> = runCatching { read() }.getOrDefault(emptyList())

    private fun put(section: Section, rows: List<RowItem>) =
        _state.update { it.copy(sections = it.sections + (section to rows)) }

    /** Search on every keystroke; an older search is dropped when a newer starts. */
    fun setQuery(query: String) {
        _state.update { it.copy(query = query, results = if (query.isBlank()) null else it.results) }
        search?.cancel()
        if (query.isBlank()) return
        search = viewModelScope.launch { runSearch(query) }
    }

    private suspend fun runSearch(query: String) {
        val hits = load { repo.search(query, SEARCH_ROWS) }.map { it.toItem(driveNames) }
        _state.update { if (it.query == query) it.copy(results = hits) else it }
    }

    fun showAll(section: Section?) = _state.update { it.copy(showAll = section) }
}
