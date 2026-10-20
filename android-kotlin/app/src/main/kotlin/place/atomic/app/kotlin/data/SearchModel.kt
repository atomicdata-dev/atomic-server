package place.atomic.app.kotlin.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.Perf
import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.core.HomeList
import place.atomic.app.kotlin.ui.classLabel

/** What a search looks for: anything, or one kind (a chip next to the field). Flutter's `SearchKind`. */
enum class SearchKind(val label: String, val hint: String, val heading: String, val classes: List<String>) {
    Any("", "Search", "Recently opened", emptyList()),
    Drives("Drives", "Search drives", "Drives", listOf("drive")),
    Chats("AI chats", "Search AI chats", "AI chats", listOf("aichat")),
    Messages("Messages", "Search messages", "Messages", listOf("conversation", "chatroom"));

    /** Whether a resource of [className] (a shortname or class URL) is of this kind. */
    fun matches(className: String): Boolean {
        val key = className.split('/', '#').last().lowercase().replace(Regex("[^a-z0-9]"), "")
        return when (this) {
            Any -> true
            Drives -> key == "drive"
            Chats -> key == "aichat"
            Messages -> key == "conversation" || key == "chatroom"
        }
    }
}

/** One line of the results: a hit, a recently opened resource, or a member of the kind looked for. */
data class SearchItem(
    val subject: String,
    val title: String,
    val className: String,
    val drive: String,
    /** The drive the row names ("" for a row that does not). */
    val shown: String = "",
    val emoji: String? = null,
)

data class SearchState(
    val query: String = "",
    /** The one drive searched, or null for all of them. */
    val scope: String? = null,
    val kind: SearchKind = SearchKind.Any,
    val drives: List<DriveRow> = emptyList(),
    val recent: List<SearchItem> = emptyList(),
    /** Every resource of [kind], listed before anything is typed; null until read. */
    val ofKind: List<SearchItem>? = null,
    val hits: List<SearchItem> = emptyList(),
    /** The query [hits] answer (they lag the field while a search runs). */
    val hitsFor: String = "",
    val error: String? = null,
) {
    /** The list shows what was opened (or the kind) instead of hits: nothing typed, or no answer yet. */
    val showsRecent get() = query.isEmpty() || hitsFor.isEmpty()

    /** What is listed, best first. */
    val items: List<SearchItem>
        get() = when {
            showsRecent && kind != SearchKind.Any -> ofKind.orEmpty()
            showsRecent -> recent
            else -> hits.filter { (scope == null || !sameDrive(it.subject, scope)) && kind.matches(it.className) }
        }

    val nothingFound get() = items.isEmpty() && query.isNotEmpty() && hitsFor == query

    fun isDrive(item: SearchItem) = kind == SearchKind.Drives || item.className.split('/', '#').last() == "Drive" ||
        drives.any { sameDrive(it.subject, item.subject) }

    /** `<class> · <drive name>`: every result says which drive it is in. */
    fun detail(item: SearchItem): String {
        val name = item.shown.takeIf { it.isNotEmpty() }?.let { d -> drives.firstOrNull { sameDrive(it.subject, d) }?.name }
        return listOfNotNull(classLabel(item.className).ifEmpty { null }, name?.ifEmpty { null }).joinToString(" · ")
    }

    fun scopeName(): String? = scope?.let { s -> drives.firstOrNull { sameDrive(it.subject, s) }?.name?.ifEmpty { null } ?: "this drive" }
}

/** The same drive may be spelled `did:ad:x` or `atomic:x`. */
fun sameDrive(a: String, b: String) = a.removePrefix("did:ad:").removePrefix("atomic:") == b.removePrefix("did:ad:").removePrefix("atomic:")

/**
 * The type-ahead search over every drive, one drive ([scope]) or one kind of
 * resource, as Flutter's `SearchScreen` runs it: searched at once on every
 * keystroke, a newer text replaces an older search, the kind is chosen in the
 * index (before the result limit), and before anything is typed the list shows
 * what was opened lately or every resource of the kind.
 */
class SearchModel(
    private val repo: HomeRepository,
    private val scope: CoroutineScope,
    scopeDrive: String? = null,
    kind: SearchKind = SearchKind.Any,
    initialQuery: String = "",
) {
    private val _state = MutableStateFlow(SearchState(scope = scopeDrive, kind = kind))
    val state: StateFlow<SearchState> = _state.asStateFlow()
    private var search: Job? = null

    init {
        scope.launch {
            val drives = runCatching { repo.drives() }.getOrDefault(emptyList())
            _state.update { it.copy(drives = drives) }
            loadRecent()
            loadKind()
        }
        if (initialQuery.isNotBlank()) setQuery(initialQuery)
    }

    private suspend fun loadRecent() {
        val scopeDrive = _state.value.scope
        val rows = runCatching { repo.list(HomeList.RECENTS, 100) }.getOrDefault(emptyList())
        val recent = rows
            .filter { scopeDrive == null || sameDrive(it.drive, scopeDrive) }
            .take(20)
            .map { SearchItem(it.subject, it.title, it.className, it.drive, shown = it.drive, emoji = it.emoji) }
        _state.update { if (it.scope == scopeDrive) it.copy(recent = recent) else it }
    }

    /** Every resource of the kind looked for, for the list before anything is typed. */
    private suspend fun loadKind() {
        val kind = _state.value.kind
        val items: List<SearchItem>? = when (kind) {
            SearchKind.Any -> null
            SearchKind.Drives -> _state.value.drives.map { SearchItem(it.subject, it.name.ifEmpty { "Untitled drive" }, "Drive", it.subject, emoji = it.emoji) }
            SearchKind.Messages -> runCatching { repo.list(HomeList.MESSAGES, 100) }.getOrDefault(emptyList())
                .map { SearchItem(it.subject, it.title, it.className.ifEmpty { "conversation" }, it.drive, emoji = it.emoji) }
            SearchKind.Chats -> {
                // The first page shows at once, the rest joins it as the pages arrive.
                val items = mutableListOf<SearchItem>()
                val known = HashSet<String>()
                while (true) {
                    val page = runCatching { repo.chats(known.size, CHATS_PAGE * 4) }.getOrDefault(emptyList())
                    for (c in page) if (known.add(c.subject)) items += SearchItem(c.subject, c.title.ifEmpty { "Untitled chat" }, "ai-chat", c.drive)
                    if (_state.value.kind != kind) return
                    if (page.size < CHATS_PAGE * 4) break
                    _state.update { it.copy(ofKind = items.toList()) }
                }
                items
            }
        }
        _state.update { if (it.kind == kind) it.copy(ofKind = items) else it }
    }

    fun setQuery(text: String) {
        Perf.typed()
        val query = text.trim()
        if (query == _state.value.query) return
        _state.update {
            it.copy(query = query, hits = if (query.isEmpty()) emptyList() else it.hits, hitsFor = if (query.isEmpty()) "" else it.hitsFor)
        }
        search?.cancel()
        if (query.isEmpty()) return
        search = scope.launch { runSearch() }
    }

    private suspend fun runSearch() {
        val (query, scopeDrive, kind) = _state.value.let { Triple(it.query, it.scope, it.kind) }
        val began = Perf.clock()
        val result = runCatching { repo.search(query, 50, scopeDrive, kind.classes) }
        Perf.span("search query", Perf.clock() - began)
        _state.update {
            // Stale: the text, the drive or the kind changed while it ran.
            if (it.query != query || it.scope != scopeDrive || it.kind != kind) it
            else result.fold(
                { hits ->
                    it.copy(
                        hits = hits.map { h -> SearchItem(h.subject, h.title, h.className, h.drive.ifEmpty { "" }, shown = h.drive, emoji = h.emoji) },
                        hitsFor = query,
                        error = null,
                    )
                },
                { e -> it.copy(error = e.message ?: e.toString(), hitsFor = query) },
            )
        }
    }

    /** Back to every drive: the query is searched again. */
    fun clearScope() {
        _state.update { it.copy(scope = null, hits = emptyList(), hitsFor = "") }
        scope.launch { loadRecent() }
        if (_state.value.query.isNotEmpty()) search = scope.launch { runSearch() }
    }

    /** Back to every kind: the query is searched again. */
    fun clearKind() {
        _state.update { it.copy(kind = SearchKind.Any, ofKind = null, hits = emptyList(), hitsFor = "") }
        if (_state.value.query.isNotEmpty()) search = scope.launch { runSearch() }
    }

    /** The explicit "search in this drive" of a drive in the results: the search goes on inside it. */
    fun searchInDrive(drive: String) {
        if (drive.isEmpty()) return
        val current = _state.value.scope
        if (current != null && sameDrive(current, drive)) return
        val query = _state.value.query
        _state.update { it.copy(scope = drive, query = "", hits = emptyList(), hitsFor = "", recent = emptyList()) }
        search?.cancel()
        scope.launch { loadRecent() }
        if (query.isNotEmpty()) setQuery(query)
    }

    /** The first row, the one Enter opens. */
    fun best(): SearchItem? = _state.value.items.firstOrNull()
}
