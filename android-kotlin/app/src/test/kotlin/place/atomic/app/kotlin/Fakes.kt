package place.atomic.app.kotlin

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.emptyFlow
import place.atomic.app.kotlin.core.ActivityRow
import place.atomic.app.kotlin.core.AgentInfo
import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.core.HomeList
import place.atomic.app.kotlin.core.ResourceRow
import place.atomic.app.kotlin.core.SearchHit
import place.atomic.app.kotlin.data.HomeRepository
import place.atomic.app.kotlin.data.toItem
import place.atomic.app.kotlin.data.Section
import place.atomic.app.kotlin.data.HomeState

const val NOW = 1_760_000_000_000L
private const val MIN = 60_000L
private const val HOUR = 60 * MIN

val fakeDrives = listOf(
    DriveRow("did:ad:home", "Joep's Drive", "🏠"),
    DriveRow("did:ad:ontola", "Ontola", null),
    DriveRow("did:ad:recipes", "Recipes", "🍲"),
)

fun fakeResource(i: Int, title: String, className: String, drive: String = "did:ad:home", ago: Long = i * HOUR, emoji: String? = null, detail: String = "") =
    ResourceRow("did:ad:res$i", title, className, emoji, drive, NOW - ago, detail)

val fakeRecents = listOf(
    fakeResource(1, "Quarterly planning", "DocumentV2", ago = 5 * MIN),
    fakeResource(2, "Customer interviews", "folder", "did:ad:ontola", ago = 2 * HOUR),
    fakeResource(3, "Pasta al limone", "DocumentV2", "did:ad:recipes", ago = 20 * HOUR, emoji = "🍋"),
    fakeResource(4, "Roadmap", "table", "did:ad:ontola", ago = 30 * HOUR),
    fakeResource(5, "Whiteboard", "canvas", ago = 80 * HOUR),
    fakeResource(6, "Release notes", "DocumentV2", "did:ad:ontola", ago = 9 * 24 * HOUR),
)

val fakeChats = listOf(
    fakeResource(11, "Plan the offsite", "AiChat", ago = 12 * MIN),
    fakeResource(12, "Summarise the interviews", "AiChat", ago = 3 * HOUR),
    fakeResource(13, "Rust lifetimes explained", "AiChat", ago = 26 * HOUR),
)

val fakeFavorites = listOf(
    fakeResource(21, "Quarterly planning", "DocumentV2", ago = 0),
    fakeResource(22, "Roadmap", "table", "did:ad:ontola", ago = 0),
)

val fakeActivity = listOf(
    ActivityRow("did:ad:res1", "did:ad:home", "changed", NOW - 4 * MIN, "Anna", "Quarterly planning", "DocumentV2"),
    ActivityRow("did:ad:res2", "did:ad:ontola", "created", NOW - 3 * HOUR, "Bram", "Customer interviews", "folder"),
    ActivityRow("did:ad:res9", "did:ad:ontola", "deleted", NOW - 30 * HOUR, "Anna", "Old draft", "DocumentV2"),
    ActivityRow("did:ad:res4", "did:ad:ontola", "changed", NOW - 2 * HOUR, "You", "Roadmap", "table"),
)

val fakeMessages = listOf(
    fakeResource(31, "Anna", "conversation", ago = 8 * MIN, detail = "Can you share the interview notes before the call?"),
    fakeResource(32, "Design team", "conversation", ago = 5 * HOUR, detail = "New icons are in the drive."),
)

class FakeRepository(
    private val drives: List<DriveRow> = fakeDrives,
    private val lists: Map<HomeList, List<ResourceRow>> = mapOf(
        HomeList.FAVORITES to fakeFavorites,
        HomeList.MESSAGES to fakeMessages,
    ),
    private val chats: List<ResourceRow> = fakeChats,
    private val activity: List<ActivityRow> = fakeActivity,
    private val hits: List<SearchHit> = emptyList(),
    val changes: MutableSharedFlow<Unit> = MutableSharedFlow(),
) : HomeRepository {
    val queries = mutableListOf<String>()
    /** Every search as (query, drive, classes). */
    val searches = mutableListOf<Triple<String, String?, List<String>>>()
    val chatPages = mutableListOf<Pair<Int, Int>>()
    val activityCalls = mutableListOf<Boolean>()
    var warmed = 0
    override fun agent() = AgentInfo("secret", "did:ad:agent:x", "x", "Joep")
    override suspend fun drives() = drives
    override suspend fun list(which: HomeList, limit: Int) = lists[which].orEmpty().take(limit)
    override suspend fun chats(offset: Int, limit: Int): List<ResourceRow> {
        chatPages += offset to limit
        return chats.drop(offset).take(limit)
    }

    override suspend fun activity(limit: Int, includeOwn: Boolean): List<ActivityRow> {
        activityCalls += includeOwn
        return activity.filter { includeOwn || it.actor != "You" }.take(limit)
    }

    override suspend fun search(query: String, limit: Int, drive: String?, classes: List<String>): List<SearchHit> {
        queries += query
        searches += Triple(query, drive, classes)
        return hits.filter { it.title.contains(query, ignoreCase = true) && (drive == null || it.drive == drive) }
    }

    override suspend fun warmSearch() {
        warmed++
    }

    override fun changes(): Flow<Unit> = changes
}

/** The state the screenshot tests draw: what the fake repository gives, mapped as the view model does. */
fun fakeHomeState(now: Long = NOW, showMine: Boolean = false): HomeState {
    val names = fakeDrives.associate { it.subject to it.name }
    fun rows(list: List<ResourceRow>, s: Section) = list.map { it.toItem(s, names, now) }
    return HomeState(
        agentName = "Joep",
        sections = mapOf(
            Section.Drives to fakeDrives.map { it.toItem() },
            Section.Activity to fakeActivity.filter { showMine || it.actor != "You" }.map { it.toItem(now) },
            Section.Chats to rows(fakeChats, Section.Chats),
            Section.Favorites to rows(fakeFavorites, Section.Favorites),
            Section.Messages to rows(fakeMessages, Section.Messages),
        ),
        showMine = showMine,
        drives = fakeDrives,
    )
}
