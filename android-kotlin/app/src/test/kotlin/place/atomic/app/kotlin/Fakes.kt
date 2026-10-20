package place.atomic.app.kotlin

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.emptyFlow
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

val fakeMessages = listOf(
    fakeResource(31, "Anna", "conversation", ago = 8 * MIN, detail = "Can you share the interview notes before the call?"),
    fakeResource(32, "Design team", "conversation", ago = 5 * HOUR, detail = "New icons are in the drive."),
)

class FakeRepository(
    private val drives: List<DriveRow> = fakeDrives,
    private val lists: Map<HomeList, List<ResourceRow>> = mapOf(
        HomeList.RECENTS to fakeRecents,
        HomeList.AI_CHATS to fakeChats,
        HomeList.FAVORITES to fakeFavorites,
        HomeList.MESSAGES to fakeMessages,
    ),
    private val hits: List<SearchHit> = emptyList(),
    val changes: MutableSharedFlow<Unit> = MutableSharedFlow(),
) : HomeRepository {
    val queries = mutableListOf<String>()
    override fun agent() = AgentInfo("secret", "did:ad:agent:x", "x", "Joep")
    override suspend fun drives() = drives
    override suspend fun list(which: HomeList, limit: Int) = lists[which].orEmpty().take(limit)
    override suspend fun search(query: String, limit: Int): List<SearchHit> {
        queries += query
        return hits.filter { it.title.contains(query, ignoreCase = true) }
    }

    override fun changes(): Flow<Unit> = changes
}

/** The state the screenshot tests draw: what the fake repository gives, mapped as the view model does. */
fun fakeHomeState(now: Long = NOW): HomeState {
    val names = fakeDrives.associate { it.subject to it.name }
    fun rows(list: List<ResourceRow>, s: Section) = list.map { it.toItem(s, names, now) }
    return HomeState(
        agentName = "Joep",
        sections = mapOf(
            Section.Drives to fakeDrives.map { it.toItem() },
            Section.Recents to rows(fakeRecents, Section.Recents),
            Section.Chats to rows(fakeChats, Section.Chats),
            Section.Favorites to rows(fakeFavorites, Section.Favorites),
            Section.Messages to rows(fakeMessages, Section.Messages),
        ),
    )
}
