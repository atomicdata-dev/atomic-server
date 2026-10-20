package place.atomic.app.kotlin.data

import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import place.atomic.app.kotlin.core.ActivityRow
import place.atomic.app.kotlin.core.AgentInfo
import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.core.HomeList
import place.atomic.app.kotlin.core.ResourceRow
import place.atomic.app.kotlin.core.SearchHit
import place.atomic.app.kotlin.core.StoreEvent
import place.atomic.app.kotlin.core.StoreListener
import place.atomic.app.kotlin.core.activeAgent
import place.atomic.app.kotlin.core.aiChatsPage
import place.atomic.app.kotlin.core.homeList
import place.atomic.app.kotlin.core.listActivity
import place.atomic.app.kotlin.core.listDrives
import place.atomic.app.kotlin.core.search
import place.atomic.app.kotlin.core.subscribeEvents
import place.atomic.app.kotlin.core.warmSearch

/** What the Home screen and the search read. The real one is the Rust core, tests fake it. */
interface HomeRepository {
    fun agent(): AgentInfo?

    /** The agent's drives: the active one first, then the most recently used. */
    suspend fun drives(): List<DriveRow>
    suspend fun list(which: HomeList, limit: Int): List<ResourceRow>

    /** [limit] AI chats after the [offset] newest; a page shorter than [limit] is the last. */
    suspend fun chats(offset: Int, limit: Int): List<ResourceRow>

    /** What others changed lately, and with [includeOwn] what the person changed too. */
    suspend fun activity(limit: Int, includeOwn: Boolean): List<ActivityRow>

    /** Search all drives, or only [drive]; [classes] keep one kind (`drive`, `aichat`, `conversation`, `chatroom`). */
    suspend fun search(query: String, limit: Int, drive: String? = null, classes: List<String> = emptyList()): List<SearchHit>

    /** Reads the search index once so the first keystroke is not cold. */
    suspend fun warmSearch()

    /** Emits when the store changed, so lists can be read again. */
    fun changes(): Flow<Unit>
}

class CoreHomeRepository : HomeRepository {
    override fun agent(): AgentInfo? = activeAgent()
    override suspend fun drives() = listDrives()
    override suspend fun list(which: HomeList, limit: Int) = homeList(which, limit.toUInt())
    override suspend fun chats(offset: Int, limit: Int) = aiChatsPage(limit.toUInt(), offset.toUInt())
    override suspend fun activity(limit: Int, includeOwn: Boolean) = listActivity(limit.toUInt(), includeOwn)
    override suspend fun search(query: String, limit: Int, drive: String?, classes: List<String>) =
        search(query, limit.toUInt(), drive, classes)
    override suspend fun warmSearch() = place.atomic.app.kotlin.core.warmSearch()

    override fun changes(): Flow<Unit> = callbackFlow {
        val subscription = subscribeEvents(object : StoreListener {
            override fun onEvent(event: StoreEvent) {
                trySend(Unit)
            }
        })
        awaitClose { subscription.cancel() }
    }
}
