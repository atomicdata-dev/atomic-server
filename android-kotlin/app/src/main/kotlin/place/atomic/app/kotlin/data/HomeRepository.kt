package place.atomic.app.kotlin.data

import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import place.atomic.app.kotlin.core.AgentInfo
import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.core.HomeList
import place.atomic.app.kotlin.core.ResourceRow
import place.atomic.app.kotlin.core.SearchHit
import place.atomic.app.kotlin.core.StoreEvent
import place.atomic.app.kotlin.core.StoreListener
import place.atomic.app.kotlin.core.activeAgent
import place.atomic.app.kotlin.core.homeList
import place.atomic.app.kotlin.core.listDrives
import place.atomic.app.kotlin.core.search
import place.atomic.app.kotlin.core.subscribeEvents

/** What the Home screen reads. The real one is the Rust core, tests fake it. */
interface HomeRepository {
    fun agent(): AgentInfo?
    suspend fun drives(): List<DriveRow>
    suspend fun list(which: HomeList, limit: Int): List<ResourceRow>
    suspend fun search(query: String, limit: Int): List<SearchHit>

    /** Emits when the store changed, so lists can be read again. */
    fun changes(): Flow<Unit>
}

class CoreHomeRepository : HomeRepository {
    override fun agent(): AgentInfo? = activeAgent()
    override suspend fun drives() = listDrives()
    override suspend fun list(which: HomeList, limit: Int) = homeList(which, limit.toUInt())
    override suspend fun search(query: String, limit: Int) = search(query, limit.toUInt())

    override fun changes(): Flow<Unit> = callbackFlow {
        val subscription = subscribeEvents(object : StoreListener {
            override fun onEvent(event: StoreEvent) {
                trySend(Unit)
            }
        })
        awaitClose { subscription.cancel() }
    }
}
