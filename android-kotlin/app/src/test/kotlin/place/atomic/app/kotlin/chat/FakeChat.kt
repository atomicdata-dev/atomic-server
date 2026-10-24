package place.atomic.app.kotlin.chat

import kotlinx.coroutines.flow.flow
import org.json.JSONArray
import org.json.JSONObject
import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.core.ResourceRow
import place.atomic.app.kotlin.core.ThreadMessage

/** The chat part of the core, in memory. */
class FakeChat : ChatBackend {
    val chats = mutableMapOf<String, MutableList<ChatEntry>>()
    val created = mutableListOf<String>()
    var failAdd: Exception? = null
    var driveRows = listOf(DriveRow("did:ad:drive", "Pelican's Drive", null))
    var recentRows = listOf(ResourceRow("did:ad:doc", "Trip", "document", null, "did:ad:drive", 1, ""))

    override suspend fun aiPage(chat: String, before: String?, limit: Int): ChatPage<ChatEntry> {
        val all = chats[chat].orEmpty()
        val end = before?.let { b -> all.indexOfFirst { it.id == b } } ?: all.size
        val start = maxOf(0, end - limit)
        val items = all.subList(start, end).toList()
        return ChatPage(items, if (start > 0) items.first().id else null, items.lastOrNull()?.id)
    }

    override suspend fun aiAfter(chat: String, after: String, limit: Int): ChatPage<ChatEntry> {
        val all = chats[chat].orEmpty()
        val from = all.indexOfFirst { it.id == after } + 1
        val items = all.drop(from).take(limit)
        return ChatPage(items, null, items.lastOrNull()?.id ?: after, more = from + items.size < all.size)
    }

    override suspend fun newChat(name: String): String {
        created += name
        return "did:ad:chat${created.size}".also { chats[it] = mutableListOf() }
    }

    override suspend fun addEntry(chat: String, entry: ChatEntry) {
        failAdd?.let { throw it }
        chats.getValue(chat) += entry.copy(id = "e${chats.getValue(chat).size}")
    }

    var thread = FakeThread()
    override fun conversation(subject: String): ThreadSource = thread
    override fun room(subject: String): ThreadSource = thread
    val renamed = mutableListOf<Pair<String, String>>()
    override suspend fun rename(subject: String, name: String) {
        renamed += subject to name
    }

    override suspend fun drives() = driveRows
    override suspend fun recents(limit: Int) = recentRows
    override suspend fun search(query: String, limit: Int) = listOf(DataReader.Hit("did:ad:doc", "Trip", "document"))
    override suspend fun resourceText(subject: String, maxChars: Int) = "Text of $subject"
}

class FakeThread(var messages: MutableList<ThreadMessage> = mutableListOf()) : ThreadSource {
    var sendError: Exception? = null
    val sent = mutableListOf<String>()
    var followed = 0

    override suspend fun page(before: String?, limit: Int): ChatPage<ThreadMessage> {
        val end = before?.let { b -> messages.indexOfFirst { it.id == b } } ?: messages.size
        val start = maxOf(0, end - limit)
        val items = messages.subList(start, end).toList()
        return ChatPage(items, if (start > 0) items.first().id else null, items.lastOrNull()?.id)
    }

    override suspend fun after(after: String, limit: Int): ChatPage<ThreadMessage> {
        val from = messages.indexOfFirst { it.id == after } + 1
        val items = messages.drop(from).take(limit)
        return ChatPage(items, null, items.lastOrNull()?.id ?: after, more = from + items.size < messages.size)
    }

    override suspend fun send(text: String) {
        sendError?.let { throw it }
        sent += text
        messages += message("s${messages.size}", text, mine = true)
    }

    override suspend fun follow() {
        followed++
    }
}

fun message(id: String, text: String, mine: Boolean = false, name: String = "Robin", at: Long = 1_000, event: Boolean = false) =
    ThreadMessage(id, if (mine) "did:ad:agent:me" else "did:ad:agent:robin", if (mine) "Me" else name, mine, text, at, null, event, null, "")

/** Completions that answer with [rounds], one per request. */
fun scripted(vararg rounds: List<String>, sent: MutableList<JSONArray> = mutableListOf()): Completions {
    var n = 0
    return { messages, _, _ ->
        sent += JSONArray(messages.toString())
        val words = rounds[minOf(n++, rounds.size - 1)]
        flow {
            words.forEach {
                emit(JSONObject().put("choices", JSONArray().put(JSONObject().put("delta", JSONObject().put("content", it)))))
            }
        }
    }
}

fun readyAi(completions: Completions) =
    HostedAi(JSONObject().put("enabled", true).put("consent", true).put("model", "m"), completions, { JSONObject() })
