package place.atomic.app.kotlin.chat

import place.atomic.app.kotlin.core.DriveRow
import place.atomic.app.kotlin.core.HomeList
import place.atomic.app.kotlin.core.ResourceRow
import place.atomic.app.kotlin.core.ThreadMessage

/**
 * One conversation or chat room, read and written as a list of [ThreadMessage]s
 * in windows. [CoreChatBackend] makes them from the Rust core; tests make their own.
 */
interface ThreadSource {
    suspend fun page(before: String?, limit: Int): ChatPage<ThreadMessage>
    suspend fun after(after: String, limit: Int): ChatPage<ThreadMessage>
    suspend fun send(text: String)

    /** Fetch the thread onto this device and follow it (a conversation). Best effort. */
    suspend fun follow() {}
}

/**
 * Everything the chat screens ask of the Rust core, so the JVM tests (where the
 * native library does not load) can answer for it. The twin of Flutter's
 * `AssistantApi`, only the chat part of it.
 */
interface ChatBackend : DataReader {
    suspend fun aiPage(chat: String, before: String?, limit: Int): ChatPage<ChatEntry>
    suspend fun aiAfter(chat: String, after: String, limit: Int): ChatPage<ChatEntry>

    /** Starts an AI chat named [name]; returns its subject. */
    suspend fun newChat(name: String): String

    /** Adds [entry] to [chat] in the web app's format (its parts and the resources attached to it). */
    suspend fun addEntry(chat: String, entry: ChatEntry)

    fun conversation(subject: String): ThreadSource
    fun room(subject: String): ThreadSource
    suspend fun rename(subject: String, name: String)

    suspend fun drives(): List<DriveRow>

    /** What this device opened lately in all drives, newest first. */
    suspend fun recents(limit: Int): List<ResourceRow>
}

/** The real one. */
object CoreChatBackend : ChatBackend {
    private fun page(p: place.atomic.app.kotlin.core.ThreadPage) = ChatPage(p.messages, p.older, p.newest, p.more)

    override suspend fun aiPage(chat: String, before: String?, limit: Int) =
        place.atomic.app.kotlin.core.readAiChatPage(chat, before, limit.toUInt()).let { p ->
            ChatPage(p.entries.map(ChatEntry::of), p.older, p.newest, p.more)
        }

    override suspend fun aiAfter(chat: String, after: String, limit: Int) =
        place.atomic.app.kotlin.core.readAiChatAfter(chat, after, limit.toUInt()).let { p ->
            ChatPage(p.entries.map(ChatEntry::of), p.older, p.newest, p.more)
        }

    override suspend fun newChat(name: String) = place.atomic.app.kotlin.core.createAiChat(name)

    override suspend fun addEntry(chat: String, entry: ChatEntry) {
        place.atomic.app.kotlin.core.appendAiChatEntry(chat, entry.role, entry.partsJson, entry.contextJson)
    }

    override fun conversation(subject: String) = object : ThreadSource {
        override suspend fun page(before: String?, limit: Int) = page(place.atomic.app.kotlin.core.readConversationPage(subject, before, limit.toUInt()))
        override suspend fun after(after: String, limit: Int) = page(place.atomic.app.kotlin.core.readConversationAfter(subject, after, limit.toUInt()))
        override suspend fun send(text: String) {
            place.atomic.app.kotlin.core.sendConversationMessage(subject, text)
        }

        override suspend fun follow() = place.atomic.app.kotlin.core.followConversation(subject)
    }

    override fun room(subject: String) = object : ThreadSource {
        override suspend fun page(before: String?, limit: Int) = page(place.atomic.app.kotlin.core.readRoomPage(subject, before, limit.toUInt()))
        override suspend fun after(after: String, limit: Int) = page(place.atomic.app.kotlin.core.readRoomAfter(subject, after, limit.toUInt()))
        override suspend fun send(text: String) {
            place.atomic.app.kotlin.core.sendRoomMessage(subject, text, null)
        }
    }

    override suspend fun rename(subject: String, name: String) = place.atomic.app.kotlin.core.renameResource(subject, name)

    override suspend fun drives() = place.atomic.app.kotlin.core.listDrives()

    override suspend fun recents(limit: Int) = place.atomic.app.kotlin.core.homeList(HomeList.RECENTS, limit.toUInt())

    override suspend fun search(query: String, limit: Int): List<DataReader.Hit> =
        place.atomic.app.kotlin.core.search(query, limit.toUInt(), null, emptyList()).map { DataReader.Hit(it.subject, it.title, it.className) }

    override suspend fun resourceText(subject: String, maxChars: Int) =
        place.atomic.app.kotlin.core.resourceText(subject, maxChars.toUInt())
}

/**
 * The resource classes that have a native screen, as Flutter's `nativeViews`
 * (AI chats, conversations, chat rooms; a meeting's chat is a chat room's).
 * Everything else is drawn by the web page in the embed.
 */
enum class NativeKind {
    AiChat, Conversation, Room;

    companion object {
        /** From a class name or URL as rows carry it (`ai-chat`, `aichat`, `.../class/chatroom`); null when the page draws it. */
        fun of(className: String): NativeKind? =
            when (className.trim().split('/', '#').lastOrNull { it.isNotEmpty() }.orEmpty().lowercase().replace(Regex("[^a-z0-9]"), "")) {
                "aichat" -> AiChat
                "conversation" -> Conversation
                "chatroom" -> Room
                else -> null
            }
    }
}
