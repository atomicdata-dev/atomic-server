package place.atomic.app.kotlin.chat

import android.util.Base64
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import org.json.JSONArray
import org.json.JSONObject

/** What the model is told before the conversation. Not shown to the person. */
private const val SYSTEM_PROMPT =
    "You are the assistant in atomic.place. Answer briefly and clearly, in the language the person writes in. " +
        "Use Markdown where it helps."

/** Added to [SYSTEM_PROMPT] when the model is given tools. */
private const val TOOLS_PROMPT =
    " When the person asks about their own data, use the tools to search their drives and read resources; " +
        "link a resource as [title](subject)."

/** The OpenAI-compatible `chat/completions` stream, chunk by chunk (see [AccountClient.chatCompletionChunks]). */
typealias Completions = (messages: JSONArray, model: String, tools: JSONArray?) -> Flow<JSONObject>

/**
 * A function the model may call while it answers; this app runs it and gives the
 * model its result (as the web app's chat does: the account's AI only passes the
 * calls on).
 */
class AiTool(
    /** The function's name, the same as the web app's tool of that name. */
    val name: String,
    val description: String,
    /** The JSON Schema of its input. */
    val parameters: JSONObject,
    /** Runs the call with the model's input; the result goes back to the model as JSON. A thrown error goes back as the call's failure. */
    val execute: suspend (JSONObject) -> Any?,
) {
    val definition: JSONObject
        get() = JSONObject().put("type", "function").put(
            "function",
            JSONObject().put("name", name).put("description", description).put("parameters", parameters),
        )
}

/** What happens while the model answers. */
sealed interface AiEvent {
    /** More text of the answer. */
    data class TextDelta(val text: String) : AiEvent

    /** The model called a tool; it runs now (the part is `input-available`). */
    data class ToolStarted(val part: ChatPart.Tool) : AiEvent

    /** A tool call ended: the part is `output-available` or `output-error`. */
    data class ToolFinished(val part: ChatPart.Tool) : AiEvent
}

/**
 * The included AI of a linked account: chat completions through the account
 * provider, paid from the account's credits. Twin of Flutter's `HostedAi`.
 * (There is no own-API-key route in the Flutter app, so there is none here.)
 */
class HostedAi(
    var status: JSONObject,
    private val completions: Completions,
    private val onEnable: suspend () -> JSONObject,
    private val log: (String) -> Unit = {},
) {
    /** The provider offers AI to this account and it is switched on. */
    val available get() = status.optBoolean("enabled")

    /** The person accepted the terms for the included AI. */
    val consent get() = status.optBoolean("consent")

    val model: String get() = status.optString("model")

    /** Credits left, in the provider's unit; null when it does not say. */
    val remaining: Long? get() = if (status.has("remaining_micros")) status.optLong("remaining_micros") else null

    /** Accepts the terms; the AI can be used afterwards. */
    suspend fun enable() {
        status = onEnable()
    }

    /**
     * The answer to [history] (oldest first): its text as it is written, and each
     * call to one of [tools] as it starts and ends. Calls are run here, and the
     * model goes on with their results, at most [MAX_STEPS] rounds.
     *
     * [context], when given, is sent as a second system message ahead of the
     * history: resources the person attached. It is not part of the chat.
     */
    fun run(history: List<ChatEntry>, context: String? = null, tools: List<AiTool> = emptyList()): Flow<AiEvent> = flow {
        val recent = recent(history)
        val messages = JSONArray()
        messages.put(msg("system", if (tools.isEmpty()) SYSTEM_PROMPT else SYSTEM_PROMPT + TOOLS_PROMPT))
        if (!context.isNullOrEmpty()) messages.put(msg("system", context))
        recent.forEach { wire(it).forEach(messages::put) }
        val defs = tools.takeIf { it.isNotEmpty() }?.let { t -> JSONArray().apply { t.forEach { put(it.definition) } } }
        log("[ai] sending ${messages.length()} messages (${recent.size} of ${history.size} of the chat, ${tools.size} tools) to model \"$model\"")
        for (step in 0 until MAX_STEPS) {
            val text = StringBuilder()
            val calls = mutableListOf<Call>()
            completions(messages, model, defs).collect { chunk ->
                val delta = chunk.optJSONArray("choices")?.optJSONObject(0)?.optJSONObject("delta") ?: return@collect
                val content = delta.optString("content")
                if (content.isNotEmpty()) {
                    text.append(content)
                    emit(AiEvent.TextDelta(content))
                }
                delta.optJSONArray("tool_calls")?.let { raw ->
                    for (i in 0 until raw.length()) raw.optJSONObject(i)?.let { addCallDelta(calls, it) }
                }
            }
            if (calls.isEmpty()) return@flow
            messages.put(
                JSONObject().put("role", "assistant")
                    .put("content", if (text.isEmpty()) JSONObject.NULL else text.toString())
                    .put(
                        "tool_calls",
                        JSONArray().apply {
                            calls.forEach { c ->
                                put(
                                    JSONObject().put("id", c.id).put("type", "function")
                                        .put("function", JSONObject().put("name", c.name).put("arguments", c.args.toString())),
                                )
                            }
                        },
                    ),
            )
            for (c in calls) {
                val input = decodeArgs(c.args.toString())
                val part = ChatPart.Tool(c.id, c.name, ToolState.InputAvailable, input = input)
                emit(AiEvent.ToolStarted(part))
                val (finished, result) = try {
                    val tool = tools.firstOrNull { it.name == c.name } ?: error("Unknown tool ${c.name}")
                    val output = tool.execute(input)
                    part.done(output) to (output ?: JSONObject.NULL).let { if (it is String) JSONObject.quote(it) else it.toString() }
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    val message = e.message ?: e.toString()
                    part.failed(message) to "Error: $message"
                }
                emit(AiEvent.ToolFinished(finished))
                messages.put(JSONObject().put("role", "tool").put("tool_call_id", c.id).put("content", result))
            }
        }
    }

    private fun msg(role: String, content: String) = JSONObject().put("role", role).put("content", content)

    /** An entry as model messages: a user's text and files; an assistant's text, and its tool calls with their results. */
    internal fun wire(e: ChatEntry): List<JSONObject> {
        if (e.role != "assistant") {
            val content = e.parts.mapNotNull { p ->
                when {
                    p is ChatPart.Text && p.text.isNotBlank() -> p.text
                    // The included AI takes text and tools only: a file is told as text.
                    p is ChatPart.File -> fileText(p)
                    else -> null
                }
            }
            val array = JSONArray().apply { content.forEach { put(JSONObject().put("type", "text").put("text", it)) } }
            return listOf(
                if (content.size == 1) msg(e.role, content.single()) else JSONObject().put("role", e.role).put("content", array),
            )
        }
        val out = mutableListOf<JSONObject>()
        val text = StringBuilder()
        val calls = mutableListOf<ChatPart.Tool>()
        fun flushCalls() {
            if (calls.isEmpty()) return
            out += JSONObject().put("role", "assistant")
                .put("content", if (text.isEmpty()) JSONObject.NULL else text.toString())
                .put(
                    "tool_calls",
                    JSONArray().apply {
                        calls.forEach { c ->
                            put(
                                JSONObject().put("id", c.toolCallId).put("type", "function").put(
                                    "function",
                                    JSONObject().put("name", c.toolName).put("arguments", (c.input ?: JSONObject()).toString()),
                                ),
                            )
                        }
                    },
                )
            text.clear()
            calls.forEach { c ->
                out += JSONObject().put("role", "tool").put("tool_call_id", c.toolCallId).put(
                    "content",
                    if (c.state == ToolState.OutputError) "Error: ${c.errorText.orEmpty()}" else (c.output ?: JSONObject.NULL).toString(),
                )
            }
            calls.clear()
        }
        for (p in e.parts) {
            if (p is ChatPart.Text) {
                if (calls.isNotEmpty()) flushCalls()
                if (p.text.isBlank()) continue
                if (text.isNotEmpty()) text.append("\n\n")
                text.append(p.text)
            } else if (p is ChatPart.Tool) {
                if (p.state.running) {
                    // No result was recorded: the model is told, not given a call.
                    flushCalls()
                    if (text.isNotEmpty()) text.append("\n\n")
                    text.append("Previous tool call ${p.toolCallId} (${p.toolName}) has no recorded result. Its outcome is unknown.")
                } else {
                    calls += p
                }
            }
        }
        flushCalls()
        if (text.isNotEmpty()) out += msg("assistant", text.toString())
        return out
    }

    /** A tool call as its pieces arrive. */
    private class Call(val index: Int, var id: String, var name: String) {
        val args = StringBuilder()
    }

    /** Adds a `tool_calls` delta: a new call (by its index, or a new id at an index already taken), or more of an argument string. */
    private fun addCallDelta(calls: MutableList<Call>, raw: JSONObject) {
        val index = if (raw.has("index")) raw.optInt("index") else calls.size
        val id = raw.optString("id").ifEmpty { null }
        val fn = raw.optJSONObject("function")
        val name = fn?.optString("name")?.ifEmpty { null }
        val args = fn?.opt("arguments")
        var call = calls.lastOrNull { it.index == index }
        if (call == null || (id != null && call.id != id && call.id.isNotEmpty())) {
            call = Call(index, id ?: "call_${calls.size}", name ?: "")
            calls += call
        }
        if (call.id.isEmpty() && id != null) call.id = id
        if (name != null && call.name.isEmpty()) call.name = name
        when (args) {
            is String -> call.args.append(args)
            is JSONObject -> call.args.append(args.toString())
        }
    }

    private fun decodeArgs(raw: String): JSONObject {
        if (raw.isBlank()) return JSONObject()
        return try {
            JSONObject(raw)
        } catch (_: Exception) {
            JSONObject().put("arguments", raw)
        }
    }

    companion object {
        /** The most of a chat sent to the model: its latest messages. */
        const val MAX_HISTORY_MESSAGES = 40
        const val MAX_HISTORY_CHARS = 24_000

        /** The most rounds of tool calls in one answer (as the web app's hosted chat). */
        const val MAX_STEPS = 8

        /** The most of an attached text file sent to the model. */
        const val MAX_FILE_CHARS = 20_000

        /**
         * A long chat is cut to its latest part: the model reads (and the account
         * bills) every token. The newest message is always sent.
         */
        fun recent(history: List<ChatEntry>): List<ChatEntry> {
            val tail = if (history.size > MAX_HISTORY_MESSAGES) history.subList(history.size - MAX_HISTORY_MESSAGES, history.size) else history
            var chars = 0
            var start = tail.size
            while (start > 0 && chars + size(tail[start - 1]) <= MAX_HISTORY_CHARS) {
                chars += size(tail[--start])
            }
            return tail.subList(if (start == tail.size) start - 1 else start, tail.size)
        }

        /** About how much of the model's budget an entry takes. */
        private fun size(e: ChatEntry): Int = e.parts.sumOf { p ->
            when (p) {
                is ChatPart.Text -> p.text.length
                is ChatPart.File -> if (p.isImage) 1000 else fileBody(p)?.length ?: 100
                is ChatPart.Tool -> (p.input?.toString()?.length ?: 4) + (p.output?.toString()?.length ?: 4) + (p.errorText?.length ?: 0)
                is ChatPart.Raw -> 0
            }
        }

        private fun fileBody(f: ChatPart.File): String? {
            if (!f.url.startsWith("data:") || !(f.mediaType.startsWith("text/") || f.mediaType == "application/json")) return null
            val comma = f.url.indexOf(',')
            if (comma < 0) return null
            return try {
                if (f.url.substring(5, comma).endsWith(";base64")) {
                    String(Base64.decode(f.url.substring(comma + 1), Base64.DEFAULT))
                } else {
                    java.net.URLDecoder.decode(f.url.substring(comma + 1), "UTF-8")
                }
            } catch (_: Exception) {
                null
            }
        }

        /** A file as the model reads it: a text file's text, otherwise a note. */
        fun fileText(f: ChatPart.File): String {
            val name = f.filename ?: "file"
            val body = fileBody(f)
            if (body != null) {
                val cut = if (body.length > MAX_FILE_CHARS) body.take(MAX_FILE_CHARS) + "\n…(cut)" else body
                return "Attached file \"$name\":\n```\n$cut\n```"
            }
            return if (f.isImage) "[The person attached an image, \"$name\", which you cannot see.]"
            else "[The person attached \"$name\" (${f.mediaType}), which you cannot read.]"
        }
    }
}
