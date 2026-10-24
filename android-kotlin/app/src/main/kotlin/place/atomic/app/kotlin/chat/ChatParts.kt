package place.atomic.app.kotlin.chat

import org.json.JSONArray
import org.json.JSONObject
import place.atomic.app.kotlin.core.AiChatEntry

/**
 * One part of an AI chat message, as the web app stores it in a `ChatLog`
 * entry (`parts`, the AI SDK's UI message parts): text, a file (a data URL), a
 * tool call with its result, or anything else (reasoning, a source), which is
 * kept as it was. Twin of Flutter's `chat_parts.dart`.
 */
sealed interface ChatPart {
    fun toJson(): JSONObject

    data class Text(val text: String) : ChatPart {
        override fun toJson() = JSONObject().put("type", "text").put("text", text)
    }

    /** A file the web app's composer attached (this app does not attach files yet). */
    data class File(val url: String, val mediaType: String, val filename: String?) : ChatPart {
        val isImage get() = mediaType.startsWith("image/")
        override fun toJson() = JSONObject().put("type", "file").put("url", url).put("mediaType", mediaType)
            .apply { if (filename != null) put("filename", filename) }
    }

    /** A call the model made to a tool, and its outcome once known. */
    data class Tool(
        val toolCallId: String,
        val toolName: String,
        val state: ToolState = ToolState.InputAvailable,
        val input: Any? = null,
        val output: Any? = null,
        val errorText: String? = null,
    ) : ChatPart {
        fun done(output: Any?) = copy(state = ToolState.OutputAvailable, output = output)
        fun failed(error: String) = copy(state = ToolState.OutputError, output = null, errorText = error)

        override fun toJson(): JSONObject = JSONObject()
            .put("type", "tool-$toolName")
            .put("toolCallId", toolCallId)
            .put("state", state.wire)
            .apply {
                if (input != null) put("input", input)
                if (state == ToolState.OutputAvailable) put("output", output ?: JSONObject.NULL)
                if (state == ToolState.OutputError) put("errorText", errorText.orEmpty())
            }
    }

    /** A part this app keeps but does not show (reasoning, a source, ...). */
    data class Raw(val json: JSONObject) : ChatPart {
        override fun toJson() = json
    }

    companion object {
        fun fromJson(json: JSONObject): ChatPart {
            val type = json.optString("type")
            return when {
                type == "text" -> Text(json.optString("text"))
                type == "file" && json.has("url") ->
                    File(json.getString("url"), json.optString("mediaType"), json.optString("filename").ifEmpty { null })
                type.startsWith("tool-") -> Tool(
                    toolCallId = json.optString("toolCallId"),
                    toolName = type.removePrefix("tool-"),
                    state = ToolState.parse(json.optString("state")),
                    input = json.opt("input")?.takeIf { it != JSONObject.NULL },
                    output = json.opt("output")?.takeIf { it != JSONObject.NULL },
                    errorText = json.optString("errorText").ifEmpty { null },
                )
                else -> Raw(json)
            }
        }
    }
}

/** Where a tool call is, as the AI SDK names it. */
enum class ToolState(val wire: String) {
    InputStreaming("input-streaming"),
    InputAvailable("input-available"),
    OutputAvailable("output-available"),
    OutputError("output-error");

    val running get() = this == InputStreaming || this == InputAvailable

    companion object {
        fun parse(wire: String?) = entries.firstOrNull { it.wire == wire } ?: InputAvailable
    }
}

/** A resource given to the AI as context with a message (the web app's `atomic-resource` context, an entry's `ctx`). */
data class ContextItem(val subject: String, val title: String, val className: String, val emoji: String? = null) {
    fun toJson(): JSONObject = JSONObject().put("type", "atomic-resource").put("subject", subject)
        .put("title", title).put("class_name", className)
}

/** One message of an AI chat with all its parts. */
data class ChatEntry(
    val id: String,
    val role: String,
    val createdAt: Long,
    val parts: List<ChatPart>,
    /** Resources attached to it, as context. */
    val context: List<ContextItem> = emptyList(),
) {
    val text: String get() = textOf(parts)
    val partsJson: String get() = JSONArray().apply { parts.forEach { put(it.toJson()) } }.toString()
    val contextJson: String? get() = context.takeIf { it.isNotEmpty() }?.let { c -> JSONArray().apply { c.forEach { put(it.toJson()) } }.toString() }

    companion object {
        /** The text parts, a blank line between them. */
        fun textOf(parts: List<ChatPart>): String =
            parts.filterIsInstance<ChatPart.Text>().map { it.text }.filter { it.isNotBlank() }.joinToString("\n\n").trim()

        fun of(entry: AiChatEntry): ChatEntry = ChatEntry(
            id = entry.id,
            role = entry.role,
            createdAt = entry.createdAt,
            parts = parseParts(entry.partsJson),
            context = parseContext(entry.ctxJson),
        )

        fun parseParts(json: String): List<ChatPart> = try {
            val array = JSONArray(json)
            (0 until array.length()).mapNotNull { array.optJSONObject(it)?.let(ChatPart::fromJson) }
        } catch (_: Exception) {
            emptyList()
        }

        /** The web app writes only `type` and `subject`; this app adds a title and class for the chip. */
        fun parseContext(json: String?): List<ContextItem> {
            if (json.isNullOrEmpty()) return emptyList()
            return try {
                val array = JSONArray(json)
                (0 until array.length()).mapNotNull { array.optJSONObject(it) }
                    .filter { it.optString("type") == "atomic-resource" && it.optString("subject").isNotEmpty() }
                    .map { ContextItem(it.getString("subject"), it.optString("title"), it.optString("class_name")) }
            } catch (_: Exception) {
                emptyList()
            }
        }
    }
}
