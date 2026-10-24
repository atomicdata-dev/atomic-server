package place.atomic.app.kotlin.chat

import org.json.JSONArray
import org.json.JSONObject
import place.atomic.app.kotlin.ui.classLabel

/** What the tools read of the person's data: search and readable text, local to this device. */
interface DataReader {
    suspend fun search(query: String, limit: Int): List<Hit>
    suspend fun resourceText(subject: String, maxChars: Int): String

    data class Hit(val subject: String, val title: String, val className: String)
}

/** Most hits `semantic_search` returns, and how many of them come with a piece of their text. */
private const val MAX_HITS = 20
private const val HITS_WITH_TEXT = 5

/** Most resources `get_atomic_resource` reads in one call, and characters of each. */
private const val MAX_READ = 5
private const val READ_CHARS = 3000

/**
 * The tools the assistant gives the model: reading the person's data, never
 * changing it. Named and shaped as the web app's tools of the same name, so a
 * chat reads the same in both.
 */
fun assistantTools(data: DataReader): List<AiTool> = listOf(semanticSearchTool(data), getResourceTool(data))

private fun schema(vararg properties: Pair<String, JSONObject>, required: List<String>) = JSONObject()
    .put("type", "object")
    .put("properties", JSONObject().apply { properties.forEach { put(it.first, it.second) } })
    .put("required", JSONArray(required))

private fun prop(type: String, description: String) = JSONObject().put("type", type).put("description", description)

/** `semantic_search`: searches the drives on this device. Its result, a list of `{subject,title,chunk}`, is what the web app shows for it. */
fun semanticSearchTool(data: DataReader) = AiTool(
    name = "semantic_search",
    description = "Search the person's drives on this device for resources. Returns the subject, title and the start of the " +
        "text of each hit. Read a hit in full with get_atomic_resource.",
    parameters = schema(
        "query" to prop("string", "What to search for."),
        "description" to prop(
            "string",
            "A short one sentence description of the search to tell the person what you are doing, e.g. " +
                "\"Searching for your notes on Lisbon\".",
        ),
        "limit" to prop("integer", "The most results to return, 1 - 20."),
        required = listOf("query", "description"),
    ),
    execute = { input ->
        val query = input.optString("query").trim()
        if (query.isEmpty()) error("No query given")
        val limit = (if (input.has("limit")) input.optInt("limit", 10) else 10).coerceIn(1, MAX_HITS)
        val hits = data.search(query, limit).take(limit)
        JSONArray().apply {
            hits.forEachIndexed { i, hit ->
                put(
                    JSONObject().put("subject", hit.subject).put("title", hit.title.ifEmpty { "Untitled" }).put(
                        "chunk",
                        if (i < HITS_WITH_TEXT) runCatching { data.resourceText(hit.subject, 300) }.getOrDefault("") else classLabel(hit.className),
                    ),
                )
            }
        }
    },
)

/** `get_atomic_resource`: reads resources by their subjects. Its result maps each subject to its readable text. */
fun getResourceTool(data: DataReader) = AiTool(
    name = "get_atomic_resource",
    description = "Read resources (documents, tables, folders, chats…) by their subjects: their title, class, properties and text.",
    parameters = schema(
        "subjects" to JSONObject().put("type", "array").put("items", JSONObject().put("type", "string"))
            .put("description", "The subjects of the resources to read."),
        required = listOf("subjects"),
    ),
    execute = { input ->
        val raw = input.opt("subjects")
        val subjects = when (raw) {
            is JSONArray -> (0 until raw.length()).mapNotNull { raw.optString(it).ifEmpty { null } }
            is String -> listOf(raw)
            else -> emptyList()
        }
        if (subjects.isEmpty()) error("No subjects given")
        JSONObject().apply {
            subjects.take(MAX_READ).forEach { s ->
                put(s, try { data.resourceText(s, READ_CHARS) } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (e: Exception) { "Error: ${e.message}" })
            }
        }
    },
)

// ── How a tool call reads in the chat ────────────────────────────────────

private fun cut(s: String, max: Int) = if (s.length <= max) s else s.take(max - 1) + "…"

private fun str(input: Any?, key: String): String? =
    (input as? JSONObject)?.optString(key)?.trim()?.takeIf { it.isNotEmpty() }

/**
 * What a tool call does, in words, as the web app says it: `semantic_search`
 * with the model's own description of the search, `get_atomic_resource` with
 * the titles of what it reads (from [titles], subject to title, when known), and
 * so on. Any other tool: its name.
 */
fun toolLabel(p: ChatPart.Tool, titles: Map<String, String> = emptyMap()): String {
    val input = p.input
    val running = p.state.running
    when (p.toolName) {
        "semantic_search" -> {
            str(input, "description")?.let { return it }
            val query = str(input, "query")
                ?: return if (running) "Searching your drives" else "Searched your drives"
            return "${if (running) "Searching" else "Searched"} your drives for “${cut(query, 40)}”"
        }
        "query" -> return str(input, "description") ?: if (running) "Querying your data" else "Queried your data"
        "get_atomic_resource" -> {
            val raw = (input as? JSONObject)?.optJSONArray("subjects")
            val subjects = raw?.let { a -> (0 until a.length()).map { a.optString(it) } }.orEmpty()
            val named = subjects.mapNotNull { s -> titles[s]?.let { cut(it, 20) } }
            val verb = if (running) "Reading" else "Read"
            if (named.size == subjects.size && named.isNotEmpty()) return "$verb ${named.joinToString(", ")}"
            return if (subjects.size > 1) "$verb ${subjects.size} resources" else "$verb a resource"
        }
        "read_file_resource" -> return if (running) "Reading a file" else "Read a file"
        "web_search_exa" -> return if (running) "Searching online" else "Searched online"
        "edit_atomic_resource", "edit_document_resource" -> return if (running) "Editing a resource" else "Edited a resource"
        "get_schema" -> return "Reading schema"
        "find_schema" -> return "Searching schemas"
        "ensure_ontology" -> return "Saving schema"
        "create_resource" -> return "${if (running) "Creating" else "Created"} ${createdName(input) ?: "a resource"}"
        "create_table" -> return "${if (running) "Creating" else "Created"} table${str(input, "name")?.let { " $it" }.orEmpty()}"
        "read_skill", "read_skill_reference" -> return "Loading skill${str(input, "name")?.let { ": $it" }.orEmpty()}"
        "delete_resource" -> return if (running) "Deleting a resource" else "Deleted a resource"
        "favorite_resource" -> return "Toggling favorite"
        "navigate_to_resource" -> return "Opening a resource"
        "open_share_settings" -> return "Opening share settings"
        "show_history" -> return "Opening history"
    }
    val name = p.toolName.replace('_', ' ')
    return if (running) "Using tool $name" else "Used tool $name"
}

private fun createdName(input: Any?): String? {
    val raw = str(input, "jsonAD") ?: return null
    return try {
        when (val v = org.json.JSONTokener(raw).nextValue()) {
            is JSONArray -> "${v.length()} resources"
            is JSONObject -> listOf("name", "shortname").map { v.optString(it) }.firstOrNull { it.isNotEmpty() }
            else -> null
        }
    } catch (_: Exception) {
        null
    }
}

/** What a finished call returned, in a line: the number of hits of a search, what was read, else the start of its result. */
fun toolSummary(p: ChatPart.Tool): String {
    if (p.state == ToolState.OutputError) return p.errorText ?: "Failed"
    val out = p.output
    if (p.toolName == "semantic_search" && out is JSONArray) {
        if (out.length() == 0) return "No results"
        val names = (0 until out.length()).mapNotNull { out.optJSONObject(it)?.optString("title")?.ifEmpty { null } }
        return "${out.length()} result${if (out.length() == 1) "" else "s"}" +
            (if (names.isEmpty()) "" else ": ${names.take(5).joinToString(", ")}") + if (names.size > 5) "…" else ""
    }
    if (p.toolName == "get_atomic_resource" && out is JSONObject) {
        return "Read ${out.length()} resource${if (out.length() == 1) "" else "s"}"
    }
    return when (out) {
        null -> "Done"
        is String -> cut(out, 300)
        is JSONObject -> cut(out.toString(2), 600)
        is JSONArray -> cut(out.toString(2), 600)
        else -> cut(out.toString(), 600)
    }
}

/** Titles of resources a message's tool calls found (search hits), by subject: to name what a later call reads. */
fun toolTitles(parts: Iterable<ChatPart>): Map<String, String> = buildMap {
    for (p in parts) {
        val out = (p as? ChatPart.Tool)?.output as? JSONArray ?: continue
        for (i in 0 until out.length()) {
            val hit = out.optJSONObject(i) ?: continue
            val subject = hit.optString("subject")
            if (subject.isNotEmpty() && hit.has("title")) put(subject, hit.optString("title"))
        }
    }
}
