package place.atomic.app.kotlin.chat

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import place.atomic.app.kotlin.core.AiChatEntry

@RunWith(RobolectricTestRunner::class)
class ChatPartsTest {
    @Test
    fun anEntryOfTheWebAppIsReadWithItsPartsAndContext() {
        val e = ChatEntry.of(
            AiChatEntry(
                "m1", "user",
                """[{"type":"text","text":"Hello"},{"type":"reasoning","text":"hm"},{"type":"tool-semantic_search","toolCallId":"c1","state":"output-available","input":{"query":"q"},"output":[1]}]""",
                """[{"type":"atomic-resource","subject":"did:ad:x"},{"type":"other"}]""",
                1000,
            ),
        )
        assertEquals(3, e.parts.size)
        assertEquals("Hello", e.text)
        assertTrue(e.parts[1] is ChatPart.Raw)
        val tool = e.parts[2] as ChatPart.Tool
        assertEquals("semantic_search", tool.toolName)
        assertEquals(ToolState.OutputAvailable, tool.state)
        assertEquals(listOf("did:ad:x"), e.context.map { it.subject })
    }

    @Test
    fun partsAreWrittenBackInTheWebAppsFormat() {
        val tool = ChatPart.Tool("c1", "get_atomic_resource", input = JSONObject().put("subjects", "x")).failed("nope")
        val json = tool.toJson()
        assertEquals("tool-get_atomic_resource", json.getString("type"))
        assertEquals("output-error", json.getString("state"))
        assertEquals("nope", json.getString("errorText"))
        val entry = ChatEntry("l", "user", 1, listOf(ChatPart.Text("Hi")), listOf(ContextItem("did:ad:x", "X", "document")))
        assertEquals("""[{"type":"text","text":"Hi"}]""", entry.partsJson)
        assertEquals("atomic-resource", JSONObject(entry.contextJson!!.trim('[', ']')).getString("type"))
    }

    @Test
    fun garbageIsNoPartsRatherThanACrash() {
        assertEquals(emptyList<ChatPart>(), ChatEntry.parseParts("not json"))
        assertEquals(emptyList<ContextItem>(), ChatEntry.parseContext("{"))
        assertEquals(emptyList<ContextItem>(), ChatEntry.parseContext(null))
    }

    @Test
    fun aToolCallReadsInWords() {
        val search = ChatPart.Tool("1", "semantic_search", input = JSONObject().put("query", "lisbon").put("description", "Searching for your notes on Lisbon"))
        assertEquals("Searching for your notes on Lisbon", toolLabel(search))
        val bare = ChatPart.Tool("2", "semantic_search", ToolState.OutputAvailable, input = JSONObject().put("query", "lisbon"))
        assertEquals("Searched your drives for “lisbon”", toolLabel(bare))
        val read = ChatPart.Tool("3", "get_atomic_resource", input = JSONObject().put("subjects", org.json.JSONArray(listOf("a", "b"))))
        assertEquals("Reading 2 resources", toolLabel(read))
        assertEquals("Reading Trip", toolLabel(ChatPart.Tool("4", "get_atomic_resource", input = JSONObject().put("subjects", org.json.JSONArray(listOf("a")))), mapOf("a" to "Trip")))
    }
}
