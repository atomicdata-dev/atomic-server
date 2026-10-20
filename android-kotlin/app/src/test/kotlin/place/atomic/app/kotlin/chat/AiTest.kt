package place.atomic.app.kotlin.chat

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import place.atomic.app.kotlin.newSession
import java.io.ByteArrayInputStream

/** The portal, answering by path. */
private class Portal(val answer: (method: String, url: String, body: String?) -> HttpReply) : HttpEngine {
    val calls = mutableListOf<Triple<String, String, Map<String, String>>>()
    val bodies = mutableListOf<String?>()
    override fun send(method: String, url: String, headers: Map<String, String>, body: String?, timeoutMs: Int): HttpReply {
        calls += Triple(method, url, headers)
        bodies += body
        return answer(method, url, body)
    }
}

private fun reply(status: Int, body: String = "", headers: Map<String, List<String>> = emptyMap()) =
    HttpReply(status, headers, ByteArrayInputStream(body.toByteArray()))

private fun chunk(delta: JSONObject) = JSONObject().put("choices", JSONArray().put(JSONObject().put("delta", delta)))
private fun text(s: String) = chunk(JSONObject().put("content", s))

@RunWith(RobolectricTestRunner::class)
class AiTest {
    @Test
    fun signingInWithTheAgentMakesACookieSession() {
        val portal = Portal { _, url, _ ->
            when {
                url.endsWith("/api/auth/agent/challenge") -> reply(200, """{"nonce":"n1","challenge":"hello"}""")
                url.contains("/api/auth/agent?if_linked=true") -> reply(204, headers = mapOf("set-cookie" to listOf("session_token=abc123; Path=/; HttpOnly")))
                else -> reply(404)
            }
        }
        val signed = mutableListOf<String>()
        val client = AccountClient("https://atomic.place", portal)
        assertTrue(client.signInWithAgent("did:ad:agent:me", { signed += it; "sig" }, now = { 42 }))
        assertEquals(listOf("hello 42"), signed)
        assertTrue(client.linked)
        assertEquals("abc123", JSONObject(client.exportSession()).getString("cookie"))
        assertEquals("sig", JSONObject(portal.bodies[1]!!).getString("signature"))
    }

    @Test
    fun anAgentWithoutAnAccountIsNotSignedIn() {
        val portal = Portal { _, url, _ ->
            if (url.endsWith("challenge")) reply(200, """{"nonce":"n","challenge":"c"}""") else reply(200, """{"signed_in":false}""")
        }
        val client = AccountClient("https://atomic.place", portal)
        assertFalse(client.signInWithAgent("did:ad:agent:me", { "s" }))
        assertFalse(client.linked)
    }

    @Test
    fun aProviderMustBeAnHttpsOrigin() {
        for (bad in listOf("http://atomic.place", "https://atomic.place/path", "https://u:p@atomic.place", "https://atomic.place?x=1")) {
            try {
                AccountClient.providerOrigin(bad)
                fail("accepted $bad")
            } catch (_: IllegalArgumentException) {
            }
        }
        assertEquals("https://atomic.place:8443", AccountClient.providerOrigin("https://atomic.place:8443/"))
    }

    @Test
    fun theStreamIsReadChunkByChunkUpToDoneAndAnErrorChunkThrows() {
        val sse = ": PROCESSING\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\ndata: not json\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\ndata: [DONE]\n\ndata: {\"late\":1}\n"
        val chunks = AccountClient.parseCompletionChunks(sse.reader().buffered()).toList()
        assertEquals(listOf("Hel", "lo"), chunks.map { it.getJSONArray("choices").getJSONObject(0).getJSONObject("delta").getString("content") })
        try {
            AccountClient.parseCompletionChunks("data: {\"error\":{\"message\":\"out of credits\"}}\n".reader().buffered()).toList()
            fail("no error")
        } catch (e: IllegalStateException) {
            assertEquals("out of credits", e.message)
        }
    }

    @Test
    fun theCompletionsRequestCarriesTheSessionAndToolsAndAPortalRefusalIsItsMessage() = runTest {
        val portal = Portal { _, url, _ ->
            if (url.endsWith("completions")) reply(200, "data: {\"choices\":[]}\n\ndata: [DONE]\n") else reply(404)
        }
        val client = AccountClient("https://atomic.place", portal)
        client.restoreSession("""{"origin":"https://atomic.place","cookie":"abc"}""")
        client.chatCompletionChunks(JSONArray(), "m", JSONArray().put(JSONObject())).toList()
        val (method, url, headers) = portal.calls.single()
        assertEquals("POST", method)
        assertEquals("https://atomic.place/api/ai/chat/completions", url)
        assertEquals("session_token=abc", headers["Cookie"])
        assertEquals("https://atomic.place", headers["Origin"])
        val body = JSONObject(portal.bodies.single()!!)
        assertTrue(body.getBoolean("stream"))
        assertEquals("auto", body.getString("tool_choice"))

        val refusing = Portal { _, _, _ -> reply(402, """{"error":"No credits left"}""") }
        val other = AccountClient("https://atomic.place", refusing).also { it.restoreSession("""{"origin":"https://atomic.place","token":"t"}""") }
        try {
            other.chatCompletionChunks(JSONArray(), "m", null).toList()
            fail("no refusal")
        } catch (e: IllegalStateException) {
            assertEquals("No credits left", e.message)
        }
    }

    @Test
    fun theAccountSessionIsSavedSealedAndTheAgentSignsInOnlyOnce() = runTest {
        val store = newSession()
        var challenges = 0
        val portal = Portal { _, url, _ ->
            when {
                url.endsWith("challenge") -> { challenges++; reply(200, """{"nonce":"n","challenge":"c"}""") }
                url.contains("auth/agent") -> reply(204, headers = mapOf("set-cookie" to listOf("session_token=zzz")))
                url.endsWith("ai/status") -> reply(200, """{"enabled":true,"consent":false,"model":"m"}""")
                else -> reply(404)
            }
        }
        val provider = AccountAi(store, { "did:ad:agent:me" }, { "sig" }, portal)
        val ai = provider.hostedAi()!!
        assertTrue(ai.available)
        assertFalse(ai.consent)
        assertEquals("zzz", JSONObject(store.accountSession()!!).getString("cookie"))
        provider.hostedAi()
        assertEquals(1, challenges)
        // No agent, no session: no AI.
        assertNull(AccountAi(newSession(), { null }, { "" }, portal).hostedAi())
    }

    // ── The tool loop ────────────────────────────────────────────────────

    private fun ai(vararg rounds: List<JSONObject>, sent: MutableList<JSONArray> = mutableListOf()): HostedAi {
        var round = 0
        val completions: Completions = { messages, _, _ ->
            sent += JSONArray(messages.toString())
            val chunks = rounds[round++]
            flow { chunks.forEach { emit(it) } }
        }
        return HostedAi(JSONObject().put("enabled", true).put("consent", true).put("model", "m"), completions, { JSONObject() })
    }

    private fun call(id: String, name: String, args: String) = chunk(
        JSONObject().put(
            "tool_calls",
            JSONArray().put(JSONObject().put("index", 0).put("id", id).put("function", JSONObject().put("name", name).put("arguments", args))),
        ),
    )

    private val user = ChatEntry("1", "user", 1, listOf(ChatPart.Text("Find my notes")))

    @Test
    fun textStreamsAsDeltas() = runTest {
        val events = ai(listOf(text("Hel"), text("lo"))).run(listOf(user)).toList()
        assertEquals(listOf("Hel", "lo"), events.map { (it as AiEvent.TextDelta).text })
    }

    @Test
    fun aToolCallIsRunAndTheModelGoesOnWithItsResult() = runTest {
        val sent = mutableListOf<JSONArray>()
        val seen = mutableListOf<JSONObject>()
        val tool = AiTool("semantic_search", "d", JSONObject()) { input -> seen += input; JSONArray().put("hit") }
        val events = ai(
            listOf(call("c1", "semantic_search", "{\"que"), call("c1", "semantic_search", "ry\":\"notes\"}")),
            listOf(text("Found it")),
            sent = sent,
        ).run(listOf(user), context = "Context!", tools = listOf(tool)).toList()
        assertEquals("notes", seen.single().getString("query"))
        assertTrue(events[0] is AiEvent.ToolStarted)
        val finished = (events[1] as AiEvent.ToolFinished).part
        assertEquals(ToolState.OutputAvailable, finished.state)
        assertEquals("Found it", (events[2] as AiEvent.TextDelta).text)
        // Second request: system, context, user, the assistant's call and the tool's result.
        val second = sent[1]
        assertEquals(listOf("system", "system", "user", "assistant", "tool"), (0 until second.length()).map { second.getJSONObject(it).getString("role") })
        assertEquals("c1", second.getJSONObject(4).getString("tool_call_id"))
    }

    @Test
    fun aFailingToolIsTheCallsFailureAndTheModelIsTold() = runTest {
        val sent = mutableListOf<JSONArray>()
        val tool = AiTool("get_atomic_resource", "d", JSONObject()) { error("not found") }
        val events = ai(listOf(call("c1", "get_atomic_resource", "{}")), listOf(text("Sorry")), sent = sent)
            .run(listOf(user), tools = listOf(tool)).toList()
        val part = (events[1] as AiEvent.ToolFinished).part
        assertEquals(ToolState.OutputError, part.state)
        assertEquals("not found", part.errorText)
        assertEquals("Error: not found", sent[1].getJSONObject(sent[1].length() - 1).getString("content"))
    }

    @Test
    fun theLoopStopsAfterEightRounds() = runTest {
        val tool = AiTool("t", "d", JSONObject()) { "x" }
        val rounds = Array(20) { listOf(call("c$it", "t", "{}")) }
        val sent = mutableListOf<JSONArray>()
        ai(*rounds, sent = sent).run(listOf(user), tools = listOf(tool)).toList()
        assertEquals(8, sent.size)
    }

    @Test
    fun aLongChatSendsOnlyItsLatestMessages() = runTest {
        val sent = mutableListOf<JSONArray>()
        val history = (0 until 200).map { ChatEntry("$it", if (it % 2 == 0) "user" else "assistant", it.toLong(), listOf(ChatPart.Text("m$it"))) }
        ai(listOf(text("ok")), sent = sent).run(history).toList()
        val messages = sent.single()
        assertTrue(messages.length() < 60)
        assertEquals("m199", messages.getJSONObject(messages.length() - 1).getString("content"))
    }
}
