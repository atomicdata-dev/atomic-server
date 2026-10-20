package place.atomic.app.kotlin.chat

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class ModelsTest {
    /** Not `backgroundScope`: `advanceUntilIdle` does not wait for background tasks. The models never finish (they follow a state), and this scope is no child of the test. */
    private fun TestScope.modelScope() = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.test.StandardTestDispatcher(testScheduler))

    private fun TestScope.aiModel(
        backend: FakeChat,
        ai: HostedAi? = readyAi(scripted(listOf("Hi ", "there"))),
        subject: String? = null,
    ) = AiChatModel(backend, { ai }, subject, "", modelScope()).also { it.start() }

    @Test
    fun aNewChatIsCreatedWithTheFirstMessageNamedAfterItAndBothMessagesAreSaved() = runTest {
        val backend = FakeChat()
        val m = aiModel(backend)
        advanceUntilIdle()
        assertEquals(AiStatus.Ready, m.ui.value.ai)
        assertEquals(listOf("did:ad:drive", "did:ad:doc"), m.ui.value.options.map { it.subject })
        m.send("  Plan my trip  ")
        advanceUntilIdle()
        assertEquals(listOf("Plan my trip"), backend.created)
        val saved = backend.chats.getValue("did:ad:chat1")
        assertEquals(listOf("user", "assistant"), saved.map { it.role })
        assertEquals("Hi there", saved[1].text)
        assertFalse(m.ui.value.sending)
        assertNull(m.ui.value.partial)
        assertEquals(listOf("Plan my trip", "Hi there"), m.ui.value.messages.map { it.text })
    }

    @Test
    fun aLongFirstMessageNamesTheChatWithAnEllipsis() = runTest {
        val backend = FakeChat()
        val m = aiModel(backend)
        advanceUntilIdle()
        m.send("x".repeat(60))
        advanceUntilIdle()
        assertEquals("x".repeat(40) + "…", backend.created.single())
    }

    @Test
    fun attachedResourcesGoToTheModelAsContextAndAreSavedWithTheMessage() = runTest {
        val backend = FakeChat()
        val sent = mutableListOf<org.json.JSONArray>()
        val m = aiModel(backend, readyAi(scripted(listOf("ok"), sent = sent)))
        advanceUntilIdle()
        m.toggle(m.ui.value.options[1])
        m.attach(ContextItem("did:ad:other", "Other", "document"))
        m.send("What is in there?")
        advanceUntilIdle()
        val context = sent.single().getJSONObject(1).getString("content")
        assertTrue(context.contains("Text of did:ad:doc"))
        assertTrue(context.contains("Text of did:ad:other"))
        val user = backend.chats.getValue("did:ad:chat1")[0]
        assertEquals(listOf("did:ad:doc", "did:ad:other"), user.context.map { it.subject })
        assertEquals(2, ChatEntry.parseContext(user.contextJson).size)
    }

    @Test
    fun stoppingKeepsWhatCameSoFarAsTheAnswer() = runTest {
        val backend = FakeChat()
        val gate = CompletableDeferred<Unit>()
        val completions: Completions = { _, _, _ ->
            flow {
                emit(JSONObject().put("choices", org.json.JSONArray().put(JSONObject().put("delta", JSONObject().put("content", "Partial")))))
                gate.await()
            }
        }
        val m = aiModel(backend, readyAi(completions))
        advanceUntilIdle()
        m.send("Go")
        advanceUntilIdle()
        assertTrue(m.ui.value.sending)
        m.stop()
        advanceUntilIdle()
        assertFalse(m.ui.value.sending)
        assertEquals("Partial", backend.chats.getValue("did:ad:chat1")[1].text)
    }

    @Test
    fun stoppingBeforeAnyTextKeepsNoAnswer() = runTest {
        val backend = FakeChat()
        val gate = CompletableDeferred<Unit>()
        val m = aiModel(backend, readyAi { _, _, _ -> flow { gate.await() } })
        advanceUntilIdle()
        m.send("Go")
        advanceUntilIdle()
        m.stop()
        advanceUntilIdle()
        assertEquals(listOf("user"), backend.chats.getValue("did:ad:chat1").map { it.role })
    }

    @Test
    fun withoutAnAccountOrConsentNothingIsSent() = runTest {
        val backend = FakeChat()
        val none = AiChatModel(backend, { null }, null, "", modelScope()).also { it.start() }
        advanceUntilIdle()
        assertEquals(AiStatus.NoAccount, none.ui.value.ai)
        none.send("hi")
        advanceUntilIdle()
        assertTrue(backend.created.isEmpty())

        val needs = HostedAi(JSONObject().put("enabled", true).put("consent", false), scripted(listOf("x")), { JSONObject().put("enabled", true).put("consent", true) })
        val m = AiChatModel(backend, { needs }, null, "", modelScope()).also { it.start() }
        advanceUntilIdle()
        assertEquals(AiStatus.NeedsConsent, m.ui.value.ai)
        m.enableAi()
        advanceUntilIdle()
        assertEquals(AiStatus.Ready, m.ui.value.ai)
    }

    @Test
    fun aFailedSaveIsShownAndTheAnswerStillComes() = runTest {
        val backend = FakeChat().apply { failAdd = IllegalStateException("disk full") }
        val m = aiModel(backend)
        advanceUntilIdle()
        m.send("Hello")
        advanceUntilIdle()
        assertEquals("disk full", m.ui.value.error)
        assertEquals(listOf("Hello", "Hi there"), m.ui.value.messages.map { it.text })
    }

    @Test
    fun anExistingChatIsReadInAWindow() = runTest {
        val backend = FakeChat()
        backend.chats["did:ad:old"] = (0 until 120).map { ChatEntry("e$it", "user", it.toLong(), listOf(ChatPart.Text("m$it"))) }.toMutableList()
        val m = aiModel(backend, subject = "did:ad:old")
        advanceUntilIdle()
        assertEquals(50, m.ui.value.messages.size)
        assertEquals("m119", m.ui.value.messages.last().text)
        m.loadOlder()
        advanceUntilIdle()
        assertEquals(100, m.ui.value.messages.size)
        assertTrue(m.ui.value.window.hasOlder)
    }

    // ── Conversations and rooms ──────────────────────────────────────────

    private fun TestScope.thread(source: FakeThread, rename: (suspend (String) -> Unit)? = null) =
        ThreadModel(source, "Robin", modelScope(), renameWith = rename).also { it.start() }

    @Test
    fun aThreadIsFetchedOnTheDeviceAndRead() = runTest {
        val source = FakeThread(mutableListOf(message("a", "Hi"), message("b", "Hello", mine = true)))
        val m = thread(source)
        advanceUntilIdle()
        assertEquals(1, source.followed)
        assertEquals(listOf("Hi", "Hello"), m.ui.value.shown.map { it.text })
    }

    @Test
    fun aSentMessageShowsAtOnceAsPendingAndThenAsRead() = runTest {
        val source = FakeThread(mutableListOf(message("a", "Hi")))
        val m = thread(source)
        advanceUntilIdle()
        m.send(" Hello back ")
        assertEquals(listOf("Hi", "Hello back"), m.ui.value.shown.map { it.text })
        assertEquals(1, m.ui.value.pending.size)
        advanceUntilIdle()
        assertTrue(m.ui.value.pending.isEmpty())
        assertEquals(listOf("Hi", "Hello back"), m.ui.value.shown.map { it.text })
        assertEquals(listOf("Hello back"), source.sent)
    }

    @Test
    fun aFailedSendGivesTheTextBackAndAnError() = runTest {
        val source = FakeThread().apply { sendError = IllegalStateException("no peers") }
        val m = thread(source)
        advanceUntilIdle()
        m.send("Lost words")
        advanceUntilIdle()
        assertEquals("Couldn't send: no peers", m.ui.value.error)
        assertEquals("Lost words", m.ui.value.unsent)
        assertTrue(m.ui.value.shown.isEmpty())
        m.unsentTaken()
        assertNull(m.ui.value.unsent)
    }

    @Test
    fun pollingFindsNewMessagesAndScrolledUpOnlyCountsThem() = runTest {
        val source = FakeThread(mutableListOf(message("a", "Hi")))
        val m = thread(source)
        advanceUntilIdle()
        source.messages += message("b", "News")
        m.poll(atBottom = false)
        advanceUntilIdle()
        assertEquals(1, m.ui.value.window.unseen)
        assertEquals(1, m.ui.value.window.items.size)
        m.jumpToLatest()
        advanceUntilIdle()
        assertEquals(2, m.ui.value.window.items.size)
    }

    @Test
    fun renamingARoomIsOptimisticAndIsUndoneWhenItFails() = runTest {
        val names = mutableListOf<String>()
        val m = thread(FakeThread(), rename = { names += it })
        advanceUntilIdle()
        m.rename(" Planning ")
        assertEquals("Planning", m.ui.value.title)
        advanceUntilIdle()
        assertEquals(listOf("Planning"), names)

        val failing = thread(FakeThread(), rename = { error("read only") })
        advanceUntilIdle()
        failing.rename("New")
        advanceUntilIdle()
        assertEquals("Robin", failing.ui.value.title)
        assertNotNull(failing.ui.value.error)
    }

    @Test
    fun classNamesChooseTheNativeScreen() {
        assertEquals(NativeKind.AiChat, NativeKind.of("aichat"))
        assertEquals(NativeKind.AiChat, NativeKind.of("AI-Chat"))
        assertEquals(NativeKind.Conversation, NativeKind.of("https://atomicdata.dev/classes/conversation"))
        assertEquals(NativeKind.Room, NativeKind.of("chatroom"))
        assertNull(NativeKind.of("document"))
        assertNull(NativeKind.of(""))
    }
}
