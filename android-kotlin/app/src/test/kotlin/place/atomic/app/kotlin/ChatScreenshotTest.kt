package place.atomic.app.kotlin

import androidx.compose.runtime.Composable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.captureRoboImage
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import place.atomic.app.kotlin.chat.AiChatState
import place.atomic.app.kotlin.chat.AiStatus
import place.atomic.app.kotlin.chat.ChatEntry
import place.atomic.app.kotlin.chat.ChatPart
import place.atomic.app.kotlin.chat.ContextItem
import place.atomic.app.kotlin.chat.NativeKind
import place.atomic.app.kotlin.chat.ThreadState
import place.atomic.app.kotlin.chat.ToolState
import place.atomic.app.kotlin.chat.WindowState
import place.atomic.app.kotlin.chat.message
import place.atomic.app.kotlin.ui.AiChatActions
import place.atomic.app.kotlin.ui.AiChatScreen
import place.atomic.app.kotlin.ui.AtomicTheme
import place.atomic.app.kotlin.ui.ChatListActions
import place.atomic.app.kotlin.ui.ThreadActions
import place.atomic.app.kotlin.ui.ThreadScreen
import java.io.File
import java.time.ZoneId
import java.time.ZonedDateTime

/**
 * Screenshots of the AI chat, conversation and chat-room screens with fake data,
 * into `$SHOTS_DIR` (never the repo):
 * `SHOTS_DIR=/tmp/claude-0/kotlin-shots ./gradlew testDebugUnitTest -Proborazzi.test.record=true`.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(qualifiers = "w390dp-h844dp-port-xxhdpi")
class ChatScreenshotTest {
    @get:Rule
    val compose = createComposeRule()
    private val dir = File(System.getenv("SHOTS_DIR") ?: "build/shots")

    private fun shot(name: String, dark: Boolean = false, content: @Composable () -> Unit) {
        compose.setContent { AtomicTheme(dark) { content() } }
        compose.onRoot().captureRoboImage(File(dir, "$name.png").path)
    }

    private val list = ChatListActions({}, {}, {}, {}, {}, 500)
    private val ai = AiChatActions({}, {}, {}, {}, {}, {}, {}, { emptyList() }, list)
    private val thread = ThreadActions({}, {}, list)

    private val now = System.currentTimeMillis()
    private fun entry(id: String, role: String, vararg parts: ChatPart, ctx: List<ContextItem> = emptyList()) =
        ChatEntry(id, role, now - 60_000, parts.toList(), ctx)

    private val trip = ContextItem("did:ad:trip", "Lisbon trip", "document")
    private val search = ChatPart.Tool(
        "c1", "semantic_search", ToolState.OutputAvailable,
        input = JSONObject().put("query", "lisbon").put("description", "Searching for your notes on Lisbon"),
        output = JSONArray(),
    )

    private val chat = AiChatState(
        title = "Plan my trip",
        chat = "did:ad:chat",
        window = WindowState(
            items = listOf(
                entry("1", "user", ChatPart.Text("What did I write about Lisbon?"), ctx = listOf(trip)),
                entry(
                    "2", "assistant", search,
                    ChatPart.Text("You have one note, [Lisbon trip](did:ad:trip). It lists:\n\n- **Flights**: arrive on Friday\n- Hotel in `Alfama`\n\n> Book the tram early."),
                ),
                entry("3", "user", ChatPart.Text("Thanks!")),
            ),
            loaded = true,
        ),
        ai = AiStatus.Ready,
    )

    @Test fun aiChat() = shot("ai-chat") { AiChatScreen(chat, ai) }
    @Test fun aiChatDark() = shot("ai-chat-dark", dark = true) { AiChatScreen(chat, ai) }

    @Test fun aiChatStreaming() = shot("ai-chat-streaming") {
        AiChatScreen(
            chat.copy(
                sending = true,
                partial = listOf(
                    ChatPart.Tool("c2", "get_atomic_resource", ToolState.InputAvailable, input = JSONObject().put("subjects", JSONArray(listOf("did:ad:trip")))),
                    ChatPart.Text("Reading it now, one momen"),
                ),
            ),
            ai,
        )
    }

    @Test fun aiChatNew() = shot("ai-chat-new") {
        AiChatScreen(
            AiChatState(
                ai = AiStatus.Ready,
                options = listOf(ContextItem("did:ad:d", "Pelican's Drive", "Drive"), trip, ContextItem("did:ad:t", "Budget", "table")),
                attached = listOf(trip),
            ),
            ai,
        )
    }

    @Test fun aiChatNoAccount() = shot("ai-chat-no-account") { AiChatScreen(chat.copy(ai = AiStatus.NoAccount, window = WindowState(loaded = true)), ai) }
    @Test fun aiChatNeedsConsent() = shot("ai-chat-needs-consent") { AiChatScreen(chat.copy(ai = AiStatus.NeedsConsent), ai) }

    private fun at(day: Int, h: Int, m: Int) =
        ZonedDateTime.now(ZoneId.systemDefault()).minusDays(day.toLong()).withHour(h).withMinute(m).toInstant().toEpochMilli()

    private val dm = ThreadState(
        title = "Robin",
        window = WindowState(
            items = listOf(
                message("1", "Are we still on for Friday?", at = at(1, 18, 2)),
                message("2", "Yes! I booked the table for 19:00.", mine = true, at = at(1, 18, 5)),
                message("3", "Perfect.", at = at(0, 9, 30)),
                message("4", "See you there", at = at(0, 9, 31)),
            ),
            loaded = true,
        ),
    )

    @Test fun conversation() = shot("conversation") { ThreadScreen(NativeKind.Conversation, dm, thread) }
    @Test fun conversationDark() = shot("conversation-dark", dark = true) { ThreadScreen(NativeKind.Conversation, dm, thread) }

    private val room = ThreadState(
        title = "Sprint planning",
        window = WindowState(
            items = listOf(
                message("e1", "Robin joined", event = true, at = at(0, 10, 0)),
                message("1", "Morning everyone", name = "Robin", at = at(0, 10, 1)),
                message("2", "Agenda is in the doc", name = "Robin", at = at(0, 10, 2)),
                message("3", "Thanks, reading it now", mine = true, at = at(0, 10, 4)),
            ),
            loaded = true,
        ),
        pending = listOf(message("pending-0", "Can we start with the budget?", mine = true, at = at(0, 10, 5))),
    )

    @Test fun chatRoom() = shot("chat-room") { ThreadScreen(NativeKind.Room, room, thread) }
    @Test fun threadFailedSend() = shot("conversation-send-failed") {
        ThreadScreen(NativeKind.Conversation, dm.copy(error = "Couldn't send: no peers online", unsent = "Hello?"), thread)
    }
    @Test fun threadEmpty() = shot("conversation-empty") { ThreadScreen(NativeKind.Conversation, ThreadState(title = "Robin", window = WindowState(loaded = true)), thread) }
}
