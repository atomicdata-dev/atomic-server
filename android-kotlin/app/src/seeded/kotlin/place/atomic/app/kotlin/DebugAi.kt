package place.atomic.app.kotlin

import android.content.Context
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.flow
import org.json.JSONArray
import org.json.JSONObject
import place.atomic.app.kotlin.chat.AiProvider
import place.atomic.app.kotlin.chat.HostedAi

/**
 * A scripted AI for debug and benchmark builds (release has a stub), so the chat
 * can be run and timed without an account: while a `fake_ai` file exists in the
 * app's external files directory
 * (`adb shell "touch /sdcard/Android/data/place.atomic.app.kotlin/files/fake_ai"`)
 * the chat answers with a streamed reply. When the last message contains
 * "search" the model first calls `semantic_search`, as the real one does.
 */
object DebugAi {
    fun provider(context: Context): AiProvider? {
        val flag = context.getExternalFilesDir(null)?.resolve("fake_ai") ?: return null
        if (!flag.exists()) return null
        return AiProvider { HostedAi(status = STATUS, completions = ::complete, onEnable = { STATUS }) }
    }

    private val STATUS = JSONObject().put("enabled", true).put("consent", true).put("model", "fake").put("remaining_micros", 1_000_000)

    private fun complete(messages: JSONArray, @Suppress("UNUSED_PARAMETER") model: String, tools: JSONArray?) = flow {
        val last = messages.optJSONObject(messages.length() - 1)
        val afterTool = last?.optString("role") == "tool"
        val asked = last?.optString("content").orEmpty()
        if (tools != null && !afterTool && asked.contains("search", ignoreCase = true)) {
            emit(
                chunk(
                    JSONObject().put(
                        "tool_calls",
                        JSONArray().put(
                            JSONObject().put("index", 0).put("id", "fake-1").put(
                                "function",
                                JSONObject().put("name", "semantic_search").put("arguments", """{"query":"notes"}"""),
                            ),
                        ),
                    ),
                ),
            )
            return@flow
        }
        for (word in "This is a scripted answer, streamed one word at a time.".split(' ')) {
            delay(40)
            emit(chunk(JSONObject().put("content", "$word ")))
        }
    }

    private fun chunk(delta: JSONObject) = JSONObject().put("choices", JSONArray().put(JSONObject().put("delta", delta)))
}
