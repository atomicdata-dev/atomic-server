package place.atomic.app.kotlin.chat

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import place.atomic.app.kotlin.session.SessionStore
import java.io.BufferedReader
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

/** A reply of the portal. Header names are lower case. */
class HttpReply(val status: Int, val headers: Map<String, List<String>>, val body: InputStream)

/** The one place that talks HTTP, so tests can answer for the portal. Blocking: call it off the main thread. */
fun interface HttpEngine {
    fun send(method: String, url: String, headers: Map<String, String>, body: String?, timeoutMs: Int): HttpReply
}

/** `HttpURLConnection` with the system's trust store; never follows a redirect, as the credentials stay on one origin. */
object UrlConnectionEngine : HttpEngine {
    override fun send(method: String, url: String, headers: Map<String, String>, body: String?, timeoutMs: Int): HttpReply {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.requestMethod = method
        conn.instanceFollowRedirects = false
        conn.connectTimeout = timeoutMs
        conn.readTimeout = 60_000
        headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
        if (body != null) {
            conn.doOutput = true
            conn.outputStream.use { it.write(body.toByteArray()) }
        }
        val status = conn.responseCode
        val stream = (if (status in 200..399) conn.inputStream else conn.errorStream) ?: "".byteInputStream()
        val reply = conn.headerFields.filterKeys { it != null }.mapKeys { it.key.lowercase() }
        return HttpReply(status, reply, stream)
    }
}

/**
 * The account of the atomic.place portal, for what the chat needs: sign in as
 * the agent, the included AI's status and consent, and the streamed chat
 * completions. Twin of Flutter's `AtomicAccountClient` (without device links
 * and recovery, which this app does not have yet). Credentials stay bound to
 * one HTTPS origin; the session is a `session_token` cookie (agent sign-in) or
 * a bearer token (a linked device). Every call blocks: run it on `Dispatchers.IO`.
 */
class AccountClient(provider: String, private val http: HttpEngine = UrlConnectionEngine) {
    val origin: String = providerOrigin(provider)
    private var token: String? = null
    private var cookie: String? = null
    val linked get() = token != null || cookie != null

    /** The saved form of the session (only the credential store may keep it). */
    fun exportSession(): String = JSONObject().put("origin", origin)
        .apply { if (token != null) put("token", token) else put("cookie", cookie) }.toString()

    fun restoreSession(saved: String) {
        val data = JSONObject(saved)
        val key = if (data.optString("token").isNotEmpty()) "token" else "cookie"
        if (providerOrigin(data.optString("origin")) != origin || data.optString(key).isEmpty()) {
            error("This session belongs to another provider")
        }
        token = if (key == "token") data.getString(key) else null
        cookie = if (key == "cookie") data.getString(key) else null
    }

    /**
     * Sign in with the Atomic agent, as the web app does: the portal issues a
     * challenge, [sign] signs `"<challenge> <timestamp>"` with the agent key and
     * the portal answers 204 with a session cookie. False when the agent is not
     * an account's identity (no session is made); throws when the portal cannot
     * be reached.
     */
    fun signInWithAgent(agentSubject: String, sign: (String) -> String, now: () -> Long = System::currentTimeMillis): Boolean {
        val issued = request("POST", "auth/agent/challenge", JSONObject().put("agent_subject", agentSubject), authenticated = false)
        if (issued.status != 200) return false
        val challenge = runCatching { JSONObject(issued.text) }.getOrNull() ?: return false
        val nonce = challenge.optString("nonce")
        val text = challenge.optString("challenge")
        if (nonce.isEmpty() || text.isEmpty()) return false
        val timestamp = now()
        val response = request(
            "POST", "auth/agent",
            JSONObject().put("nonce", nonce).put("timestamp", timestamp).put("signature", sign("$text $timestamp")),
            query = "if_linked=true", authenticated = false,
        )
        // Only 204 makes a session; 200 with signed_in:false means no account.
        if (response.status != 204) return false
        val set = response.headers["set-cookie"].orEmpty().joinToString(",")
        val value = COOKIE.find(set)?.groupValues?.get(1)?.takeIf { it.isNotEmpty() } ?: return false
        token = null
        cookie = value
        return true
    }

    /** The included AI: whether it is on, consent, model, credits left. Null when the portal offers none (404) or the session is not valid (401). */
    fun aiStatus(): JSONObject? {
        val r = request("GET", "ai/status")
        if (r.status == 404 || r.status == 401) return null
        return r.obj()
    }

    /** Accept the included-AI terms for this account. */
    fun aiConsent(): JSONObject = request("POST", "ai/consent", JSONObject().put("accepted", true)).obj()

    /**
     * One streamed answer, chunk by chunk: the decoded JSON of each `data:` line
     * of the OpenAI-compatible `chat/completions` stream. [messages] may carry
     * tool calls and results, [tools] the functions the model may call (the
     * portal passes them on; the caller runs them). Throws with the portal's own
     * message when it refuses, and on an error chunk.
     */
    fun chatCompletionChunks(messages: JSONArray, model: String, tools: JSONArray?): Flow<JSONObject> = flow {
        if (!linked) error("Sign in first")
        val body = JSONObject().put("model", model).put("messages", messages).put("stream", true)
        if (tools != null && tools.length() > 0) body.put("tools", tools).put("tool_choice", "auto")
        val reply = try {
            http.send("POST", "$origin/api/ai/chat/completions", authorize(mapOf("Content-Type" to "application/json", "Accept" to "text/event-stream")), body.toString(), 30_000)
        } catch (e: java.io.IOException) {
            error("Could not reach the account provider")
        }
        if (reply.status !in 200..299) {
            val text = reply.body.use { it.readBytes().decodeToString() }
            var message = "Included AI is unavailable (${reply.status})"
            runCatching { JSONObject(text).optString("error").takeIf { it.isNotEmpty() } }.getOrNull()?.let { message = it }
            if (reply.status == 401) message = "Sign in again to continue"
            error(message)
        }
        reply.body.bufferedReader().use { reader -> parseCompletionChunks(reader).forEach { emit(it) } }
    }.flowOn(Dispatchers.IO)

    private class Reply(val status: Int, val headers: Map<String, List<String>>, val text: String) {
        fun obj(): JSONObject {
            if (status !in 200..299) {
                error(
                    when (status) {
                        401 -> "Sign in again to continue"
                        429 -> "Too many attempts. Try again shortly"
                        else -> "Account request failed ($status)"
                    },
                )
            }
            return runCatching { JSONObject(text) }.getOrElse { throw IllegalStateException("Invalid account response") }
        }
    }

    private fun request(method: String, path: String, body: JSONObject? = null, query: String? = null, authenticated: Boolean = true): Reply {
        if (authenticated && !linked) error("Sign in first")
        val url = "$origin/api/$path" + (query?.let { "?$it" } ?: "")
        var headers = mapOf("Accept" to "application/json")
        if (body != null) headers = headers + ("Content-Type" to "application/json")
        if (authenticated) headers = authorize(headers)
        return try {
            val reply = http.send(method, url, headers, body?.toString(), 20_000)
            Reply(reply.status, reply.headers, reply.body.use { it.readBytes().decodeToString() })
        } catch (e: java.io.IOException) {
            // Network exceptions can contain the polling URL.
            throw IllegalStateException("Could not reach the account provider")
        }
    }

    /** A bearer token needs nothing more. A cookie session also names the portal as `Origin`, which it requires of writes. */
    private fun authorize(headers: Map<String, String>): Map<String, String> = headers + when {
        token != null -> mapOf("Authorization" to "Bearer $token")
        else -> mapOf("Cookie" to "session_token=$cookie", "Origin" to origin)
    }

    companion object {
        private val COOKIE = Regex("""(?:^|[\s,])session_token=([^;,\s]+)""")

        /** The portal as an origin: HTTPS, no path, query or credentials. */
        fun providerOrigin(input: String): String {
            val uri = runCatching { java.net.URI(input.trim()) }.getOrNull()
            require(
                uri != null && uri.scheme == "https" && !uri.host.isNullOrEmpty() && uri.userInfo == null &&
                    uri.query == null && uri.fragment == null && (uri.path.isNullOrEmpty() || uri.path == "/"),
            ) { "An account provider must be an HTTPS origin" }
            return "https://${uri!!.host}" + if (uri.port != -1) ":${uri.port}" else ""
        }

        /** The portal a saved session belongs to. */
        fun sessionOrigin(saved: String): String = providerOrigin(JSONObject(saved).getString("origin"))

        /**
         * The decoded JSON chunks of a server-sent-events completion stream, up to
         * `[DONE]`. Comments (`: OPENROUTER PROCESSING`) and lines that are not JSON
         * are skipped; an error chunk throws.
         */
        fun parseCompletionChunks(reader: BufferedReader): Sequence<JSONObject> = sequence {
            while (true) {
                val line = (reader.readLine() ?: break).trim()
                if (!line.startsWith("data:")) continue
                val data = line.removePrefix("data:").trim()
                if (data == "[DONE]") break
                val json = runCatching { JSONObject(data) }.getOrNull() ?: continue
                if (json.has("error") && !json.isNull("error")) {
                    val error = json.get("error")
                    throw IllegalStateException(
                        if (error is JSONObject) error.optString("message").ifEmpty { "Included AI failed" } else "$error",
                    )
                }
                yield(json)
            }
        }
    }
}

/** The AI of the linked account, as the chat screens look it up. */
fun interface AiProvider {
    /** The account's AI; null when no account is linked or the portal offers none. Throws when the portal cannot be reached. */
    suspend fun hostedAi(): HostedAi?
}

/**
 * The linked account's session lives in the [SessionStore] next to the agent
 * secret (sealed by the Keystore), never in plain preferences. With none saved,
 * the active agent signs the account in first (as the web app does), so an
 * agent that is an account identity needs no link code. This is the one route
 * of the app's AI: the account's credits, nothing else.
 */
class AccountAi(
    private val store: SessionStore,
    private val agentSubject: () -> String?,
    private val sign: (String) -> String,
    private val http: HttpEngine = UrlConnectionEngine,
    private val portal: String = DEFAULT_PORTAL,
) : AiProvider {
    private var attemptedAgent: String? = null

    override suspend fun hostedAi(): HostedAi? = withContext(Dispatchers.IO) {
        var saved = store.accountSession()
        if (saved == null && signIn()) saved = store.accountSession()
        if (saved == null) return@withContext null
        val client = AccountClient(AccountClient.sessionOrigin(saved), http).also { it.restoreSession(saved) }
        val status = client.aiStatus() ?: return@withContext null
        HostedAi(
            status = status,
            completions = client::chatCompletionChunks,
            onEnable = { withContext(Dispatchers.IO) { client.aiConsent() } },
        )
    }

    /** Signs the account in with the active agent. True when a session is now saved; quiet otherwise (no account, no agent). */
    private fun signIn(): Boolean {
        val subject = agentSubject() ?: return false
        if (attemptedAgent == subject) return false
        return try {
            val client = AccountClient(portal, http)
            val signedIn = client.signInWithAgent(subject, sign)
            // A refusal is final for this run; an unreachable portal throws below.
            attemptedAgent = subject
            if (signedIn) store.saveAccountSession(client.exportSession())
            signedIn
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        const val DEFAULT_PORTAL = "https://atomic.place"
    }
}
