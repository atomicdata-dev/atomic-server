package place.atomic.app.kotlin.embed

import org.json.JSONArray
import org.json.JSONObject

/**
 * The wire format between the embedded page (`browser/data-browser/src/embed`)
 * and this app. It is the Flutter app's contract, unchanged:
 *
 *  - page to app: `AtomicFlutter.postMessage('{"id":1,"method":"…","args":[…]}')`
 *    (the JavaScript interface is called `AtomicFlutter` so the same bundle
 *    runs in both apps); `{"method":"ready"}` and `{"method":"flushed",…}` are
 *    notifications without an id,
 *  - app to page: `window.__atomicReply(id, ok, payload)`, `payload` being the
 *    JSON text of the result (or the error text),
 *  - app to page, host API: `window.atomicEmbed.{open,show,changed,back,flush,setColorScheme}`.
 */
object EmbedProtocol {
    /** Name of the JavaScript interface the page's `createFlutterHost` looks for. */
    const val CHANNEL_NAME = "AtomicFlutter"

    /** The virtual origin the bundle is served from (see [EmbedAssets]). */
    const val HOST = "appassets.androidplatform.net"
    const val ORIGIN = "https://$HOST"

    /** A message from the page. [id] is null for notifications. */
    data class Request(val id: Int?, val method: String, val argsJson: String, val flushId: Int?, val ms: Long? = null)

    /** Parses one message of the page; null when it is not one of ours. */
    fun parse(message: String): Request? = try {
        val json = JSONObject(message)
        Request(
            id = if (json.has("id")) json.getInt("id") else null,
            method = json.getString("method"),
            argsJson = (json.optJSONArray("args") ?: JSONArray()).toString(),
            flushId = if (json.has("flush")) json.getInt("flush") else null,
            ms = if (json.has("ms")) json.optLong("ms") else null,
        )
    } catch (_: Exception) {
        null
    }

    /** [text] as a JavaScript string literal, safe to splice into a script. */
    fun jsString(text: String): String {
        val out = StringBuilder(text.length + 2).append('"')
        for (c in text) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == ' ' -> out.append("\\u2028")
                c == ' ' -> out.append("\\u2029")
                c < ' ' -> out.append("\\u%04x".format(c.code))
                else -> out.append(c)
            }
        }
        return out.append('"').toString()
    }

    /** The answer to call [id]: [payload] is the JSON of the result, or the error text. */
    fun replyScript(id: Int, ok: Boolean, payload: String) =
        "window.__atomicReply($id,$ok,${jsString(payload)})"

    /** Renders [subject]; replaces the current history entry so back leaves the resource. */
    fun openScript(subject: String) =
        "(function(e){if(!e)return;(e.open||e.show)(${jsString(subject)})})(window.atomicEmbed)"

    /** These resources changed in the store: the page reads them again. */
    fun changedScript(subjects: List<String>) =
        "window.atomicEmbed&&window.atomicEmbed.changed&&window.atomicEmbed.changed(" +
            subjects.joinToString(",", "[", "]") { jsString(it) } + ")"

    /**
     * `[perf] resource painted`: posts `painted` two frames after the page's `main`
     * shows [title], with the page's own clock (from this script when [warm], from
     * the page's load when not). Twin of Flutter's `_watchPainted`.
     */
    fun paintedScript(title: String, warm: Boolean): String {
        val since = if (warm) "Date.now()" else "Date.now()-performance.now()"
        return "(function(){var t0=$since,s=Date.now();function c(){" +
            "var m=document.querySelector(\"main\");" +
            "if(m&&m.innerText.indexOf(${jsString(title)})>=0){requestAnimationFrame(" +
            "function(){requestAnimationFrame(function(){" +
            "AtomicFlutter.postMessage(JSON.stringify({method:\"painted\"," +
            "ms:Date.now()-t0}))})});return}" +
            "if(Date.now()-s<20000)setTimeout(c,16)}c()})()"
    }

    /**
     * `[perf] resource revealed`: posts `revealed` two frames after `main[about=subject]`
     * holds more than a loading state (or after 1.5 s). Twin of Flutter's `_watchReveal`.
     */
    fun revealedScript(subject: String) =
        "(function(){var s=${jsString(subject)},t=Date.now();" +
            "function done(){requestAnimationFrame(function(){" +
            "requestAnimationFrame(function(){AtomicFlutter.postMessage(" +
            "JSON.stringify({method:\"revealed\",ms:Date.now()-t}))})})}" +
            "function c(){var all=document.querySelectorAll(\"main\"),m=null;" +
            "for(var i=0;i<all.length;i++)if(all[i].getAttribute(\"about\")===s)" +
            "m=all[i];if((m&&m.children.length>1&&" +
            "!m.querySelector(\"[role=status]\"))||Date.now()-t>1500){done();" +
            "return}setTimeout(c,16)}c()})()"

    fun setColorSchemeScript(dark: Boolean) =
        "window.atomicEmbed&&window.atomicEmbed.setColorScheme&&" +
            "window.atomicEmbed.setColorScheme(${if (dark) "\"dark\"" else "\"light\""})"

    /** One step back inside the page (an overlay, a form); evaluates to `true` when it went. */
    const val BACK_SCRIPT = "window.atomicEmbed?window.atomicEmbed.back()===true:false"

    /** Hands every pending edit to the app, then posts `flushed` with [flushId]. */
    fun flushScript(flushId: Int, leaving: Boolean): String {
        val done = "function(){$CHANNEL_NAME.postMessage(JSON.stringify({method:'flushed',flush:$flushId}))}"
        return "Promise.resolve(window.atomicEmbed&&window.atomicEmbed.flush&&" +
            "window.atomicEmbed.flush($leaving)).then($done,$done)"
    }
}
