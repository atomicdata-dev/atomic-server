package place.atomic.app.kotlin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import place.atomic.app.kotlin.embed.EmbedAssets
import place.atomic.app.kotlin.embed.EmbedProtocol

// Robolectric only for org.json, which the Android jar stubs.
@RunWith(RobolectricTestRunner::class)
class EmbedProtocolTest {
    @Test
    fun aCallOfThePageIsParsed() {
        val r = EmbedProtocol.parse("""{"id":7,"method":"getResource","args":["did:ad:x"]}""")!!
        assertEquals(7, r.id)
        assertEquals("getResource", r.method)
        assertEquals("""["did:ad:x"]""", r.argsJson)
    }

    @Test
    fun aNotificationHasNoIdAndNoArgs() {
        val ready = EmbedProtocol.parse("""{"method":"ready"}""")!!
        assertNull(ready.id)
        assertEquals("[]", ready.argsJson)
        assertEquals(3, EmbedProtocol.parse("""{"method":"flushed","flush":3}""")!!.flushId)
    }

    @Test
    fun garbageIsNotAMessage() {
        assertNull(EmbedProtocol.parse("not json"))
        assertNull(EmbedProtocol.parse("""{"id":1}"""))
    }

    @Test
    fun aReplyCarriesTheResultAsOneJavaScriptString() {
        val json = """{"jsonAd":"{\"a\":\"b\"}","n":"line\nbreak"}"""
        val script = EmbedProtocol.replyScript(4, true, json)
        // The page JSON.parses the literal back into exactly the Rust answer.
        assertEquals(
            """window.__atomicReply(4,true,"{\"jsonAd\":\"{\\\"a\\\":\\\"b\\\"}\",\"n\":\"line\\nbreak\"}")""",
            script,
        )
    }

    @Test
    fun scriptsCannotBeBrokenOutOfByASubject() {
        val evil = "x\"); alert(1); (\" \n"
        val literal = EmbedProtocol.jsString(evil)
        assertFalse(literal.contains('\n'))
        assertFalse(literal.contains(' '))
        assertTrue(literal.startsWith("\"x\\\"); alert(1); (\\\""))
        assertTrue(EmbedProtocol.changedScript(listOf("a", "b")).endsWith("changed([\"a\",\"b\"])"))
    }

    @Test
    fun routeScriptsRenderAResourceByOpeningThePagesRoute() {
        assertEquals(
            "(function(e){if(!e)return;(e.open||e.show)(\"did:ad:abc\")})(window.atomicEmbed)",
            EmbedProtocol.openScript("did:ad:abc"),
        )
        assertTrue(EmbedProtocol.setColorSchemeScript(true).endsWith("setColorScheme(\"dark\")"))
        assertTrue(EmbedProtocol.flushScript(2, true).contains("flush:2"))
        assertTrue(EmbedProtocol.flushScript(2, true).contains("flush(true)"))
    }

    @Test
    fun theBundleIsServedUnderOneVirtualOriginAndNothingElse() {
        assertEquals("embed/embed.html", EmbedAssets.assetPath("https://appassets.androidplatform.net/embed.html?subject=a"))
        assertEquals("embed/embed.html", EmbedAssets.assetPath("https://appassets.androidplatform.net/"))
        assertEquals("embed/assets/index-1.js", EmbedAssets.assetPath("https://appassets.androidplatform.net/assets/index-1.js"))
        assertNull(EmbedAssets.assetPath("https://example.com/assets/index-1.js"))
        assertNull(EmbedAssets.assetPath("https://appassets.androidplatform.net.evil.com/embed.html"))
        assertNull(EmbedAssets.assetPath("https://appassets.androidplatform.net/../secret"))
        assertTrue(EmbedAssets.isOurs("https://appassets.androidplatform.net/embed.html"))
        assertFalse(EmbedAssets.isOurs("http://appassets.androidplatform.net/embed.html"))
    }

    @Test
    fun theColdPageUrlCarriesTheSubject() {
        assertEquals("https://appassets.androidplatform.net/embed.html", EmbedAssets.pageUrl())
        assertEquals(
            "https://appassets.androidplatform.net/embed.html?subject=did%3Aad%3Aabc",
            EmbedAssets.pageUrl("did:ad:abc"),
        )
    }

    @Test
    fun scriptsAndWasmGetTypesTheBrowserWillRun() {
        assertEquals("text/javascript", EmbedAssets.mimeType("embed/assets/a.js"))
        assertEquals("application/wasm", EmbedAssets.mimeType("embed/assets/loro_bg.wasm"))
        assertEquals("font/woff2", EmbedAssets.mimeType("embed/assets/f.woff2"))
        assertTrue(EmbedAssets.cacheControl("embed/assets/a.js").contains("immutable"))
        assertEquals("no-cache", EmbedAssets.cacheControl("embed/embed.html"))
    }
}
