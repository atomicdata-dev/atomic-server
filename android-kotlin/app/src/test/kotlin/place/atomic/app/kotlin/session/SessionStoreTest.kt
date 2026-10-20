package place.atomic.app.kotlin.session

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MapKeyValue(val map: MutableMap<String, String> = mutableMapOf()) : KeyValue {
    override fun getString(key: String) = map[key]
    override fun putString(key: String, value: String?) {
        if (value == null) map.remove(key) else map[key] = value
    }
}

/** Not secure, only reversible: proves the secret is not stored as it is. */
class ReverseBox : SecretBox {
    override fun seal(plain: String) = plain.reversed()
    override fun open(sealed: String): String? = sealed.reversed()
}

class SessionStoreTest {
    private val drive = "did:ad:abc"

    @Test
    fun a_saved_session_is_read_back_by_a_new_store_over_the_same_storage() {
        val kv = MapKeyValue()
        SessionStore(kv, ReverseBox()).save("s3cret", "https://x.example", drive)
        val loaded = SessionStore(kv, ReverseBox()).load()
        assertEquals(Session("s3cret", "https://x.example", drive), loaded)
    }

    @Test
    fun the_secret_is_not_stored_in_the_clear() {
        val kv = MapKeyValue()
        SessionStore(kv, ReverseBox()).save("s3cret")
        assertFalse(kv.map.values.any { it == "s3cret" })
    }

    @Test
    fun nothing_saved_is_no_session_and_an_unopenable_secret_too() {
        assertNull(SessionStore(MapKeyValue(), ReverseBox()).load())
        val kv = MapKeyValue()
        SessionStore(kv, ReverseBox()).save("s3cret")
        val lost = object : SecretBox {
            override fun seal(plain: String) = plain
            override fun open(sealed: String): String? = null
        }
        assertNull(SessionStore(kv, lost).load())
    }

    @Test
    fun only_a_drive_that_can_be_found_again_is_remembered() {
        val store = SessionStore(MapKeyValue(), ReverseBox())
        store.save("s", drive = "https://x.example/drive/1")
        assertNull(store.load()?.drive)
        store.saveDrive(drive)
        assertEquals(drive, store.load()?.drive)
    }

    @Test
    fun clear_forgets_the_session() {
        val store = SessionStore(MapKeyValue(), ReverseBox())
        store.save("s", "https://x.example", drive)
        store.clear()
        assertNull(store.load())
    }

    @Test
    fun servers_are_normalized_deduplicated_and_removing_the_active_one_clears_it() {
        val store = SessionStore(MapKeyValue(), ReverseBox())
        store.addKnownServer("localhost:9883")
        store.addKnownServer("http://localhost:9883/")
        store.setActiveServer("example.org")
        assertEquals(listOf("http://localhost:9883", "https://example.org"), store.knownServers())
        assertEquals("https://example.org", store.activeServer())
        store.removeKnownServer("example.org")
        assertNull(store.activeServer())
        assertEquals(listOf("http://localhost:9883"), store.knownServers())
    }
}

class ServerUrlTest {
    @Test
    fun local_addresses_get_http_and_others_https() {
        assertEquals("http://localhost:9883", normalizeServerUrl(" localhost:9883/ "))
        assertEquals("http://192.168.1.4:9883", normalizeServerUrl("192.168.1.4:9883"))
        assertEquals("https://atomicserver.eu", normalizeServerUrl("atomicserver.eu"))
        assertEquals("http://x.example", normalizeServerUrl("http://x.example"))
        assertEquals("", normalizeServerUrl("  "))
    }

    @Test
    fun private_ranges_are_local_and_public_ones_not() {
        assertTrue(isLocalAddress("172.20.0.1"))
        assertFalse(isLocalAddress("172.32.0.1"))
        assertFalse(isLocalAddress("8.8.8.8"))
    }

    @Test
    fun same_origin_ignores_paths_and_the_label_keeps_the_port() {
        assertTrue(sameOrigin("https://a.example/x", "https://a.example"))
        assertFalse(sameOrigin("https://a.example", "http://a.example"))
        assertFalse(sameOrigin("https://a.example", null))
        assertEquals("localhost:9883", serverLabel("http://localhost:9883"))
        assertEquals("a.example", serverLabel("https://a.example"))
    }
}
