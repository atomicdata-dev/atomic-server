package place.atomic.app.kotlin.session

/** What start-up needs to sign in again: the agent's secret and where it was working. */
data class Session(val secret: String, val serverUrl: String, val drive: String?)

/** Plain key/value storage (SharedPreferences on the phone, a map in tests). */
interface KeyValue {
    fun getString(key: String): String?
    fun putString(key: String, value: String?)
}

/** Seals the secret at rest (Android Keystore on the phone). */
interface SecretBox {
    fun seal(plain: String): String

    /** The secret, or `null` when it cannot be opened (key lost, data damaged). */
    fun open(sealed: String): String?
}

/**
 * The session across restarts, the twin of Flutter's `AtomicSession`. The
 * agent's secret is the one sensitive value (it is the account's private key)
 * and goes through [SecretBox]; the rest is routing state. The Rust store does
 * not keep the agent, so without this every start would look like a first run.
 */
class SessionStore(private val kv: KeyValue, private val box: SecretBox) {
    fun save(secret: String, serverUrl: String = "", drive: String? = null) {
        kv.putString(KEY_SECRET, box.seal(secret))
        kv.putString(KEY_SERVER, serverUrl)
        if (isResumableDrive(drive)) kv.putString(KEY_DRIVE, drive)
        if (serverUrl.isNotEmpty()) addKnownServer(serverUrl)
    }

    fun load(): Session? {
        val sealed = kv.getString(KEY_SECRET) ?: return null
        val secret = box.open(sealed)?.takeIf { it.isNotEmpty() } ?: return null
        val drive = kv.getString(KEY_DRIVE)?.takeIf(::isResumableDrive)
        return Session(secret, kv.getString(KEY_SERVER).orEmpty(), drive)
    }

    /** Only a drive that can be found again from its own subject is worth remembering. */
    fun saveDrive(drive: String) {
        if (isResumableDrive(drive)) kv.putString(KEY_DRIVE, drive)
    }

    fun clear() {
        listOf(KEY_SECRET, KEY_SERVER, KEY_DRIVE, KEY_ACCOUNT).forEach { kv.putString(it, null) }
    }

    // ── The linked atomic.place account (its AI) ──

    /**
     * The account's session at the portal, a cookie or token for one origin: as
     * sensitive as the secret, so it is sealed the same way (Flutter keeps it in
     * secure storage too). `null` when no account is linked.
     */
    fun accountSession(): String? = kv.getString(KEY_ACCOUNT)?.let(box::open)?.takeIf { it.isNotEmpty() }

    fun saveAccountSession(session: String?) = kv.putString(KEY_ACCOUNT, session?.let(box::seal))

    // ── Servers: one active, the others remembered so switching is a tap ──

    fun knownServers(): List<String> =
        kv.getString(KEY_SERVERS)?.split('\n')?.filter { it.isNotEmpty() }.orEmpty()

    /** The server in use, `null` when syncing device to device only. */
    fun activeServer(): String? = kv.getString(KEY_SERVER)?.takeIf { it.isNotEmpty() }

    fun addKnownServer(url: String) {
        val normalized = normalizeServerUrl(url)
        if (normalized.isEmpty()) return
        val servers = knownServers()
        if (servers.any { sameOrigin(it, normalized) }) return
        kv.putString(KEY_SERVERS, (servers + normalized).joinToString("\n"))
    }

    fun setActiveServer(url: String) {
        val normalized = normalizeServerUrl(url)
        kv.putString(KEY_SERVER, normalized)
        addKnownServer(normalized)
    }

    /** Forgets `url`; clears the active server too when it was the one removed. */
    fun removeKnownServer(url: String) {
        val normalized = normalizeServerUrl(url)
        kv.putString(KEY_SERVERS, knownServers().filterNot { sameOrigin(it, normalized) }.joinToString("\n"))
        if (sameOrigin(normalized, activeServer())) kv.putString(KEY_SERVER, "")
    }

    companion object {
        private const val KEY_SECRET = "atomic_agent_secret_sealed"
        private const val KEY_SERVER = "atomic_server_url"
        private const val KEY_DRIVE = "atomic_drive"
        private const val KEY_ACCOUNT = "atomic_account_session_sealed"
        private const val KEY_SERVERS = "atomic_known_servers"

        fun isResumableDrive(drive: String?): Boolean =
            drive != null && (drive.startsWith("did:ad:") || drive.startsWith("atomic:"))
    }
}
