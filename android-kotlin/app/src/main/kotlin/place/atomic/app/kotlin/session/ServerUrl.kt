package place.atomic.app.kotlin.session

import java.net.URI

/**
 * Server URL rules, the twin of `flutter/lib/atomic/server_url.dart` (and the
 * data-browser's `serverUrl.ts`): the same address typed into either client
 * means the same thing.
 */

/**
 * A server address as typed, made into one that can be fetched. Local
 * addresses get `http` (a dev box has no certificate), the rest `https`; an
 * explicit scheme is kept. Empty stays empty.
 */
fun normalizeServerUrl(input: String): String {
    val trimmed = input.trim().trimEnd('/')
    if (trimmed.isEmpty()) return ""
    if (Regex("^https?://", RegexOption.IGNORE_CASE).containsMatchIn(trimmed)) return trimmed
    return "${if (isLocalAddress(trimmed)) "http" else "https"}://$trimmed"
}

/** Whether `authority` (`host` or `host:port`) names a machine on this network. */
fun isLocalAddress(authority: String): Boolean {
    val host = authority.substringBefore(':').lowercase()
    if (host == "localhost" || host == "::1" || host.endsWith(".local")) return true
    val octets = host.split('.')
    if (octets.size != 4 || octets.any { it.toIntOrNull() == null }) return false
    val (a, b) = octets[0].toInt() to octets[1].toInt()
    return a == 127 || a == 10 || (a == 192 && b == 168) || (a == 172 && b in 16..31)
}

private data class Origin(val scheme: String?, val host: String?, val port: Int)

private fun origin(url: String): Origin? = try {
    URI(url).let { Origin(it.scheme, it.host, it.port) }
} catch (_: Exception) {
    null
}

/** Whether two URLs point at the same server (scheme, host and port). */
fun sameOrigin(a: String, b: String?): Boolean {
    if (b.isNullOrEmpty()) return false
    val (x, y) = origin(a) to origin(b)
    return x != null && x == y
}

/** A server as shown to a person: the bare authority, keeping the port. */
fun serverLabel(url: String): String {
    val o = origin(url)
    if (o?.host.isNullOrEmpty()) return url
    return if (o!!.port != -1) "${o.host}:${o.port}" else o.host!!
}
