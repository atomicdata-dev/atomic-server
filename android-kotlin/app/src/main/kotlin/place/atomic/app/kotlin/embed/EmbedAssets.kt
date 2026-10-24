package place.atomic.app.kotlin.embed

/**
 * What the WebView may load: the bundled embed (`assets/embed/`, built from
 * `browser/data-browser` by `scripts/build_embed.sh`) under a virtual HTTPS
 * origin, and nothing else. The page has no network: its data comes over the
 * JavaScript channel.
 */
object EmbedAssets {
    const val ASSET_DIR = "embed"
    const val PAGE_URL = "${EmbedProtocol.ORIGIN}/embed.html"

    /** The page's URL; [subject] makes a cold (not pre-loaded) page open on it. */
    fun pageUrl(subject: String? = null): String =
        if (subject.isNullOrEmpty()) PAGE_URL else PAGE_URL + "?subject=" + java.net.URLEncoder.encode(subject, "UTF-8")

    /**
     * A cold page that opens one of the web app's own pages ([path], such as `/app/new-drive`)
     * instead of a resource: the embed reads `path` only when it loads.
     */
    fun actionUrl(path: String, dark: Boolean? = null): String =
        PAGE_URL + "?path=" + java.net.URLEncoder.encode(path, "UTF-8") +
            (dark?.let { "&scheme=" + if (it) "dark" else "light" } ?: "")

    /** Is [url] a page of the bundled origin (everything else is not ours to load)? */
    fun isOurs(url: String): Boolean = url == EmbedProtocol.ORIGIN || url.startsWith(EmbedProtocol.ORIGIN + "/")

    /**
     * The file inside `assets/embed/` that [url] names, or null when it is not
     * a bundled file (another origin, a path out of the folder).
     */
    fun assetPath(url: String): String? {
        if (!isOurs(url)) return null
        val path = url.removePrefix(EmbedProtocol.ORIGIN).substringBefore('#').substringBefore('?')
        if (path.contains("..") || path.contains('\\')) return null
        val relative = path.trimStart('/').ifEmpty { "embed.html" }
        return "$ASSET_DIR/$relative"
    }

    /**
     * Android's `MimeTypeMap` does not know WebAssembly, and a module script
     * needs a JavaScript type, so the types are fixed here.
     */
    fun mimeType(path: String): String = when (path.substringAfterLast('.', "").lowercase()) {
        "html" -> "text/html"
        "js", "mjs" -> "text/javascript"
        "css" -> "text/css"
        "json", "map" -> "application/json"
        "wasm" -> "application/wasm"
        "svg" -> "image/svg+xml"
        "png" -> "image/png"
        "jpg", "jpeg" -> "image/jpeg"
        "webp" -> "image/webp"
        "gif" -> "image/gif"
        "ico" -> "image/x-icon"
        "woff2" -> "font/woff2"
        "woff" -> "font/woff"
        "ttf" -> "font/ttf"
        "txt" -> "text/plain"
        else -> "application/octet-stream"
    }

    /** Built files carry a content hash in their name. */
    fun cacheControl(path: String) =
        if (path.startsWith("$ASSET_DIR/assets/")) "max-age=31536000, immutable" else "no-cache"
}
