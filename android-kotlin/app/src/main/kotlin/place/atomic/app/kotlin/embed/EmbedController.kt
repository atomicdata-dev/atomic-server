package place.atomic.app.kotlin.embed

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.MutableContextWrapper
import android.content.pm.ApplicationInfo
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.ByteArrayInputStream
import kotlin.coroutines.resume

/**
 * The one warm WebView. It loads the bundled embed once, when the app is ready
 * ([warm]), and is kept alive: opening a resource is a route change inside the
 * page (`atomicEmbed.open`), not a page load, and leaving it blanks the route.
 *
 * The page has no database and no network: [EmbedWebViewClient] serves its
 * files from the app's assets and refuses everything else, and every read and
 * write goes through `AtomicFlutter.postMessage` into [EmbedBridge], which
 * calls Rust. The secret key never enters the page; commits are signed there.
 */
class EmbedController(
    context: Context,
    private val scope: CoroutineScope,
    private val core: EmbedCore,
    onOpenNative: (kind: String, subject: String, title: String) -> Boolean = { _, _, _ -> false },
) {
    private val appContext = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private var webView: WebView? = null
    private var holder: MutableContextWrapper? = null

    private val page = object : EmbedPage {
        override fun run(script: String) {
            main.post { webView?.evaluateJavascript(script, null) }
        }

        override suspend fun evaluate(script: String): String? = suspendCancellableCoroutine { cont ->
            main.post {
                val view = webView
                if (view == null) cont.resume(null) else view.evaluateJavascript(script) { cont.resume(it) }
            }
        }
    }

    val bridge = EmbedBridge(scope, core, page, onOpenNative = onOpenNative)

    /** Creates the WebView (on the main thread) and starts loading the embed. Idempotent. */
    fun warm() {
        if (webView == null) webView = create()
    }

    /**
     * The WebView for a screen to show. It moves between screens, so it is
     * taken out of its previous parent, and its context follows the activity
     * that shows it (dialogs need one).
     */
    fun attach(activity: Context): WebView {
        warm()
        val view = webView!!
        holder?.baseContext = activity
        (view.parent as? ViewGroup)?.removeView(view)
        // Without parameters the holder adds it as wrap_content, which for a
        // page whose height is `100dvh - …` is no height at all.
        view.layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        view.onResume()
        // The page measured its viewport while it was away; tell it the real one.
        view.post { view.evaluateJavascript("window.dispatchEvent(new Event('resize'))", null) }
        return view
    }

    /** The screen is gone: the view stays alive for the next resource. */
    fun detach() {
        val view = webView ?: return
        (view.parent as? ViewGroup)?.removeView(view)
        holder?.baseContext = appContext
        view.onPause()
    }

    fun destroy() {
        webView?.let {
            (it.parent as? android.view.ViewGroup)?.removeView(it)
            it.destroy()
        }
        webView = null
        holder = null
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun create(): WebView {
        val wrapper = MutableContextWrapper(appContext)
        holder = wrapper
        val view = WebView(wrapper)
        if ((appContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            WebView.setWebContentsDebuggingEnabled(true)
        }
        view.setBackgroundColor(Color.TRANSPARENT)
        giveScreenSize(view)
        view.settings.apply {
            javaScriptEnabled = true
            // The page's own settings (theme, locale) live in localStorage.
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            blockNetworkLoads = true
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            setSupportZoom(false)
            mediaPlaybackRequiresUserGesture = true
        }
        view.addJavascriptInterface(Channel(bridge), EmbedProtocol.CHANNEL_NAME)
        view.webViewClient = EmbedWebViewClient(
            context = appContext,
            onStarted = bridge::pageStarted,
            onGone = {
                // The renderer died (memory pressure): start over with a new view.
                main.post {
                    destroy()
                    warm()
                }
            },
        )
        view.loadUrl(EmbedAssets.PAGE_URL)
        return view
    }

    /**
     * A WebView that was never attached is 0 x 0, and the page lays itself out
     * for the viewport it loads in: `100dvh` and `visualViewport.height` were 0,
     * so `main` computed to 0px and only the breadcrumb showed (Samsung Tab
     * S9+). The Flutter host keeps its warm page at screen size. Lay the view
     * out at the screen's size before the page loads; the screen then resizes it.
     */
    private fun giveScreenSize(view: WebView) {
        val metrics = appContext.resources.displayMetrics
        view.layoutParams = ViewGroup.LayoutParams(metrics.widthPixels, metrics.heightPixels)
        view.measure(
            View.MeasureSpec.makeMeasureSpec(metrics.widthPixels, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(metrics.heightPixels, View.MeasureSpec.EXACTLY),
        )
        view.layout(0, 0, metrics.widthPixels, metrics.heightPixels)
    }

    /** Only [EmbedProtocol.CHANNEL_NAME] is exposed to the page. */
    private class Channel(private val bridge: EmbedBridge) {
        @JavascriptInterface
        fun postMessage(message: String) = bridge.onMessage(message)
    }
}

/** Serves the bundle from assets and keeps the page on its own origin. */
internal class EmbedWebViewClient(
    private val context: Context,
    private val onStarted: () -> Unit,
    private val onGone: () -> Unit,
) : WebViewClient() {
    override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
        val url = request.url.toString()
        val path = EmbedAssets.assetPath(url) ?: return blocked(403, "Forbidden")
        return try {
            WebResourceResponse(
                EmbedAssets.mimeType(path), null, 200, "OK",
                mapOf("Cache-Control" to EmbedAssets.cacheControl(path)),
                context.assets.open(path),
            )
        } catch (_: java.io.IOException) {
            blocked(404, "Not Found")
        }
    }

    private fun blocked(status: Int, reason: String) =
        WebResourceResponse("text/plain", "utf-8", status, reason, emptyMap(), ByteArrayInputStream(ByteArray(0)))

    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        val url = request.url.toString()
        if (EmbedAssets.isOurs(url)) return false
        // A link out of the page opens in the system, never inside this view.
        if (request.url.scheme == "http" || request.url.scheme == "https") {
            runCatching {
                context.startActivity(
                    Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            }
        }
        return true
    }

    override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) = onStarted()

    override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
        onGone()
        return true
    }
}
