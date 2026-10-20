package com.ontola.atomiccanvas_flutter

import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.graphics.Color
import android.net.ConnectivityManager
import android.net.Network
import android.net.wifi.WifiManager
import android.os.Bundle
import androidx.core.view.WindowCompat
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import com.eyedeadevelopment.fluttertts.FlutterTtsPlugin
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    private val CHANNEL = "app.atomicdata.app/deeplink"
    private val NETWORK_CHANNEL = "app.atomicdata.app/network"
    private var initialLink: String? = null
    private var channel: MethodChannel? = null
    private var networkChannel: MethodChannel? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        styleNavigationBar()
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        styleNavigationBar()
    }

    /** Black bar with light buttons in dark mode, white with dark ones in light mode. */
    private fun styleNavigationBar() {
        val dark = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES
        window.navigationBarColor = if (dark) Color.BLACK else Color.WHITE
        if (Build.VERSION.SDK_INT >= 29) window.isNavigationBarContrastEnforced = false
        WindowCompat.getInsetsController(window, window.decorView).isAppearanceLightNavigationBars = !dark
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        holdBackTts(flutterEngine)
        networkChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, NETWORK_CHANNEL)
        channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        channel?.setMethodCallHandler { call, result ->
            when (call.method) {
                "getInitialLink" -> {
                    result.success(initialLink)
                    initialLink = null
                }
                "getDeviceName" -> {
                    result.success(Build.MODEL ?: "Android")
                }
                else -> result.notImplemented()
            }
        }
        // Check if launched from a deep link
        handleIntent(intent)
    }

    /**
     * flutter_tts creates a TextToSpeech when the engine attaches and reads
     * every voice on the main thread (about a second of each start), for a
     * feature only voice mode uses. It is taken out again here and added when
     * Dart asks for it just before the first utterance (PluginSpeechOutput).
     */
    private fun holdBackTts(flutterEngine: FlutterEngine) {
        flutterEngine.plugins.remove(FlutterTtsPlugin::class.java)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "atomic_chat/tts")
            .setMethodCallHandler { call, result ->
                if (call.method != "ensure") return@setMethodCallHandler result.notImplemented()
                if (!flutterEngine.plugins.has(FlutterTtsPlugin::class.java)) {
                    flutterEngine.plugins.add(FlutterTtsPlugin())
                }
                result.success(null)
            }
    }

    /**
     * While the app is in front, Iroh's endpoint runs: hold a MulticastLock so
     * its mDNS (local network discovery) receives the other devices' answers
     * (Android drops multicast to apps without one), and tell Dart when the
     * network changes, so the device search looks again at once.
     */
    override fun onStart() {
        super.onStart()
        try {
            val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            multicastLock = wifi.createMulticastLock("atomic-iroh-mdns").apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (e: Exception) {
            android.util.Log.w("atomic", "MulticastLock not acquired: $e")
        }
        if (Build.VERSION.SDK_INT >= 24) try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val callback = object : ConnectivityManager.NetworkCallback() {
                private var first = true
                override fun onAvailable(network: Network) {
                    // The first call is the network that was already there.
                    if (first) { first = false; return }
                    notifyNetworkChanged()
                }
                override fun onLost(network: Network) = notifyNetworkChanged()
            }
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        } catch (e: Exception) {
            android.util.Log.w("atomic", "Network callback not registered: $e")
        }
    }

    override fun onStop() {
        try { multicastLock?.release() } catch (_: Exception) {}
        multicastLock = null
        networkCallback?.let {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                    .unregisterNetworkCallback(it)
            } catch (_: Exception) {}
        }
        networkCallback = null
        super.onStop()
    }

    private fun notifyNetworkChanged() {
        runOnUiThread { networkChannel?.invokeMethod("changed", null) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        if (intent.action == Intent.ACTION_VIEW) {
            val uri = intent.data?.toString()
            if (uri != null && (uri.startsWith("did:ad:node:") || uri.startsWith("atomic:node:"))) {
                if (channel != null) {
                    channel?.invokeMethod("onNewLink", uri)
                } else {
                    initialLink = uri
                }
            }
        }
    }
}
