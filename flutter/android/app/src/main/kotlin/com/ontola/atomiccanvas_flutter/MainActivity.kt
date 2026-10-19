package com.ontola.atomiccanvas_flutter

import android.content.Intent
import android.content.res.Configuration
import android.graphics.Color
import android.os.Bundle
import androidx.core.view.WindowCompat
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    private val CHANNEL = "app.atomicdata.app/deeplink"
    private var initialLink: String? = null
    private var channel: MethodChannel? = null

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
