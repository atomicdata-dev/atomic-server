package place.atomic.app.kotlin.ui

import android.webkit.WebView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.viewinterop.AndroidView
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.embed.EmbedController

/** What the person opened: a resource, and the drive Recents files it under. */
data class OpenResource(val subject: String, val title: String, val drive: String)

/**
 * A resource in the warm WebView, under a top bar with its title and back.
 * Back (the arrow, the gesture) goes one step back inside the page first (an
 * overlay, a form) and leaves the resource when there is none; leaving first
 * hands pending edits to Rust.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResourceScreen(
    target: OpenResource,
    embed: EmbedController,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val goBack: () -> Unit = {
        scope.launch {
            if (!embed.bridge.back()) {
                embed.bridge.leave()
                onClose()
            }
        }
    }
    BackHandler(onBack = goBack)
    LaunchedEffect(target) { embed.bridge.open(target.subject, target.drive) }
    DisposableEffect(embed) { onDispose { embed.detach() } }

    Scaffold(
        modifier = modifier,
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(target.title.ifEmpty { target.subject }, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = {
                    IconButton(onClick = goBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
            )
        },
    ) { padding ->
        Box(Modifier.padding(padding).imePadding().fillMaxSize()) {
            AndroidView<WebView>(
                modifier = Modifier.fillMaxSize(),
                factory = { context -> embed.attach(context) },
                // The same view stays alive across resources: nothing to update.
                update = {},
            )
        }
    }
}
