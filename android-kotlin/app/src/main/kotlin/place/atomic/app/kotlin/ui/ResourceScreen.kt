package place.atomic.app.kotlin.ui

import android.view.View
import android.webkit.WebView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.embed.EmbedController

/** What the person opened: a resource, and the drive Recents files it under. */
data class OpenResource(val subject: String, val title: String, val drive: String)

/** The height of the bar above a resource's page (Material's top app bar, below the status bar). */
private val CHROME_HEIGHT = 64.dp

/**
 * The warm WebView, kept in the layout for as long as the shell is up (Flutter's
 * warm view under the pages). Opening a resource is then only a route change
 * inside the page ([OpenResource] and `atomicEmbed.open`): the view is neither
 * attached nor laid out again, which is what a warm open costs. It is invisible
 * and takes no touches while no resource is on top ([visible]); a resource's
 * page starts under [ResourceChrome]'s bar.
 */
@Composable
fun EmbedSlot(embed: EmbedController, visible: Boolean, modifier: Modifier = Modifier) {
    AndroidView<WebView>(
        modifier = modifier.fillMaxSize().windowInsetsPadding(WindowInsets.statusBars).padding(top = CHROME_HEIGHT),
        factory = { context -> embed.attach(context) },
        update = { it.visibility = if (visible) View.VISIBLE else View.INVISIBLE },
        onRelease = { embed.detach() },
    )
}

/**
 * The bar above a resource's page, with its title and back, and the opening of
 * the resource in the page. Back (the arrow, the gesture) goes one step back
 * inside the page first (an overlay, a form) and leaves the resource when
 * there is none; leaving first hands pending edits to Rust.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResourceChrome(
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
    LaunchedEffect(target) { embed.bridge.open(target.subject, target.drive, target.title) }
    TopAppBar(
        modifier = modifier,
        title = { Text(target.title.ifEmpty { target.subject }, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        navigationIcon = {
            IconButton(onClick = goBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
        },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
    )
}

/**
 * One of the web app's own pages (the template picker of a new drive, a new chat
 * room's form) in a page of its own: a second, cold WebView, because the warm
 * one only opens resources. It is released when the page is left.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActionPage(title: String, embed: EmbedController, onClose: () -> Unit, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    val goBack: () -> Unit = { scope.launch { if (!embed.bridge.back()) onClose() } }
    BackHandler(onBack = goBack)
    androidx.compose.material3.Scaffold(
        modifier = modifier,
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = { IconButton(onClick = goBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        },
    ) { padding ->
        AndroidView<WebView>(
            modifier = Modifier.padding(padding).fillMaxSize(),
            factory = { context -> embed.attach(context) },
            update = {},
        )
    }
}
