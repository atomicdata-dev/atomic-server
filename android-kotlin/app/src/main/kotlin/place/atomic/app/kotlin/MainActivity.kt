package place.atomic.app.kotlin

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import place.atomic.app.kotlin.core.noteResourceOpened
import place.atomic.app.kotlin.data.RowItem
import place.atomic.app.kotlin.ui.OpenResource
import place.atomic.app.kotlin.ui.ResourceScreen
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import place.atomic.app.kotlin.data.CoreHomeRepository
import place.atomic.app.kotlin.data.HomeViewModel
import place.atomic.app.kotlin.ui.AtomicTheme
import place.atomic.app.kotlin.ui.HomeScreen
import place.atomic.app.kotlin.ui.WelcomeScreen
import place.atomic.app.kotlin.ui.isWide

class MainActivity : ComponentActivity() {
    private val app: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AtomicTheme {
                val state by app.state.collectAsStateWithLifecycle()
                when (val s = state) {
                    AppState.Opening -> Box(Modifier.fillMaxSize(), Alignment.Center) { CircularProgressIndicator() }
                    AppState.Welcome -> WelcomeScreen(onStart = app::createAccount)
                    AppState.Ready -> Ready()
                    is AppState.Failed -> Box(Modifier.fillMaxSize().padding(24.dp), Alignment.Center) {
                        Text("The store could not be opened: ${s.message}", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        // Android may kill a backgrounded app without warning.
        app.flush()
    }

    /** Home, or the resource that was opened from it (back returns to Home). */
    @Composable
    private fun Ready() {
        val atomic = application as AtomicApp
        var open by rememberSaveable(stateSaver = OpenResourceSaver) { mutableStateOf<OpenResource?>(null) }
        val dark = isSystemInDarkTheme()
        LaunchedEffect(Unit) { atomic.startEmbed() }
        LaunchedEffect(dark) { atomic.embed.bridge.setColorScheme(dark) }
        val target = open
        if (target == null) {
            Home(onOpen = { row ->
                // Drives are their own drive; rows from search or lists name theirs.
                val drive = row.drive.ifEmpty { row.subject }
                runCatching { noteResourceOpened(drive, row.subject) }
                open = OpenResource(row.subject, row.title, drive)
            })
        } else {
            ResourceScreen(target, atomic.embed, onClose = { open = null })
        }
    }

    @Composable
    private fun Home(onOpen: (RowItem) -> Unit) {
        val vm: HomeViewModel = viewModel(factory = viewModelFactory { initializer { HomeViewModel(CoreHomeRepository()) } })
        val state by vm.state.collectAsStateWithLifecycle()
        HomeScreen(
            state = state,
            onQuery = vm::setQuery,
            onShowAll = vm::showAll,
            onOpen = onOpen,
            onSettings = {},
            wide = isWide(LocalConfiguration.current.screenWidthDp),
        )
    }
}

/** Survives the activity being recreated: the opened resource as three strings. */
private val OpenResourceSaver = listSaver<OpenResource?, String>(
    save = { it?.let { r -> listOf(r.subject, r.title, r.drive) } ?: emptyList() },
    restore = { if (it.size == 3) OpenResource(it[0], it[1], it[2]) else null },
)
