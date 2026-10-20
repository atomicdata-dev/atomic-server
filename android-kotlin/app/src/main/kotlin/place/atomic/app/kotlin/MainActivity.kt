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
import androidx.compose.runtime.getValue
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
                    AppState.Ready -> Home()
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

    @Composable
    private fun Home() {
        val vm: HomeViewModel = viewModel(factory = viewModelFactory { initializer { HomeViewModel(CoreHomeRepository()) } })
        val state by vm.state.collectAsStateWithLifecycle()
        HomeScreen(
            state = state,
            onQuery = vm::setQuery,
            onShowAll = vm::showAll,
            // Resources open in the warm WebView in a later stage (planning/android-kotlin.md).
            onOpen = {},
            onSettings = {},
            wide = isWide(LocalConfiguration.current.screenWidthDp),
        )
    }
}
