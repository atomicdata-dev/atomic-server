package place.atomic.app.kotlin

import android.os.Bundle
import android.view.MotionEvent
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import place.atomic.app.kotlin.data.CoreBackend
import place.atomic.app.kotlin.data.PairModel
import place.atomic.app.kotlin.shell.Shell
import place.atomic.app.kotlin.ui.AtomicTheme
import place.atomic.app.kotlin.ui.LoginActions
import place.atomic.app.kotlin.ui.LoginScreen
import place.atomic.app.kotlin.ui.PairScreen
import place.atomic.app.kotlin.ui.StartupFailedScreen
import place.atomic.app.kotlin.ui.StoreOpenFailedScreen
import place.atomic.app.kotlin.ui.StoreRecoveryScreen
import place.atomic.app.kotlin.ui.ToastHost

class MainActivity : ComponentActivity() {
    private val app: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // The first frame the window draws (Flutter's `first frame`).
        window.decorView.viewTreeObserver.addOnDrawListener(object : android.view.ViewTreeObserver.OnDrawListener {
            override fun onDraw() {
                Perf.once("first frame")
                window.decorView.post { window.decorView.viewTreeObserver.removeOnDrawListener(this) }
            }
        })
        setContent {
            AtomicTheme {
                val state by app.state.collectAsStateWithLifecycle()
                val ui by app.ui.collectAsStateWithLifecycle()
                // Pairing can start from the sign-in screens and from settings.
                var pairing by rememberSaveable { mutableStateOf<String?>(null) }
                var pairRequested by rememberSaveable { mutableStateOf(false) }
                if (pairRequested) {
                    Pairing(initialNodeId = pairing, onClose = {
                        pairRequested = false
                        pairing = null
                        if (state == AppState.NeedsSync) app.pairedCheck()
                    })
                    return@AtomicTheme
                }
                Box(Modifier.fillMaxSize()) {
                when (val s = state) {
                    AppState.Opening -> Box(Modifier.fillMaxSize(), Alignment.Center) { CircularProgressIndicator() }
                    is AppState.StoreFailed -> StoreOpenFailedScreen(s.message, app::retryStart)
                    is AppState.StartupFailed -> StartupFailedScreen(s.message, app::retryStart)
                    is AppState.Recovery -> StoreRecoveryScreen(s.notice, app::continueAfterRecovery)
                    AppState.Login, is AppState.ShowSecret, AppState.NeedsSync -> LoginScreen(
                        state = s,
                        ui = ui,
                        actions = LoginActions(
                            onCreate = app::createAccount,
                            onSignIn = app::signIn,
                            onSecretSaved = app::secretSaved,
                            onFindDrive = app::findDrive,
                            onPair = { nodeId -> pairing = nodeId; pairRequested = true },
                            nodeIdOf = { CoreBackend.parseCode(it)?.nodeId },
                            onBack = app::backToLogin,
                        ),
                    )
                    AppState.Ready -> Shell(app, application as AtomicApp, onPair = { pairing = null; pairRequested = true })
                }
                ToastHost(app.toasts)
                }
            }
        }
    }

    /** Every finger lifted starts the "since tap" marks, as Flutter's `watchTaps` does. */
    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (ev.actionMasked == MotionEvent.ACTION_UP) Perf.tapped()
        return super.dispatchTouchEvent(ev)
    }

    override fun onResume() {
        super.onResume()
        app.resumed()
    }

    override fun onStop() {
        super.onStop()
        // Android may kill a backgrounded app without warning.
        app.flush()
    }

    @Composable
    private fun Pairing(initialNodeId: String?, onClose: () -> Unit) {
        val atomic = application as AtomicApp
        val scope = rememberCoroutineScope()
        val model = remember { PairModel(CoreBackend, atomic.session, scope) }
        val state by model.state.collectAsStateWithLifecycle()
        LaunchedEffect(Unit) { model.start(initialNodeId) }
        BackHandler(onBack = onClose)
        PairScreen(state, onCode = model::onCode, onRetry = model::retry, onClose = onClose)
    }
}
