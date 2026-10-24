package place.atomic.app.kotlin.shell

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import place.atomic.app.kotlin.data.Backend

/**
 * The sync with the other devices that runs after sign-in and on every resume
 * (Flutter's `_startBackgroundSync`). One failure is quiet: a cold radio or a
 * device waking from sleep times out once and works on the retry. It retries on
 * its own with growing waits ([retrySeconds]) and speaks, with one small toast
 * that [ToastController] keeps unique and quiet for a while after a dismissal,
 * from the [TOAST_AFTER]th failure in a row.
 */
class BackgroundSync(
    private val backend: Backend,
    private val toasts: ToastController,
    private val scope: CoroutineScope,
    private val log: (String) -> Unit = {},
) {
    var failures = 0
        private set
    private var running = false
    private var retry: Job? = null
    private var active = true

    /** Syncs once, unless a sync is running already. */
    fun start() {
        if (running) return
        running = true
        active = true
        retry?.cancel()
        scope.launch {
            try {
                val report = backend.syncNow()
                // Only a failure is worth a notice; being connected is the normal case.
                if (report.livePeers == 0u && report.imported == 0 && !report.message.startsWith("No other device found yet")) {
                    failed(report.message)
                } else {
                    succeeded()
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                failed("Sync: ${e.message ?: e}")
            } finally {
                running = false
            }
        }
    }

    /** Signed out: no more retries. */
    fun stop() {
        active = false
        retry?.cancel()
        failures = 0
        toasts.resolve(TOAST_KEY)
    }

    private fun failed(message: String) {
        failures++
        log("Background sync failed ($failures in a row): $message")
        if (failures >= TOAST_AFTER) {
            toasts.show(TOAST_KEY, message, actionLabel = "Retry", onAction = {
                failures = 0
                start()
            })
        }
        retry?.cancel()
        if (!active) return
        retry = scope.launch {
            delay(retrySeconds(failures) * 1_000)
            start()
        }
    }

    private fun succeeded() {
        failures = 0
        retry?.cancel()
        toasts.resolve(TOAST_KEY)
    }

    companion object {
        const val TOAST_AFTER = 2
        const val TOAST_KEY = "sync:error"

        /** 20 s, 40 s, 80 s ... at most 5 min. */
        fun retrySeconds(failures: Int): Long = (20L shl (failures - 1).coerceIn(0, 4)).coerceIn(20, 300)
    }
}
