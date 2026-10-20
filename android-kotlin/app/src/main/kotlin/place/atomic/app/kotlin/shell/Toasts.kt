package place.atomic.app.kotlin.shell

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/** One notice on screen, identified by [key]: raised again, it is the same notice. */
data class ToastEntry(
    val key: String,
    val message: String,
    val actionLabel: String? = null,
    val onAction: (() -> Unit)? = null,
    val durationMs: Long = 6_000,
    /** Bumped when the same notice is raised again; restarts the dismiss timer. */
    val revision: Int = 0,
)

/**
 * What is on screen and what may be raised (Flutter's `ToastController`): at
 * most [maxVisible] toasts, de-duplicated by key, and a key that was just
 * dismissed stays quiet for [cooldownMs] (until [clearCooldown], which a success
 * calls through [resolve]).
 */
class ToastController(
    private val maxVisible: Int = 3,
    private val cooldownMs: Long = 30_000,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val _toasts = MutableStateFlow<List<ToastEntry>>(emptyList())
    val toasts: StateFlow<List<ToastEntry>> = _toasts.asStateFlow()
    private val dismissedAt = mutableMapOf<String, Long>()

    /** Raises a toast; false when the cool-down swallowed it. */
    @Synchronized
    fun show(
        key: String,
        message: String,
        actionLabel: String? = null,
        onAction: (() -> Unit)? = null,
        durationMs: Long = 6_000,
    ): Boolean {
        val existing = _toasts.value.firstOrNull { it.key == key }
        if (existing != null) {
            _toasts.update { list -> list.map { if (it.key == key) it.copy(message = message, revision = it.revision + 1) else it } }
            return true
        }
        val at = dismissedAt[key]
        if (at != null && now() - at < cooldownMs) return false
        _toasts.update { list ->
            val all = list + ToastEntry(key, message, actionLabel, onAction, durationMs)
            all.dropLast(maxVisible.coerceAtLeast(0).coerceAtMost(all.size)).forEach { dismissedAt[it.key] = now() }
            all.takeLast(maxVisible)
        }
        return true
    }

    @Synchronized
    fun dismiss(key: String) {
        if (_toasts.value.any { it.key == key }) {
            _toasts.update { list -> list.filter { it.key != key } }
            dismissedAt[key] = now()
        }
    }

    /** The cause went away (a sync worked): drop the toast and let the next failure speak at once. */
    @Synchronized
    fun resolve(key: String) {
        dismissedAt.remove(key)
        _toasts.update { list -> list.filter { it.key != key } }
    }

    @Synchronized
    fun clearCooldown(key: String) {
        dismissedAt.remove(key)
    }
}
