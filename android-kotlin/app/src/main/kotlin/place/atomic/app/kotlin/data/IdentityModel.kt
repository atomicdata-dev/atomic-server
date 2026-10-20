package place.atomic.app.kotlin.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Who the person is as the avatar shows them: name, emoji and the picture's
 * bytes (the web app's pictures are File resources without a download URL, so
 * the bytes are read from the store). [pending]: the profile has a picture that
 * is not on this device yet.
 */
class Identity(
    val name: String,
    val emoji: String?,
    val image: ByteArray?,
    val pending: Boolean = false,
) {
    override fun equals(other: Any?) = other is Identity && name == other.name && emoji == other.emoji &&
        pending == other.pending && (image?.contentEquals(other.image) ?: (other.image == null))

    override fun hashCode() = name.hashCode() * 31 + (image?.size ?: 0)
}

/** The own profile with the picture's bytes; throws when the profile cannot be read. */
suspend fun Backend.loadIdentity(): Identity {
    val profile = ownProfile()
    val file = profile.iconFile
    val bytes = if (file != null) runCatching { readFileBytes(file) }.getOrNull()?.takeIf { it.isNotEmpty() } else null
    return Identity(
        name = profile.name,
        emoji = profile.emoji,
        image = bytes,
        pending = file != null && bytes == null && profile.imageUrl == null,
    )
}

/**
 * The identity the bottom bar's profile button shows, refreshed when the
 * profile page is left and on resume. A picture that has not arrived yet (a
 * synced File without its bytes) is tried again a few times.
 */
class IdentityModel(
    private val backend: Backend,
    private val scope: CoroutineScope,
    private val retryAfterMs: Long = 5_000,
    private val maxRetries: Int = 6,
) {
    private val _state = MutableStateFlow<Identity?>(null)
    val state: StateFlow<Identity?> = _state.asStateFlow()
    private var generation = 0

    fun refresh() {
        val mine = ++generation
        scope.launch {
            var tries = 0
            while (mine == generation) {
                val identity = runCatching { backend.loadIdentity() }.getOrNull() ?: return@launch
                if (mine == generation && identity != _state.value) _state.value = identity
                if (!identity.pending || ++tries > maxRetries) return@launch
                delay(retryAfterMs)
            }
        }
    }
}
