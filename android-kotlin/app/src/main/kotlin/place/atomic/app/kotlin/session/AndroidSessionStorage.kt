package place.atomic.app.kotlin.session

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** SharedPreferences as [KeyValue]. `commit()` so a force-stop right after cannot lose it. */
class PrefsKeyValue(context: Context) : KeyValue {
    private val prefs = context.getSharedPreferences("atomic_session", Context.MODE_PRIVATE)
    override fun getString(key: String): String? = prefs.getString(key, null)
    override fun putString(key: String, value: String?) {
        prefs.edit().apply { if (value == null) remove(key) else putString(key, value) }.commit()
    }
}

/** AES-GCM with a key that never leaves the Android Keystore. */
class KeystoreSecretBox : SecretBox {
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    override fun seal(plain: String): String {
        val cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val sealed = cipher.iv + cipher.doFinal(plain.toByteArray())
        return Base64.encodeToString(sealed, Base64.NO_WRAP)
    }

    override fun open(sealed: String): String? = try {
        val bytes = Base64.decode(sealed, Base64.NO_WRAP)
        val cipher = Cipher.getInstance(TRANSFORM)
            .apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes, 0, IV_BYTES)) }
        String(cipher.doFinal(bytes, IV_BYTES, bytes.size - IV_BYTES))
    } catch (_: Exception) {
        null
    }

    private companion object {
        const val ALIAS = "atomic_session_key"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
    }
}
