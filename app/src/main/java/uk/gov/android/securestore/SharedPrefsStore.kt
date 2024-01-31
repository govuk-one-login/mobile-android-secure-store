package uk.gov.android.securestore

import android.content.Context
import androidx.fragment.app.FragmentActivity
import java.security.GeneralSecurityException
import java.security.KeyStoreException
import kotlin.coroutines.suspendCoroutine
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.authentication.UserAuthenticator
import uk.gov.android.securestore.crypto.CryptoManager
import uk.gov.android.securestore.crypto.RsaCryptoManager

class SharedPrefsStore(
    context: FragmentActivity,
    configuration: SecureStorageConfiguration,
    private val authenticator: Authenticator = UserAuthenticator(context),
    private val cryptoManager: CryptoManager = RsaCryptoManager(
        configuration.id,
        configuration.accessControlLevel,
        authenticator
    )
) : SecureStore {
    private val sharedPrefs = context.getSharedPreferences(configuration.id, Context.MODE_PRIVATE)

    override suspend fun upsert(key: String, value: String): String {
        return suspendCoroutine { continuation ->
            try {
                val result = cryptoManager.encryptText(value)
                    .also { writeToPrefs(key, it) }
                continuation.resumeWith(Result.success(result))
            } catch (e: GeneralSecurityException) {
                throw SecureStorageError(e)
            }
        }
    }

    override fun delete(key: String) {
        writeToPrefs(key, null)
        try {
            cryptoManager.deleteKey()
        } catch (e: KeyStoreException) {
            throw SecureStorageError(e)
        }
    }

    override suspend fun retrieve(
        key: String,
        authPromptConfig: AuthenticatorPromptConfiguration?
    ): String? {
        return suspendCoroutine { continuation ->
            try {
                sharedPrefs.getString(key, null)?.let { encryptedText ->
                    cryptoManager.decryptText(
                        encryptedText,
                        { text -> continuation.resumeWith(Result.success(text)) },
                        authPromptConfig
                    )
                } ?: continuation.resumeWith(Result.success(null))
            } catch (e: GeneralSecurityException) {
                throw SecureStorageError(e)
            }
        }
    }

    override fun exists(key: String): Boolean {
        return sharedPrefs.contains(key)
    }

    private fun writeToPrefs(key: String, value: String?) {
        with(sharedPrefs.edit()) {
            putString(key, value)
            apply()
        }
    }
}
