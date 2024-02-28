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
    context: Context,
    configuration: SecureStorageConfiguration,
    private val authenticator: Authenticator = UserAuthenticator(),
    private val cryptoManager: CryptoManager = RsaCryptoManager(
        configuration.id,
        configuration.accessControlLevel,
        authenticator
    )
) : SecureStore {
    private val sharedPrefs = context.getSharedPreferences(configuration.id, Context.MODE_PRIVATE)

    override suspend fun upsert(key: String, value: String, context: FragmentActivity): String {
        authenticator.init(context)
        return suspendCoroutine { continuation ->
            try {
                val result = cryptoManager.encryptText(value)
                    .also { writeToPrefs(key, it) }
                continuation.resumeWith(Result.success(result))
                authenticator.close(context)
            } catch (e: GeneralSecurityException) {
                throw SecureStorageError(e)
            }
        }
    }

    override fun delete(key: String, context: FragmentActivity) {
        writeToPrefs(key, null)
        authenticator.init(context)
        try {
            cryptoManager.deleteKey()
            authenticator.close(context)
        } catch (e: KeyStoreException) {
            throw SecureStorageError(e)
        }
    }

    override suspend fun retrieve(
        key: String,
        authPromptConfig: AuthenticatorPromptConfiguration?,
        context: FragmentActivity
    ): String? {
        authenticator.init(context)
        return suspendCoroutine { continuation ->
            try {
                sharedPrefs.getString(key, null)?.let { encryptedText ->
                    cryptoManager.decryptText(
                        encryptedText,
                        { text -> continuation.resumeWith(Result.success(text)) },
                        authPromptConfig
                    )
                } ?: continuation.resumeWith(Result.success(null))
                authenticator.close(context)
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
