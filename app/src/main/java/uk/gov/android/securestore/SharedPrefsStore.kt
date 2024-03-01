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
        return suspendCoroutine { continuation ->
            try {
                authenticator.init(context)
                val result = cryptoManager.encryptText(value)
                    .also { writeToPrefs(key, it) }
                continuation.resumeWith(Result.success(result))
            } catch (e: GeneralSecurityException) {
                throw SecureStorageError(e)
            } finally {
                authenticator.close()
            }
        }
    }

    override fun delete(key: String, context: FragmentActivity) {
        writeToPrefs(key, null)
        try {
            authenticator.init(context)
            cryptoManager.deleteKey()
        } catch (e: KeyStoreException) {
            throw SecureStorageError(e)
        } finally {
            authenticator.close()
        }
    }

    override suspend fun retrieve(
        key: String,
        authPromptConfig: AuthenticatorPromptConfiguration?,
        context: FragmentActivity
    ): String? {
        return suspendCoroutine { continuation ->
            try {
                authenticator.init(context)
                sharedPrefs.getString(key, null)?.let { encryptedText ->
                    cryptoManager.decryptText(
                        encryptedText,
                        { text -> continuation.resumeWith(Result.success(text)) },
                        authPromptConfig
                    )
                } ?: continuation.resumeWith(Result.success(null))
            } catch (e: GeneralSecurityException) {
                throw SecureStorageError(e)
            } finally {
                authenticator.close()
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
