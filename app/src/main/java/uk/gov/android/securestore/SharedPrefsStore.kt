package uk.gov.android.securestore

import android.content.Context
import androidx.fragment.app.FragmentActivity
import java.security.GeneralSecurityException
import java.security.KeyStoreException
import kotlin.coroutines.Continuation
import kotlin.coroutines.suspendCoroutine
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.authentication.UserAuthenticator
import uk.gov.android.securestore.crypto.CryptoManager
import uk.gov.android.securestore.crypto.RsaCryptoManager

class SharedPrefsStore(
    context: Context,
    private val configuration: SecureStorageConfiguration,
    private val authenticator: Authenticator = UserAuthenticator(),
    private val cryptoManager: CryptoManager = RsaCryptoManager(
        configuration.id,
        configuration.accessControlLevel
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
        key: String
    ): String? {
        if (configuration.accessControlLevel != AccessControlLevel.OPEN) {
            throw SecureStorageError(
                Exception("Access control level must be OPEN to use this retrieve method")
            )
        }
        return suspendCoroutine { continuation ->
            try {
                cryptoDecryptText(key, continuation)
            } catch (e: GeneralSecurityException) {
                throw SecureStorageError(e)
            }
        }
    }

    override suspend fun retrieveWithAuthentication(
        key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity
    ): String? {
        if (configuration.accessControlLevel == AccessControlLevel.OPEN) {
            throw SecureStorageError(
                Exception("Use retrieve method, access control is set to OPEN, no need for auth")
            )
        }
        return suspendCoroutine { continuation ->
            try {
                authenticator.init(context)
                authenticator.authenticate(
                    configuration.accessControlLevel,
                    authPromptConfig,
                    AuthenticatorCallbackHandler(
                        onSuccess = {
                            cryptoDecryptText(key, continuation)
                        }
                    )
                )
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

    private fun cryptoDecryptText(
        key: String,
        continuation: Continuation<String?>
    ) {
        sharedPrefs.getString(key, null)?.let { encryptedText ->
            cryptoManager.decryptText(
                encryptedText
            ) { text -> continuation.resumeWith(Result.success(text)) }
        } ?: continuation.resumeWith(Result.success(null))
    }
}
