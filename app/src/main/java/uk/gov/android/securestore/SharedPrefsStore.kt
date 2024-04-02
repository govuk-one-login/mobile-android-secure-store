package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import androidx.fragment.app.FragmentActivity
import java.lang.NullPointerException
import java.security.GeneralSecurityException
import kotlin.coroutines.Continuation
import kotlin.coroutines.suspendCoroutine
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.authentication.UserAuthenticator
import uk.gov.android.securestore.crypto.CryptoManager
import uk.gov.android.securestore.crypto.RsaCryptoManager

@Suppress("TooGenericExceptionCaught")
class SharedPrefsStore(
    private val authenticator: Authenticator = UserAuthenticator(),
    private val cryptoManager: CryptoManager = RsaCryptoManager()
) : SecureStore {

    private var configuration: SecureStorageConfiguration? = null
    private var sharedPrefs: SharedPreferences? = null

    override fun init(
        context: Context,
        configuration: SecureStorageConfiguration
    ) {
        this.configuration = configuration
        cryptoManager.init(
            configuration.id,
            configuration.accessControlLevel
        )
        sharedPrefs = context.getSharedPreferences(configuration.id, Context.MODE_PRIVATE)
    }

    override suspend fun upsert(key: String, value: String, context: FragmentActivity): String {
        return suspendCoroutine { continuation ->
            try {
                authenticator.init(context)
                val result = cryptoManager.encryptText(value)
                    .also { writeToPrefs(key, it) }
                continuation.resumeWith(Result.success(result))
            } catch (e: Exception) {
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
        } catch (e: Exception) {
            throw SecureStorageError(e)
        } finally {
            authenticator.close()
        }
    }

    override suspend fun retrieve(
        key: String
    ): String? {
        configuration?.let { configuration ->
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
        } ?: throw SecureStorageError(Exception("You must call init first!"))
    }

    override suspend fun retrieveWithAuthentication(
        key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity
    ): String? {
        configuration?.let { configuration ->
            if (configuration.accessControlLevel == AccessControlLevel.OPEN) {
                throw SecureStorageError(
                    Exception(
                        "Use retrieve method, access control is set to OPEN, no need for auth"
                    )
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
        } ?: throw SecureStorageError(Exception("You must call init first!"))
    }

    override fun exists(key: String): Boolean {
        sharedPrefs?.let {
            try {
                return it.contains(key)
            } catch (e: NullPointerException) {
                throw SecureStorageError(e)
            }
        } ?: throw SecureStorageError(Exception("You must call init first!"))
    }

    private fun writeToPrefs(key: String, value: String?) {
        sharedPrefs?.let {
            with(it.edit()) {
                putString(key, value)
                apply()
            }
        } ?: throw SecureStorageError(Exception("You must call init first!"))
    }

    private fun cryptoDecryptText(
        key: String,
        continuation: Continuation<String?>
    ) {
        sharedPrefs?.let {
            try {
                it.getString(key, null)?.let { encryptedText ->
                    cryptoManager.decryptText(
                        encryptedText
                    ) { text -> continuation.resumeWith(Result.success(text)) }
                } ?: continuation.resumeWith(Result.success(null))
            } catch (e: NullPointerException) {
                throw SecureStorageError(e)
            }
        } ?: throw SecureStorageError(Exception("You must call init first!"))
    }
}
