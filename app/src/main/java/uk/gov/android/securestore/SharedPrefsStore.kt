package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.GeneralSecurityException
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.suspendCancellableCoroutine
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.authentication.UserAuthenticator
import uk.gov.android.securestore.crypto.CryptoManager
import uk.gov.android.securestore.crypto.RsaCryptoManager
import uk.gov.android.securestore.error.SecureStorageError
import uk.gov.android.securestore.error.SecureStoreErrorType
import javax.crypto.Cipher

@Suppress("TooGenericExceptionCaught")
class SharedPrefsStore(
    private val authenticator: Authenticator = UserAuthenticator(),
    private val cryptoManager: CryptoManager = RsaCryptoManager()
) : SecureStore {
    private val tag = this::class.java.simpleName
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

    override suspend fun upsert(key: String, value: String): String {
        println("encrypting: $key")
        return suspendCoroutine { continuation ->
            try {
                val result = cryptoManager.encryptText(value)
                    .also {
                        writeToPrefs(key, it.first)
                        writeToPrefs(key+"key", it.second)
                    }
                continuation.resumeWith(Result.success(result.first))
            } catch (e: Exception) {
                throw SecureStorageError(e)
            }
        }
    }

    override fun delete(key: String) {
        writeToPrefs(key, null)
        try {
            cryptoManager.deleteKey()
        } catch (e: Exception) {
            throw SecureStorageError(e)
        }
    }

    override suspend fun retrieve(
        vararg key: String
    ): RetrievalEvent {
        return configuration?.let { configuration ->
            if (configuration.accessControlLevel != AccessControlLevel.OPEN) {
                RetrievalEvent.Failed(
                    SecureStoreErrorType.GENERAL,
                    "Access control level must be OPEN to use this retrieve method"
                )
            } else {
                suspendCancellableCoroutine<RetrievalEvent> { continuation ->
                    try {
                        val results = mutableMapOf<String, String?>()
                        key.forEach { key ->
                            cryptoDecryptText(key, null) {
                                results[key] = it
                            }
                        }
                        continuation.resume(RetrievalEvent.Success(results))
                    } catch (e: SecureStorageError) {
                        Log.e(tag, e.message, e)
                        continuation.resume(
                            RetrievalEvent.Failed(
                                SecureStoreErrorType.GENERAL
                            )
                        )
                    }
                }
            }
        } ?: RetrievalEvent.Failed(
            SecureStoreErrorType.GENERAL,
            "Must call init on SecureStore first!"
        )
    }

    override suspend fun retrieveWithAuthentication(
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity,
        vararg key: String
    ): RetrievalEvent {
        configuration?.let { configuration ->
            if (configuration.accessControlLevel == AccessControlLevel.OPEN) {
                return RetrievalEvent.Failed(
                    SecureStoreErrorType.GENERAL,
                    "Use retrieve method, access control is set to OPEN, no need for auth"
                )
            }

            return suspendCancellableCoroutine { continuation ->
                try {
                    authenticator.init(context)
                    authenticator.authenticate(
                        configuration.accessControlLevel,
                        authPromptConfig,
                        AuthenticatorCallbackHandler(
                            onSuccess = { result ->
                                val results = mutableMapOf<String, String?>()
                                key.forEach { key ->
                                    cryptoDecryptText(key, null) {
                                        println("putting decrypted value: $it")
                                        results[key] = it
                                    }
                                }

                                continuation.resume(RetrievalEvent.Success(results))
//                                result.cryptoObject?.cipher?.let { cipher ->
//                                } ?: continuation.resume(RetrievalEvent.Failed(SecureStoreErrorType.GENERAL))
                            },
                            onError = { errorCode, errorString ->
                                continuation.resume(
                                    RetrievalEvent.Failed(
                                        getErrorType(errorCode),
                                        errorString.toString()
                                    )
                                )
                            },
                            onFailure = {
                                continuation.resume(
                                    RetrievalEvent.Failed(
                                        SecureStoreErrorType.FAILED_BIO_PROMPT,
                                        "Bio Prompt failed"
                                    )
                                )
                            }
                        ),
                        //cryptoManager.getCipher()
                    )
                } catch (e: GeneralSecurityException) {
                    Log.e(tag, e.message, e)
                    continuation.resume(RetrievalEvent.Failed(SecureStoreErrorType.GENERAL))
                } finally {
                    authenticator.close()
                }
            }
        } ?: return RetrievalEvent.Failed(
            SecureStoreErrorType.GENERAL,
            "Must call init on SecureStore first!"
        )
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
        println("Saving: $key - $value")
        sharedPrefs?.let {
            with(it.edit()) {
                putString(key, value)
                apply()
            }
        } ?: throw SecureStorageError(Exception("You must call init first!"))
    }

    private fun cryptoDecryptText(
        key: String,
        cipher: Cipher?,
        onTextReady: (String?) -> Unit
    ) {
        sharedPrefs?.let { sharedPref ->
            try {
                sharedPref.getString(key, null)?.let { encryptedText ->
                    cipher?.let { cipher ->
                        cryptoManager.decryptText(
                            sharedPref.getString(key+"key", null)!!,
                            encryptedText,
                            cipher
                        ) { text -> onTextReady(text) }
                    } ?: {
                        cryptoManager.decryptText(
                            sharedPref.getString(key+"key", null)!!,
                            encryptedText
                        ) { text -> onTextReady(text) }
                    }
                } ?: onTextReady(null)
            } catch (e: Exception) {
                throw SecureStorageError(e)
            }
        } ?: throw SecureStorageError(Exception("You must call init first!"))
    }

    private fun getErrorType(errorCode: Int): SecureStoreErrorType {
        return if (
            errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
            errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
        ) {
            SecureStoreErrorType.USER_CANCELED_BIO_PROMPT
        } else {
            SecureStoreErrorType.GENERAL
        }
    }
}
