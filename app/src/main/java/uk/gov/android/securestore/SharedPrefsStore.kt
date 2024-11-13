package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.authentication.UserAuthenticator
import uk.gov.android.securestore.crypto.CryptoManager
import uk.gov.android.securestore.crypto.RsaCryptoManager
import uk.gov.android.securestore.error.SecureStorageError
import uk.gov.android.securestore.error.SecureStoreErrorType
import java.security.GeneralSecurityException
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@Suppress("TooGenericExceptionCaught")
class SharedPrefsStore(
    private val authenticator: Authenticator = UserAuthenticator(),
    private val cryptoManager: CryptoManager = RsaCryptoManager(),
) : SecureStore {
    private val tag = this::class.java.simpleName
    private var configuration: SecureStorageConfiguration? = null
    private var sharedPrefs: SharedPreferences? = null

    override fun init(
        context: Context,
        configuration: SecureStorageConfiguration,
    ) {
        this.configuration = configuration
        cryptoManager.init(
            configuration.id,
            configuration.accessControlLevel,
        )
        sharedPrefs = context.getSharedPreferences(configuration.id, Context.MODE_PRIVATE)
    }

    override suspend fun upsert(key: String, value: String): String {
        return suspendCoroutine { continuation ->
            try {
                val result = cryptoManager.encryptText(value)
                    .also { writeToPrefs(key, it) }
                continuation.resumeWith(Result.success(result))
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
        key: String,
    ): RetrievalEvent {
        return configuration?.let { configuration ->
            if (configuration.accessControlLevel != AccessControlLevel.OPEN) {
                RetrievalEvent.Failed(
                    SecureStoreErrorType.GENERAL,
                    "Access control level must be OPEN to use this retrieve method",
                )
            } else {
                suspendCoroutine<RetrievalEvent> { continuation ->
                    try {
                        cryptoDecryptText(key) {
                            val event = it?.let {
                                RetrievalEvent.Success(it)
                            } ?: RetrievalEvent.Failed(SecureStoreErrorType.NOT_FOUND)

                            continuation.resume(event)
                        }
                    } catch (e: SecureStorageError) {
                        Log.e(tag, e.message, e)
                        continuation.resume(
                            RetrievalEvent.Failed(
                                SecureStoreErrorType.GENERAL,
                            ),
                        )
                    }
                }
            }
        } ?: RetrievalEvent.Failed(
            SecureStoreErrorType.GENERAL,
            "Must call init on SecureStore first!",
        )
    }

    override suspend fun retrieveWithAuthentication(
        key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity,
    ): Flow<RetrievalEvent> = callbackFlow {
        configuration?.let { configuration ->
            if (configuration.accessControlLevel == AccessControlLevel.OPEN) {
                trySend(
                    RetrievalEvent.Failed(
                        SecureStoreErrorType.GENERAL,
                        "Use retrieve method, access control is set to OPEN, no need for auth",
                    ),
                )
            }
            try {
                authenticator.init(context)
                authenticator.authenticate(
                    configuration.accessControlLevel,
                    authPromptConfig,
                    AuthenticatorCallbackHandler(
                        onSuccess = {
                            cryptoDecryptText(key) {
                                val event = it?.let {
                                    RetrievalEvent.Success(it)
                                } ?: RetrievalEvent.Failed(SecureStoreErrorType.NOT_FOUND)
                                trySend(event)
                            }
                        },
                        onError = { errorCode, errorString ->
                            trySend(
                                RetrievalEvent.Failed(
                                    getErrorType(errorCode),
                                    errorString.toString(),
                                ),
                            )
                        },
                        onFailure = {
                            trySend(
                                RetrievalEvent.Failed(
                                    SecureStoreErrorType.FAILED_BIO_PROMPT,
                                    "Bio Prompt failed",
                                ),
                            )
                        },
                    ),
                )
            } catch (e: GeneralSecurityException) {
                Log.e(tag, e.message, e)
                trySend(RetrievalEvent.Failed(SecureStoreErrorType.GENERAL))
            } finally {
                authenticator.close()
            }
        } ?: trySend(
            RetrievalEvent.Failed(
                SecureStoreErrorType.GENERAL,
                "Must call init on SecureStore first!",
            ),
        )

        awaitClose {
            channel.close()
        }
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
        onTextReady: (String?) -> Unit,
    ) {
        sharedPrefs?.let {
            try {
                it.getString(key, null)?.let { encryptedText ->
                    cryptoManager.decryptText(
                        encryptedText,
                    ) { text -> onTextReady(text) }
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
