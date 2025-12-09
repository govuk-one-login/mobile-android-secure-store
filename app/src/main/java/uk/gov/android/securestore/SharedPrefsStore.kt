package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.authentication.UserAuthenticator
import uk.gov.android.securestore.crypto.HybridCryptoManager
import uk.gov.android.securestore.crypto.HybridCryptoManagerImpl
import uk.gov.android.securestore.error.ErrorTypeHandler
import uk.gov.android.securestore.error.SecureStorageError
import uk.gov.android.securestore.error.SecureStoreErrorType
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@Suppress("TooGenericExceptionCaught", "TooManyFunctions")
class SharedPrefsStore(
    private val authenticator: Authenticator = UserAuthenticator(),
    private val hybridCryptoManager: HybridCryptoManager = HybridCryptoManagerImpl(),
) : SecureStore {
    private val tag = this::class.java.simpleName
    private var configuration: SecureStorageConfiguration? = null
    private var sharedPrefs: SharedPreferences? = null

    override fun init(
        context: Context,
        configuration: SecureStorageConfiguration,
    ) {
        this.configuration = configuration
        hybridCryptoManager.init(
            configuration.id,
            configuration.accessControlLevel,
        )
        sharedPrefs = context.getSharedPreferences(configuration.id, Context.MODE_PRIVATE)
    }

    override suspend fun upsert(key: String, value: String): String {
        return try {
            val result = hybridCryptoManager.encrypt(value)
                .also {
                    writeToPrefs(key, it.data)
                    writeToPrefs(key + KEY_SUFFIX, it.key)
                }
            result.data
        } catch (e: Exception) {
            throw SecureStorageError(e)
        }
    }

    override fun delete(key: String) {
        sharedPrefs?.edit {
            remove(key)
        }
    }

    override fun deleteAll() {
        sharedPrefs?.edit {
            clear()
        }
        try {
            hybridCryptoManager.deleteKey()
        } catch (e: Exception) {
            throw SecureStorageError(e)
        }
    }

    override suspend fun retrieve(
        vararg key: String,
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
                        val results = handleResults(*key)
                        continuation.resume(RetrievalEvent.Success(results))
                    } catch (e: SecureStorageError) {
                        continuation.resume(
                            RetrievalEvent.Failed(
                                e.type,
                                e.message,
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

    @Suppress("LongMethod")
    override suspend fun retrieveWithAuthentication(
        vararg key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity,
    ): RetrievalEvent {
        return configuration?.let { configuration ->
            suspendCoroutine { continuation ->
                if (configuration.accessControlLevel == AccessControlLevel.OPEN) {
                    continuation.resume(
                        RetrievalEvent.Failed(
                            SecureStoreErrorType.GENERAL,
                            "Use retrieve method, access control is set to OPEN, " +
                                "no need for auth",
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
                                val results = try {
                                    RetrievalEvent.Success(handleResults(*key))
                                } catch (e: SecureStorageError) {
                                    RetrievalEvent.Failed(
                                        ErrorTypeHandler.getErrorType(e),
                                        "authenticate call onSuccess callback throws " +
                                            "SecureStorageError ${e.message}",
                                    )
                                }
                                continuation.resume(results)
                            },
                            onError = { errorCode, errorString ->
                                continuation.resume(
                                    RetrievalEvent.Failed(
                                        getErrorType(errorCode),
                                        "$BIOMETRIC_PREFIX$errorCode $errorString",
                                    ),
                                )
                            },
                            onFailure = {
                                Log.e(tag, "Bio Prompt Failed")
                            },
                        ),
                    )
                } catch (e: SecureStorageError) {
                    continuation.resume(
                        RetrievalEvent.Failed(
                            ErrorTypeHandler.getErrorType(e),
                            "authenticate call throws SecureStorageError ${e.message}",
                        ),
                    )
                } catch (e: Exception) {
                    Log.e(tag, e.message, e)
                    continuation.resume(
                        RetrievalEvent.Failed(
                            SecureStoreErrorType.GENERAL,
                            "authenticate call throws Exception ${e.message}",
                        ),
                    )
                } finally {
                    authenticator.close()
                }
            }
        } ?: RetrievalEvent.Failed(
            SecureStoreErrorType.GENERAL,
            "Must call init on SecureStore first!",
        )
    }

    override fun exists(key: String): Boolean {
        return sharedPrefs?.contains(key) == true
    }

    private fun writeToPrefs(key: String, value: String?) {
        sharedPrefs?.let {
            it.edit {
                putString(key, value)
            }
        } ?: throw SecureStorageError(Exception("You must call init first!"))
    }

    private fun cryptoDecryptText(
        alias: String,
        onTextReady: (String?) -> Unit,
    ) {
        sharedPrefs?.let {
            try {
                val encryptedData = it.getString(alias, null)
                val encryptedKey = it.getString(alias + KEY_SUFFIX, null)
                if (encryptedData.isNullOrEmpty() || encryptedKey.isNullOrEmpty()) {
                    onTextReady(null)
                } else {
                    hybridCryptoManager.decrypt(encryptedData, encryptedKey) { result ->
                        onTextReady(result)
                    }
                }
            } catch (e: Exception) {
                throw SecureStorageError(e)
            }
        } ?: throw SecureStorageError(Exception("You must call init first!"))
    }

    private fun getErrorType(errorCode: Int): SecureStoreErrorType {
        return when (errorCode) {
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_TIMEOUT,
            BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
            BiometricPrompt.ERROR_NO_BIOMETRICS,
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_CANCELED,
            BiometricPrompt.ERROR_LOCKOUT,
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
            -> SecureStoreErrorType.USER_CANCELED_BIO_PROMPT

            else -> SecureStoreErrorType.GENERAL
        }
    }

    private fun handleResults(vararg key: String): MutableMap<String, String> {
        val results = mutableMapOf<String, String>()
        key.forEach { alias ->
            cryptoDecryptText(alias) { data ->
                data?.let {
                    results[alias] = data
                } ?: throw sseNotFound(alias)
            }
        }
        return results
    }

    companion object {
        // DO NOT CHANGE THIS
        private const val KEY_SUFFIX = "Key"

        private const val BIOMETRIC_PREFIX = "biometric error code "
        private fun sseNotFound(alias: String) = SecureStorageError(
            Exception("$alias not found"),
            SecureStoreErrorType.NOT_FOUND,
        )
    }
}
