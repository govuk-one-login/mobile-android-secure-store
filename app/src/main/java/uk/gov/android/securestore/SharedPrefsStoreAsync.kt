package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import androidx.biometric.BiometricPrompt
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.authentication.UserAuthenticator
import uk.gov.android.securestore.crypto.HybridCryptoManagerAsync
import uk.gov.android.securestore.crypto.HybridCryptoManagerAsyncImpl
import uk.gov.android.securestore.error.ErrorTypeHandler
import uk.gov.android.securestore.error.SecureStorageError
import uk.gov.android.securestore.error.SecureStoreErrorType
import kotlin.coroutines.suspendCoroutine

@Suppress("TooGenericExceptionCaught", "TooManyFunctions")
@Deprecated(
    "Replace with SecureStoreAsyncV2 to allow handling errors correctly - aim to be removed by 20th of April 2026",
    replaceWith = ReplaceWith("java/uk/gov/android/securestore/SharedPrefsStoreAsyncV2.kt"),
    level = DeprecationLevel.WARNING,
)
class SharedPrefsStoreAsync(
    private val authenticator: Authenticator = UserAuthenticator(),
    private val hybridCryptoManagerAsync: HybridCryptoManagerAsync = HybridCryptoManagerAsyncImpl(),
) : SecureStoreAsync {
    private var configurationAsync: SecureStorageConfigurationAsync? = null
    private var sharedPrefs: SharedPreferences? = null

    @Deprecated(
        "Replace with SecureStoreAsyncV2.init() to allow handling errors correctly " +
            "- aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("java/uk/gov/android/securestore/SecureStoreAsyncV2.kt"),
        level = DeprecationLevel.WARNING,
    )
    override fun init(
        context: Context,
        configurationAsync: SecureStorageConfigurationAsync,
    ) {
        this.configurationAsync = configurationAsync
        hybridCryptoManagerAsync.init(
            configurationAsync.id,
            configurationAsync.accessControlLevel,
            configurationAsync.dispatcher,
        )
        sharedPrefs = context.getSharedPreferences(configurationAsync.id, Context.MODE_PRIVATE)
    }

    @Deprecated(
        "Replace with SecureStoreAsyncV2.upsert() to allow handling errors correctly " +
            "- aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("java/uk/gov/android/securestore/SecureStoreAsyncV2.kt"),
        level = DeprecationLevel.WARNING,
    )
    override suspend fun upsert(key: String, value: String): String {
        return try {
            val result = hybridCryptoManagerAsync.encrypt(value)
                .also {
                    writeToPrefs(key, it.data)
                    writeToPrefs(key + KEY_SUFFIX, it.key)
                }
            result.data
        } catch (e: Exception) {
            throw SecureStorageError(e)
        }
    }

    @Deprecated(
        "Replace with SecureStoreAsyncV2.delete(...) to allow handling errors correctly " +
            "- aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("java/uk/gov/android/securestore/SecureStoreAsyncV2.kt"),
        level = DeprecationLevel.WARNING,
    )
    override fun delete(key: String) {
        sharedPrefs?.edit {
            remove(key)
        }
    }

    @Deprecated(
        "Replace with SecureStoreAsyncV2.deleteAll(...) to allow handling errors correctly" +
            " - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("java/uk/gov/android/securestore/SecureStoreAsyncV2.kt"),
        level = DeprecationLevel.WARNING,
    )
    override suspend fun deleteAll() {
        sharedPrefs?.edit {
            clear()
        }
        try {
            hybridCryptoManagerAsync.deleteKey()
        } catch (e: Exception) {
            throw SecureStorageError(e)
        }
    }

    @Deprecated(
        "Replace with SecureStoreAsyncV2.retrieve() to allow handling errors correctly" +
            " - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("java/uk/gov/android/securestore/SecureStoreAsyncV2.kt"),
        level = DeprecationLevel.WARNING,
    )
    override suspend fun retrieve(
        vararg key: String,
    ): RetrievalEvent {
        return configurationAsync?.let { configuration ->
            if (configuration.accessControlLevel != AccessControlLevel.OPEN) {
                RetrievalEvent.Failed(
                    SecureStoreErrorType.GENERAL,
                    "Access control level must be OPEN to use this retrieve method",
                )
            } else {
                try {
                    val results = handleResults(*key)
                    RetrievalEvent.Success(results)
                } catch (e: SecureStorageError) {
                    RetrievalEvent.Failed(
                        e.type,
                        e.message,
                    )
                }
            }
        } ?: RetrievalEvent.Failed(
            SecureStoreErrorType.GENERAL,
            "Must call init on SecureStore first!",
        )
    }

    @Deprecated(
        "Replace with SecureStoreAsyncV2.retrieveWithAuthentication(...) to allow" +
            " handling errors correctly - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("java/uk/gov/android/securestore/SecureStoreAsyncV2.kt"),
        level = DeprecationLevel.WARNING,
    )
    @Suppress("NestedBlockDepth", "LongMethod")
    override suspend fun retrieveWithAuthentication(
        vararg key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity,
    ): RetrievalEvent {
        var result: RetrievalEvent = RetrievalEvent.Failed(
            SecureStoreErrorType.GENERAL,
            "Must call init on SecureStore first!",
        )
        configurationAsync?.let { configuration ->
            if (configuration.accessControlLevel == AccessControlLevel.OPEN) {
                result = RetrievalEvent.Failed(
                    SecureStoreErrorType.GENERAL,
                    "Use retrieve method, access control is set to OPEN, " +
                        "no need for auth",
                )
            } else {
                try {
                    authenticator.init(context)
                    val authenticateResultSuccess: Boolean = suspendCoroutine { continuation ->
                        authenticator.authenticate(
                            configuration.accessControlLevel,
                            authPromptConfig,
                            AuthenticatorCallbackHandler(
                                onSuccess = {
                                    continuation.resumeWith(Result.success(true))
                                },
                                onError = { errorCode, errorString ->
                                    result = RetrievalEvent.Failed(
                                        getErrorType(errorCode),
                                        "$BIOMETRIC_PREFIX$errorCode $errorString",
                                    )
                                    continuation.resumeWith(Result.success(false))
                                },
                                onFailure = {
                                    // Do nothing to allow user to try again
                                },
                            ),
                        )
                    }
                    if (authenticateResultSuccess) {
                        result = processSafeHandleResultsOnAuthenticateSuccess(*key)
                    }
                } catch (e: SecureStorageError) {
                    result = RetrievalEvent.Failed(
                        ErrorTypeHandler.getErrorType(e),
                        "authenticate call throws SecureStorageError ${e.message}",
                    )
                } catch (e: Exception) {
                    result = RetrievalEvent.Failed(
                        SecureStoreErrorType.GENERAL,
                        "authenticate call throws Exception ${e.message}",
                    )
                } finally {
                    authenticator.close()
                }
            }
        }
        return result
    }

    @Deprecated(
        "Replace with SecureStoreAsyncV2.exists(...) to allow handling errors correctly" +
            " - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("java/uk/gov/android/securestore/SecureStoreAsyncV2.kt"),
        level = DeprecationLevel.WARNING,
    )
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

    private suspend fun cryptoDecryptText(
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
                    onTextReady(hybridCryptoManagerAsync.decrypt(encryptedData, encryptedKey))
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

    private suspend fun handleResults(vararg key: String): MutableMap<String, String> {
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

    private suspend fun processSafeHandleResultsOnAuthenticateSuccess(
        vararg key: String,
    ): RetrievalEvent =
        try {
            RetrievalEvent.Success(handleResults(*key))
        } catch (e: SecureStorageError) {
            RetrievalEvent.Failed(
                ErrorTypeHandler.getErrorType(e),
                "authenticate call onSuccess callback throws " +
                    "SecureStorageError ${e.message}",
            )
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
