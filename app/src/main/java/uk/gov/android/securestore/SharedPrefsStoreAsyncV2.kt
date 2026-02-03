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
import uk.gov.android.securestore.error.ErrorTypeHandlerV2
import uk.gov.android.securestore.error.SecureStorageError
import uk.gov.android.securestore.error.SecureStorageErrorV2
import uk.gov.android.securestore.error.SecureStoreErrorType
import uk.gov.android.securestore.error.SecureStoreErrorTypeV2
import kotlin.coroutines.suspendCoroutine

@Suppress("TooGenericExceptionCaught", "TooManyFunctions")
class SharedPrefsStoreAsyncV2(
    private val authenticator: Authenticator = UserAuthenticator(),
    private val hybridCryptoManagerAsync: HybridCryptoManagerAsync = HybridCryptoManagerAsyncImpl(),
) : SecureStoreAsyncV2 {
    private var configurationAsync: SecureStorageConfigurationAsync? = null
    private var sharedPrefs: SharedPreferences? = null

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

    override suspend fun upsert(key: String, value: String): String {
        return try {
            val result = hybridCryptoManagerAsync.encrypt(value)
                .also {
                    writeToPrefs(key, it.data)
                    writeToPrefs(key + KEY_SUFFIX, it.key)
                }
            result.data
        } catch (e: Exception) {
            throw SecureStorageErrorV2(e)
        }
    }

    override fun delete(key: String) {
        sharedPrefs?.edit {
            remove(key)
        }
    }

    override suspend fun deleteAll() {
        sharedPrefs?.edit {
            clear()
        }
        try {
            hybridCryptoManagerAsync.deleteKey()
        } catch (e: Exception) {
            throw SecureStorageErrorV2(e)
        }
    }

    override suspend fun retrieve(
        vararg key: String,
    ): RetrievalEventV2 {
        return configurationAsync?.let { configuration ->
            if (configuration.accessControlLevel != AccessControlLevel.OPEN) {
                RetrievalEventV2.Failed(
                    SecureStoreErrorTypeV2.RECOVERABLE,
                    "Access control level must be OPEN to use this retrieve method",
                )
            } else {
                try {
                    val results = handleResults(*key)
                    RetrievalEventV2.Success(results)
                } catch (e: SecureStorageErrorV2) {
                    RetrievalEventV2.Failed(
                        e.type,
                        e.message,
                    )
                }
            }
        } ?: RetrievalEventV2.Failed(
            SecureStoreErrorTypeV2.RECOVERABLE,
            "Must call init on SecureStore first!",
        )
    }

    @Suppress("NestedBlockDepth", "LongMethod")
    override suspend fun retrieveWithAuthentication(
        vararg key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity,
    ): RetrievalEventV2 {
        var result: RetrievalEventV2 = RetrievalEventV2.Failed(
            SecureStoreErrorTypeV2.RECOVERABLE,
            "Must call init on SecureStore first!",
        )
        configurationAsync?.let { configuration ->
            if (configuration.accessControlLevel == AccessControlLevel.OPEN) {
                result = RetrievalEventV2.Failed(
                    SecureStoreErrorTypeV2.RECOVERABLE,
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
                                    result = RetrievalEventV2.Failed(
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
                } catch (e: SecureStorageErrorV2) {
                    result = RetrievalEventV2.Failed(
                        ErrorTypeHandlerV2.getErrorType(e),
                        "authenticate call throws SecureStorageError ${e.message}",
                    )
                } catch (e: Exception) {
                    result = RetrievalEventV2.Failed(
                        SecureStoreErrorTypeV2.RECOVERABLE,
                        "authenticate call throws Exception ${e.message}",
                    )
                } finally {
                    authenticator.close()
                }
            }
        }
        return result
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
                throw SecureStorageErrorV2(e)
            }
        } ?: throw SecureStorageErrorV2(Exception("You must call init first!"))
    }

    private fun getErrorType(errorCode: Int): SecureStoreErrorTypeV2 {
        return when (errorCode) {
            BiometricPrompt.ERROR_USER_CANCELED -> SecureStoreErrorTypeV2.USER_CANCELLED
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL ->
                SecureStoreErrorTypeV2.ERROR_NO_DEVICE_CREDENTIAL
            else -> SecureStoreErrorTypeV2.RECOVERABLE
        }
    }

    private suspend fun handleResults(vararg key: String): MutableMap<String, String?> {
        val results = mutableMapOf<String, String?>()
        key.forEach { alias ->
            cryptoDecryptText(alias) { data ->
                results[alias] = data
            }
        }
        return results
    }

    private suspend fun processSafeHandleResultsOnAuthenticateSuccess(
        vararg key: String,
    ): RetrievalEventV2 =
        try {
            RetrievalEventV2.Success(handleResults(*key))
        } catch (e: SecureStorageErrorV2) {
            RetrievalEventV2.Failed(
                ErrorTypeHandlerV2.getErrorType(e),
                "authenticate call onSuccess callback throws " +
                    "SecureStorageError ${e.message}",
            )
        }

    companion object {
        // DO NOT CHANGE THIS
        private const val KEY_SUFFIX = "Key"

        private const val BIOMETRIC_PREFIX = "biometric error code "
    }
}
