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
import uk.gov.android.securestore.crypto.HybridCryptoManagerAsync
import uk.gov.android.securestore.crypto.HybridCryptoManagerAsyncImpl
import uk.gov.android.securestore.error.SecureStorageError
import uk.gov.android.securestore.error.SecureStoreErrorType
import kotlin.coroutines.suspendCoroutine

@Suppress("TooGenericExceptionCaught", "TooManyFunctions")
class SharedPrefsStoreAsync(
    private val authenticator: Authenticator = UserAuthenticator(),
    private val hybridCryptoManagerAsync: HybridCryptoManagerAsync = HybridCryptoManagerAsyncImpl(),
) : SecureStoreAsync {
    private val tag = this::class.java.simpleName
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
            throw SecureStorageError(e)
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
            throw SecureStorageError(e)
        }
    }

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
                                        errorString.toString(),
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
                        result =
                            RetrievalEvent.Success(handleResults(*key))
                    }
                } catch (e: SecureStorageError) {
                    result = RetrievalEvent.Failed(e.type, e.message)
                } catch (e: Exception) {
                    Log.e(tag, e.message, e)
                    result = RetrievalEvent.Failed(
                        SecureStoreErrorType.GENERAL,
                        e.message,
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

    companion object {
        private const val KEY_SUFFIX = "Key"
        private fun sseNotFound(alias: String) = SecureStorageError(
            Exception("$alias not found"),
            SecureStoreErrorType.NOT_FOUND,
        )
    }
}
