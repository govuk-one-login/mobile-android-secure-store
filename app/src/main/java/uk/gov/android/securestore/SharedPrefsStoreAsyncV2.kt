package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.authentication.UserAuthenticator
import uk.gov.android.securestore.crypto.HybridCryptoManagerAsync
import uk.gov.android.securestore.crypto.HybridCryptoManagerAsyncImpl
import uk.gov.android.securestore.error.SecureStorageErrorV2
import uk.gov.android.securestore.error.SecureStorageErrorV2.Companion.mapToSecureStorageError
import kotlin.coroutines.resumeWithException
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
            throw e.mapToSecureStorageError()
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
            throw e.mapToSecureStorageError()
        }
    }

    override suspend fun retrieve(
        vararg key: String,
    ): Map<String, String?> {
        return configurationAsync?.let { configuration ->
            if (configuration.accessControlLevel != AccessControlLevel.OPEN) {
                throw SecureStorageErrorV2(Exception(REQUIRE_OPEN_ACCESS_LEVEL))
            } else {
                try {
                    handleResults(*key)
                } catch (e: Throwable) {
                    throw e.mapToSecureStorageError()
                }
            }
        } ?: throw SecureStorageErrorV2(INIT_ERROR)
    }

    override suspend fun retrieveWithAuthentication(
        vararg key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity,
    ): Map<String, String?> {
        return configurationAsync?.let { configuration ->
            // When access control is set to open on the secureStore instance, then redirect consumer to use the retrieve method
            if (configuration.accessControlLevel == AccessControlLevel.OPEN) {
                throw SecureStorageErrorV2(Exception(AUTH_ON_OPEN_STORE_ERROR_MSG))
            } else {
                // Attempt to surface the Biometrics prompt and handle the result of that
                try {
                    authenticator.init(context)
                    // Can throw secure storage error that doesn't need to be mapped
                    handleBiometricPrompt(configuration, authPromptConfig)
                    handleResults(*key)
                    // Catches errors thrown from the BiometricPrompt onError(...)
                } catch (sse: SecureStorageErrorV2) {
                    throw sse
                    // Catches any other errors (mainly the java.security and java.crypto fron the KeyStore)
                } catch (e: Throwable) {
                    throw e.mapToSecureStorageError()
                } finally {
                    authenticator.close()
                }
            }
        } ?: throw SecureStorageErrorV2(INIT_ERROR)
    }

    override fun exists(key: String): Boolean {
        return sharedPrefs?.contains(key) == true
    }

    private fun writeToPrefs(key: String, value: String?) {
        sharedPrefs?.let {
            it.edit {
                putString(key, value)
            }
        } ?: throw INIT_ERROR
    }

    /**
     * Handles data decryption given a certain alias.
     *
     * @param alias - [String] representing a key for a value stored in Shared Prefs
     * @throws [java.security.GeneralSecurityException] and it's subclasses and  [Exception]
     */
    private suspend fun cryptoDecryptText(
        alias: String,
        onTextReady: (String?) -> Unit,
    ) {
        sharedPrefs?.let {
            val encryptedData = it.getString(alias, null)
            val encryptedKey = it.getString(alias + KEY_SUFFIX, null)
            if (encryptedData.isNullOrEmpty() || encryptedKey.isNullOrEmpty()) {
                onTextReady(null)
            } else {
                onTextReady(hybridCryptoManagerAsync.decrypt(encryptedData, encryptedKey))
            }
        } ?: throw INIT_ERROR
    }

    /**
     * Handles decryption of data provided a EC key.
     *
     * @param key - [String] representing a key for a value stored in Shared Prefs
     * @throws [java.security.GeneralSecurityException] and it's subclasses and  [Exception]
     */
    private suspend fun handleResults(vararg key: String): Map<String, String?> {
        val results = mutableMapOf<String, String?>()
        key.forEach { alias ->
            cryptoDecryptText(alias) { data ->
                results[alias] = data
            }
        }
        return results
    }

    /**
     * Manages displaying the biometric prompt and it's behaviour.
     *
     * @throws [SecureStorageErrorV2] when onError is called. See [SecureStorageErrorV2.getErrorFromBiometricsError] for more info
     */
    private suspend fun handleBiometricPrompt(
        config: SecureStorageConfigurationAsync,
        authPromptConfig: AuthenticatorPromptConfiguration,
    ) {
        suspendCoroutine { continuation ->
            authenticator.authenticate(
                config.accessControlLevel,
                authPromptConfig,
                AuthenticatorCallbackHandler(
                    onSuccess = {
                        // This just allows for continuation
                        continuation.resumeWith(Result.success(true))
                    },
                    onError = { errorCode, errorString ->
                        // Continues the coroutine with the error
                        continuation.resumeWithException(
                            SecureStorageErrorV2
                                .getErrorFromBiometricsError(errorCode, errorString),
                        )
                    },
                    onFailure = {
                        // Do nothing to allow user to try again
                    },
                ),
            )
        }
    }

    companion object {
        // DO NOT CHANGE THIS
        internal const val KEY_SUFFIX = "Key"

        internal val INIT_ERROR = Exception("Must call init on SecureStore first!")
        internal const val AUTH_ON_OPEN_STORE_ERROR_MSG = "Use retrieve method, access control is" +
            " set to OPEN, no need for auth"
        internal const val REQUIRE_OPEN_ACCESS_LEVEL = "Access control level must be OPEN to use" +
            " this retrieve method"
    }
}
