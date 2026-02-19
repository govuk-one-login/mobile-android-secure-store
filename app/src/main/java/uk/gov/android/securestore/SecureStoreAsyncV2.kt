package uk.gov.android.securestore

import android.content.Context
import androidx.fragment.app.FragmentActivity
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration

/**
 * Create an instance of [SecureStoreAsyncV2] to save, query and delete data. Data stored as a key value pair, with the value being a [String]
 */
interface SecureStoreAsyncV2 {
    /**
     *This must be called before using an instance of secure store, it sets the [AccessControlLevel] for the [SecureStoreAsyncV2]
     *
     * @param context Just a basic context to allow initialisation of storage
     * @param configurationAsync [SecureStorageConfigurationAsync] to allow setting of [AccessControlLevel] and store ID
     */
    fun init(
        context: Context,
        configurationAsync: SecureStorageConfigurationAsync,
    )

    /**
     * Save a value, if the key exists it is overwritten, if it doesn't exist it's added
     *
     * @param [key] The unique key to save the data against
     * @param [value] The data to save as a [String]
     *
     * @throws [uk.gov.android.securestore.error.SecureStorageErrorV2] if unable to save
     */
    suspend fun upsert(key: String, value: String): String

    /**
     * Delete a given value based on a key
     *
     * @param [key] The unique identifier for the value to delete
     *
     */
    fun delete(key: String)

    /**
     * Delete everything in the SecureStore
     *
     * @throws [uk.gov.android.securestore.error.SecureStorageErrorV2] if unable to delete
     */
    suspend fun deleteAll()

    /**
     * Access the data for a given key when authentication is not required; access control level is set to OPEN
     *
     * @param [key] The unique key to identify data to retrieve
     * @return A [Map] of [String] to [String?] to cover success or failure
     *
     * @throws [uk.gov.android.securestore.error.SecureStorageErrorV2] if unable to retrieve
     */
    suspend fun retrieve(
        vararg key: String,
    ): Map<String, String?>

    /**
     * Access the data for a given key when authentication is required; access control level is not OPEN
     *
     * @param [key] The unique key to identify data to retrieve
     * @param [authPromptConfig] Configuration for the Biometric prompt
     * @param [context] The [FragmentActivity] where the method is called, used for auth prompt
     * @return A [Map] of [String] to [String?], allowing for multiple failed attempts for auth
     *
     * @throws [uk.gov.android.securestore.error.SecureStorageErrorV2] if unable to retrieve
     */
    suspend fun retrieveWithAuthentication(
        vararg key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity,
    ): Map<String, String?>

    /**
     * Check if a certain key exists in the store
     *
     * @param [key] Key to select
     * @return True or false if the key exists in the store
     *
     * @throws [uk.gov.android.securestore.error.SecureStorageErrorV2] if unable to check for existence
     */
    fun exists(key: String): Boolean
}
