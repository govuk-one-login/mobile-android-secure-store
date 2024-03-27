package uk.gov.android.securestore

import androidx.fragment.app.FragmentActivity
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration

/**
 * Create an instance of [SecureStore] to save, query and delete data. Data stored as a key value pair, with the value being a [String]
 */
interface SecureStore {
    /**
     * Save a value, if the key exists it is overwritten, if it doesn't exist it's added
     *
     * @param [key] The unique key to save the data against
     * @param [value] The data to save as a [String]
     * @param [context] The [FragmentActivity] where the method is called
     *
     * @throws [SecureStorageError] if unable to save
     */
    suspend fun upsert(key: String, value: String, context: FragmentActivity): String

    /**
     * Delete a given value based on a key
     *
     * @param [key] The unique identifier for the value to delete
     * @param [context] The [FragmentActivity] where the method is called
     *
     * @throws [SecureStorageError] if unable to delete
     */
    fun delete(key: String, context: FragmentActivity)

    /**
     * Access the data for a given key when authentication is not required; access control level is set to OPEN
     *
     * @param [key] The unique key to identify data to retrieve
     * @return The data held against the given key, null if no data held
     *
     * @throws [SecureStorageError] if unable to retrieve
     */
    suspend fun retrieve(
        key: String
    ): String?

    /**
     * Access the data for a given key when authentication is required; access control level is not OPEN
     *
     * @param [key] The unique key to identify data to retrieve
     * @param authPromptConfig Configuration for the Biometric prompt
     * @param [context] The [FragmentActivity] where the method is called, used for auth prompt
     * @return The data held against the given key, null if no data held
     *
     * @throws [SecureStorageError] if unable to retrieve
     */
    suspend fun retrieveWithAuthentication(
        key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity
    ): String?

    /**
     * Check if a certain key exists in the store
     *
     * @param [key] Key to select
     * @return True or false if the key exists in the store
     *
     * @throws [SecureStorageError] if unable to check for existence
     */
    fun exists(key: String): Boolean
}
