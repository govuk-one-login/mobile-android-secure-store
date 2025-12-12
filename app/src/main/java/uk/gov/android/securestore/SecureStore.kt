package uk.gov.android.securestore

import android.content.Context
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.flow.Flow
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration

/**
 * Create an instance of [SecureStore] to save, query and delete data. Data stored as a key value pair, with the value being a [String]
 */
@Deprecated(
    message = "This has been replaced by a Secure Store with async methods.",
    replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStoreAsync"),
    level = DeprecationLevel.WARNING,
)
interface SecureStore {
    /**
     *This must be called before using an instance of secure store, it sets the [AccessControlLevel] for the [SecureStore]
     *
     * @param context Just a basic context to allow initialisation of storage
     * @param configuration [SecureStorageConfiguration] to allow setting of [AccessControlLevel] and store ID
     */
    fun init(
        context: Context,
        configuration: SecureStorageConfiguration,
    )

    /**
     * Save a value, if the key exists it is overwritten, if it doesn't exist it's added
     *
     * @param [key] The unique key to save the data against
     * @param [value] The data to save as a [String]
     *
     * @throws [uk.gov.android.securestore.error.SecureStorageError] if unable to save
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
     * @throws [uk.gov.android.securestore.error.SecureStorageError] if unable to delete
     */
    fun deleteAll()

    /**
     * Access the data for a given key when authentication is not required; access control level is set to OPEN
     *
     * @param [key] The unique key to identify data to retrieve
     * @return [RetrievalEvent] to cover success or failure
     *
     */
    suspend fun retrieve(
        vararg key: String,
    ): RetrievalEvent

    /**
     * Access the data for a given key when authentication is required; access control level is not OPEN
     *
     * @param [key] The unique key to identify data to retrieve
     * @param [authPromptConfig] Configuration for the Biometric prompt
     * @param [context] The [FragmentActivity] where the method is called, used for auth prompt
     * @return A [Flow] of [RetrievalEvent]s, allowing for multiple failed attempts for auth
     *
     */
    suspend fun retrieveWithAuthentication(
        vararg key: String,
        authPromptConfig: AuthenticatorPromptConfiguration,
        context: FragmentActivity,
    ): RetrievalEvent

    /**
     * Check if a certain key exists in the store
     *
     * @param [key] Key to select
     * @return True or false if the key exists in the store
     *
     * @throws [uk.gov.android.securestore.error.SecureStorageError] if unable to check for existence
     */
    fun exists(key: String): Boolean
}
