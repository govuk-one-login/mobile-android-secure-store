package uk.gov.android.securestore

import android.content.Context
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.flow.Flow
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration

/**
 * Create an instance of [SecureStoreAsync] to save, query and delete data. Data stored as a key value pair, with the value being a [String]
 */
@Deprecated(
    "Replace with SecureStoreAsyncV2 to allow handling errors correctly - aim to be removed by 20th of April 2026",
    replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStoreAsyncV2"),
    level = DeprecationLevel.WARNING,
)
interface SecureStoreAsync {
    /**
     *This must be called before using an instance of secure store, it sets the [AccessControlLevel] for the [SecureStoreAsync]
     *
     * @param context Just a basic context to allow initialisation of storage
     * @param configurationAsync [SecureStorageConfigurationAsync] to allow setting of [AccessControlLevel] and store ID
     */
    @Deprecated(
        "Replace with SecureStoreAsyncV2.init() to allow handling errors correctly" +
            " - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStoreAsyncV2"),
        level = DeprecationLevel.WARNING,
    )
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
     * @throws [uk.gov.android.securestore.error.SecureStorageError] if unable to save
     */
    @Deprecated(
        "Replace with SecureStoreAsyncV2.upsert() to allow handling errors correctly" +
            " - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStoreAsyncV2"),
        level = DeprecationLevel.WARNING,
    )
    suspend fun upsert(key: String, value: String): String

    /**
     * Delete a given value based on a key
     *
     * @param [key] The unique identifier for the value to delete
     *
     */
    @Deprecated(
        "Replace with SecureStoreAsyncV2.delete(...) to allow handling errors correctly" +
            " - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStoreAsyncV2"),
        level = DeprecationLevel.WARNING,
    )
    fun delete(key: String)

    /**
     * Delete everything in the SecureStore
     *
     * @throws [uk.gov.android.securestore.error.SecureStorageError] if unable to delete
     */
    @Deprecated(
        "Replace with SecureStoreAsyncV2.deleteAll(...) to allow handling errors correctly" +
            " - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStoreAsyncV2"),
        level = DeprecationLevel.WARNING,
    )
    suspend fun deleteAll()

    /**
     * Access the data for a given key when authentication is not required; access control level is set to OPEN
     *
     * @param [key] The unique key to identify data to retrieve
     * @return [RetrievalEvent] to cover success or failure
     *
     */
    @Deprecated(
        "Replace with SecureStoreAsyncV2.retrieve() to allow handling errors correctly" +
            " - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStoreAsyncV2"),
        level = DeprecationLevel.WARNING,
    )
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
    @Deprecated(
        "Replace with SecureStoreAsyncV2.retrieveWithAuthentication(...) to allow" +
            " handling errors correctly - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStoreAsyncV2"),
        level = DeprecationLevel.WARNING,
    )
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
    @Deprecated(
        "Replace with SecureStoreAsyncV2.exists(...) to allow handling errors correctly" +
            " - aim to be removed by 20th of April 2026",
        replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStoreAsyncV2"),
        level = DeprecationLevel.WARNING,
    )
    fun exists(key: String): Boolean
}
