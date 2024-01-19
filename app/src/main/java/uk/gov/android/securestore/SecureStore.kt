package uk.gov.android.securestore

/**
 * Create an instance of [SecureStore] to save, query and delete data. Data stored as a key value pair, with the value being a [String]
 */
interface SecureStore {
    /**
     * Save a value, if the key exists it is overwritten, if it doesn't exist it's added
     *
     * @param [key] The unique key to save the data against
     * @param [value] The data to save as a [String]
     *
     * @throws [SecureStorageError] if unable to save
     */
    fun upsert(key: String, value: String): String

    /**
     * Delete a given value based on a key
     *
     * @param [key] The unique identifier for the value to delete
     *
     * @throws [SecureStorageError] if unable to delete
     */
    fun delete(key: String)

    /**
     * Access the data for a given key
     *
     * @param [key] The unique key to identify data to retrieve
     * @return The data held against the given key, null if no data held
     *
     * @throws [SecureStorageError] if unable to retrieve
     */
    fun retrieve(key: String): String?

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
