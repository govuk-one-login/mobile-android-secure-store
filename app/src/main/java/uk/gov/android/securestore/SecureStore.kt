package uk.gov.android.securestore

/**
 * Create an instance of [SecureStore] to save, query and delete data. Data is stored as a key value pair, with the value being a [String]
 */
interface SecureStore {
    /**
     * Save a value, if the key exists it will be overwritten, if it does not exist it will be added
     *
     * @param [key] The unique key to save the data against
     * @param [value] The data to be saved as a [String]
     *
     * @throws [SecureStorageError] if unable to save
     */
    fun upsert(key: String, value: String)

    /**
     * Delete a given value based on a key
     *
     * @param [key] The unique identifier for the value to be deleted
     *
     * @throws [SecureStorageError] if unable to delete
     */
    fun delete(key: String)

    /**
     * Access the data for a given key
     *
     * @param [key] The unique key to identify data to be retrieved
     * @return The data held against the given key, null if no data held
     *
     * @throws [SecureStorageError] if unable to retrieve
     */
    fun retrieve(key: String): String?

    /**
     * Check if a certain key exists in the store
     *
     * @param [key] Key to check against
     * @return True or false if the key exists in the store
     *
     * @throws [SecureStorageError] if unable to check for existence
     */
    fun exists(key: String): Boolean
}
