package uk.gov.android.securestore.crypto.limitedmanager

/**
 * Interface to handle encryption and decryption of [String] data
 */
interface LimitedCryptoManager {
    /**
     * Encrypt a [String]
     *
     * @param input Plain text to encrypt
     * @param callback Additional key for encryption
     *
     * @return Encrypted data as a [String]
     *
     * @throws [java.security.GeneralSecurityException] if encryption fails
     */
    fun encrypt(
        input: String,
        callback: (key: ByteArray) -> String?,
    ): EncryptedData

    /**
     * Decrypt a [String]
     *
     * @param encryptedData Encrypted [String] to decrypt
     * @param callback Method to use decrypted text (the result)
     *
     * @throws [java.security.GeneralSecurityException] if decryption fails
     */
    fun decrypt(
        encryptedData: String,
        key: String,
        callback: (data: String?) -> Unit,
    )

    data class EncryptedData(
        val data: String,
        val key: String,
    )

    sealed class CryptoManagerError(private val error: String) : Exception(error) {
        data object NullEncryptedKey : CryptoManagerError(NULL_ENCRYPTED_KEY_ERROR)
    }

    companion object {
        const val NULL_ENCRYPTED_KEY_ERROR = "NullEncryptedKey:" +
            " Encrypted key shouldn't be null or empty!"
    }
}
