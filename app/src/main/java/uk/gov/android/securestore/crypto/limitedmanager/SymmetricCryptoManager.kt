package uk.gov.android.securestore.crypto.limitedmanager

import uk.gov.android.securestore.crypto.EncryptedData

/**
 * Interface to handle encryption and decryption of [String] data
 */
interface SymmetricCryptoManager {
    /**
     * Encrypt a [String]
     *
     * @param input Plain text to encrypt
     * @param encryptAesKey Additional encryption for the key that is used for encrypting the data
     *
     * @return Encrypted data as a [EncryptedData] returning an encrypted key and encrypted data
     *
     * @throws [java.security.GeneralSecurityException] if encryption fails
     * @throws [SymmetricCryptoManager.CryptoManagerError.NullEncryptedKey] if the returned encrypted key from
     * the callback is null or empty
     */
    fun encrypt(
        input: String,
        encryptAesKey: (key: ByteArray) -> String?,
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
    ): String

    sealed class CryptoManagerError(private val error: String) : Exception(error) {
        data object NullEncryptedKey : CryptoManagerError(NULL_ENCRYPTED_KEY_ERROR)
    }

    companion object {
        const val NULL_ENCRYPTED_KEY_ERROR = "NullEncryptedKey:" +
            " Encrypted key shouldn't be null or empty!"
    }
}
