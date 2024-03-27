package uk.gov.android.securestore.crypto

/**
 * Class to handle encryption and decryption of [String] data
 */
interface CryptoManager {
    /**
     * Encrypt a [String]
     *
     * @param text Plain text to encrypt
     *
     * @return Encrypted data as a [String]
     *
     * @throws [java.security.GeneralSecurityException] If encryption fails
     */
    fun encryptText(
        text: String
    ): String

    /**
     * Decrypt a [String]
     *
     * @param text Encrypted [String] to decrypt
     * @param callback Method to use decrypted text (the result)
     *
     * @throws [java.security.GeneralSecurityException] If decryption fails
     */
    fun decryptText(
        text: String,
        callback: (result: String?) -> Unit
    )

    /**
     * Remove an encryption key entry from the Keystore
     *
     * @throws [java.security.KeyStoreException] If Keystore is not initialized or entry not removed
     */
    fun deleteKey()
}
