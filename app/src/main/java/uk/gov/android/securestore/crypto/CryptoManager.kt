package uk.gov.android.securestore.crypto

/**
 * Class to handle encryption and decryption of [String] data
 */
interface CryptoManager {
    /**
     * Encrypt a [String]
     *
     * @param alias [String] value for the name of the encryption key. Uses existing one or create a new one
     * @param text Plain text to encrypt
     *
     * @return Encrypted data as a [String]
     */
    fun encryptText(alias: String, text: String): String

    /**
     * Decrypt a [String]
     *
     * @param alias [String] value for the name of the decryption key. Must be same as key used to encrypt the data
     * @param text Encrypted [String] to decrypt
     *
     * @return The decrypted text as a [String]
     */
    fun decryptText(alias: String, text: String): String

    /**
     * Remove an encryption key from the KeyStore
     *
     * @param alias Name of key to remove
     */
    fun deleteKey(alias: String)
}
