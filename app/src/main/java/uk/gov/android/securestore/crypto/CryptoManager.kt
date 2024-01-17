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
     *
     * @throws [java.security.GeneralSecurityException] If encryption fails
     */
    fun encryptText(alias: String, text: String): String

    /**
     * Decrypt a [String]
     *
     * @param alias [String] value for the name of the decryption key. Must be same as key used to encrypt the data
     * @param text Encrypted [String] to decrypt
     *
     * @return The decrypted text as a [String]
     *
     * @throws [java.security.GeneralSecurityException] If decryption fails
     */
    fun decryptText(alias: String, text: String): String

    /**
     * Remove an encryption key entry from the Keystore
     *
     * @param alias Name of key entry to remove
     *
     * @throws [java.security.KeyStoreException] If Keystore is not initialized or entry not removed
     */
    fun deleteKey(alias: String)
}
