package uk.gov.android.securestore.crypto

import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration

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
     * @param authPromptConfig Configuration for the Biometric prompt, can be null if [uk.gov.android.securestore.SecureStore] is set to OPEN. Default as null
     *
     * @throws [java.security.GeneralSecurityException] If decryption fails
     */
    fun decryptText(
        text: String,
        callback: (result: String?) -> Unit,
        authPromptConfig: AuthenticatorPromptConfiguration? = null
    )

    /**
     * Remove an encryption key entry from the Keystore
     *
     * @throws [java.security.KeyStoreException] If Keystore is not initialized or entry not removed
     */
    fun deleteKey()
}
