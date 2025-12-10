package uk.gov.android.securestore.crypto

import kotlinx.coroutines.CoroutineDispatcher
import uk.gov.android.securestore.AccessControlLevel

/**
 * Interface to handle encryption and decryption of [String] data
 */
interface HybridCryptoManagerAsync {
    /**
     *Init the [AccessControlLevel] and alias, this must be done before using the CryptoManager
     */
    fun init(alias: String, acl: AccessControlLevel, dispatcher: CoroutineDispatcher)

    /**
     * Encrypt a [String]
     *
     * @param input Plain text to encrypt
     *
     * @return Encrypted data as a [EncryptedData] returning an encrypted key and encrypted data
     *
     * @throws [java.security.GeneralSecurityException] if encryption fails
     */
    suspend fun encrypt(
        input: String,
    ): EncryptedData

    /**
     * Decrypt a [String]
     *
     * @param encryptedData Encrypted [String] to decrypt
     * @param callback Method to use decrypted text (the result)
     *
     * @throws [java.security.GeneralSecurityException] if decryption fails
     */
    suspend fun decrypt(
        encryptedData: String,
        encryptedKey: String,
    ): String

    /**
     * Remove an encryption key entry from the Keystore
     *
     * @throws [java.security.KeyStoreException] If Keystore is not initialized or entry not removed
     */
    suspend fun deleteKey()
}
