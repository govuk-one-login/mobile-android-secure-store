package uk.gov.android.securestore.crypto

import uk.gov.android.securestore.AccessControlLevel
import uk.gov.android.securestore.crypto.limitedmanager.LimitedCryptoManager

/**
 * Interface to handle encryption and decryption of [String] data
 */
interface HybridCryptoManager : LimitedCryptoManager {
    /**
     *Init the [AccessControlLevel] and alias, this must be done before using the CryptoManager
     */
    fun init(alias: String, acl: AccessControlLevel)

    /**
     * Remove an encryption key entry from the Keystore
     *
     * @throws [java.security.KeyStoreException] If Keystore is not initialized or entry not removed
     */
    fun deleteKey()
}
