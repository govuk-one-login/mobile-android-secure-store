package uk.gov.android.securestore.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import javax.crypto.Cipher

/**
 * Implementation of [CryptoManager] using RSA encryption algorithm to create Public/Private key pair.
 */
internal class RsaCryptoManager : CryptoManager {
    private val keyStore: KeyStore = KeyStore.getInstance(TYPE).apply {
        load(null)
    }

    override fun encryptText(alias: String, text: String): String {
        val encryptCipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getKeyEntry(alias).certificate.publicKey)
        }

        val encryptedBytes = encryptCipher.doFinal(text.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
    }

    override fun decryptText(alias: String, text: String): String {
        val encryptedBytes = Base64.decode(text, Base64.NO_WRAP)

        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, getKeyEntry(alias).privateKey)
        }
            .doFinal(encryptedBytes)
            .decodeToString()
    }

    override fun deleteKey(alias: String) {
        keyStore.deleteEntry(alias)
    }

    private fun getKeyEntry(alias: String): PrivateKeyEntry {
        val existingKey = keyStore.getEntry(alias, null) as? PrivateKeyEntry
        return if (existingKey != null) {
            existingKey
        } else {
            createKeyEntry(alias)
            keyStore.getEntry(alias, null) as PrivateKeyEntry
        }
    }

    private fun createKeyEntry(alias: String) {
        KeyPairGenerator.getInstance(ALGORITHM, TYPE).apply {
            initialize(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setKeySize(KEY_SIZE)
                    .setBlockModes(BLOCK_MODE)
                    .setEncryptionPaddings(PADDING)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
        }.generateKeyPair()
    }

    companion object {
        private const val TYPE = "AndroidKeyStore"
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_ECB
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
        private const val KEY_SIZE = 4096
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }
}
