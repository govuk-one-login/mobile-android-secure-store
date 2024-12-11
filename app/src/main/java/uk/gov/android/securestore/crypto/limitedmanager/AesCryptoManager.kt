package uk.gov.android.securestore.crypto.limitedmanager

import android.security.keystore.KeyProperties
import uk.gov.android.securestore.crypto.EncryptedData
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
class AesCryptoManager : SymmetricCryptoManager {
    override fun encrypt(
        input: String,
        encryptAesKey: (key: ByteArray) -> String?,
    ): EncryptedData {
        // Create and initialize the Cipher
        val cipher = Cipher.getInstance(AES_ALG)
        val aesKey = createKey()
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(aesKey.encoded, KeyProperties.KEY_ALGORITHM_AES),
        )

        val encryptedKey = encryptAesKey(aesKey.encoded)
        // Encrypt the data with the AES key
        val encryptionIv = cipher.iv // Store this IV for decryption
        val encryptedDataByteArr = cipher.doFinal(input.toByteArray())
        val encryptedData = Base64.encode(encryptionIv + encryptedDataByteArr)

        // Combine IV and encrypted data (IV needs to be passed with the ciphertext for decryption)
        if (!encryptedKey.isNullOrEmpty()) {
            return EncryptedData(data = encryptedData, key = encryptedKey)
        } else {
            throw SymmetricCryptoManager.CryptoManagerError.NullEncryptedKey
        }
    }

    override fun decrypt(
        encryptedData: String,
        key: String,
        callback: (data: String?) -> Unit,
    ) {
        val decodedKey = Base64.decode(key)
        // Extract the IV and encrypted data
        val encryptedDataBytes = Base64.decode(encryptedData)
        val encryptionIv = encryptedDataBytes.copyOfRange(OFFSET, IV_BYTES_SIZE)
        val ciphertext = encryptedDataBytes.copyOfRange(IV_BYTES_SIZE, encryptedDataBytes.size)

        // Create and initialize the Cipher for decryption
        val cipher = Cipher.getInstance(AES_ALG)
        val gcmSpec = GCMParameterSpec(TAG_LENGTH, encryptionIv)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(decodedKey, KeyProperties.KEY_ALGORITHM_AES),
            gcmSpec,
        )

        // Decrypt the data
        callback(cipher.doFinal(ciphertext).decodeToString())
    }

    private fun createKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        // Do *not* seed secureRandom - Automatically seeded from system entropy.
        val secureRandom = SecureRandom()
        // Generate a 256-bit key
        keyGenerator.init(KEY_SIZE, secureRandom)
        return keyGenerator.generateKey()
    }

    companion object {
        private const val KEY_SIZE = 256
        private const val IV_BYTES_SIZE = 12
        private const val TAG_LENGTH = 128
        private const val OFFSET = 0
        private const val AES_ALG = "AES/GCM/NoPadding"
    }
}
