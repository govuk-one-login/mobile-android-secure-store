package uk.gov.android.securestore.crypto.limitedmanager

import android.security.keystore.KeyProperties
import android.util.Log
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import uk.gov.android.securestore.crypto.limitedmanager.LimitedCryptoManager.EncryptedData
import java.security.SecureRandom
import javax.crypto.spec.GCMParameterSpec

@OptIn(ExperimentalEncodingApi::class)
class AesCryptoManager : LimitedCryptoManager {
    override fun encrypt(
        input: String,
        callback: (key: ByteArray) -> String?
    ): EncryptedData {
        // Create and initialize the Cipher
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val aesKey = createKey()
        println("generate symmetric key: ${aesKey.encoded} for $input")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(aesKey.encoded, KeyProperties.KEY_ALGORITHM_AES),
        )

        val encryptedKey = callback(aesKey.encoded)
        // Encrypt the data with the AES key
        val encryptionIv = cipher.iv // Store this IV for decryption
        val encryptedDataByteArr = cipher.doFinal(input.toByteArray())
        val encryptedData = Base64.encode(encryptionIv + encryptedDataByteArr)

        // Combine IV and encrypted data (IV needs to be passed with the ciphertext for decryption)
        if (!encryptedKey.isNullOrEmpty()) {
            return EncryptedData(data = encryptedData, key = encryptedKey)
        } else {
            throw LimitedCryptoManager.CryptoManagerError.NullEncryptedKey
        }
    }

    override fun decrypt(
        encryptedData: String,
        key: String,
        callback: (data: String?) -> Unit
    ) {
        val decodedKey = Base64.decode(key)
        // Extract the IV and encrypted data
        val encryptedDataBytes = Base64.decode(encryptedData)
        val encryptionIv = encryptedDataBytes.copyOfRange(0, 12)
        val ciphertext = encryptedDataBytes.copyOfRange(12, encryptedDataBytes.size)

        // Create and initialize the Cipher for decryption
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, encryptionIv)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(decodedKey, KeyProperties.KEY_ALGORITHM_AES),
            gcmSpec
        )

        Log.d("AesKey", key)
        Log.d("EncryptedDataAES", encryptedData)
        Log.d("DecryptedDataAES", cipher.doFinal(ciphertext).decodeToString())

        // Decrypt the data
        callback(cipher.doFinal(ciphertext).decodeToString())
    }

    private fun createKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        // Do *not* seed secureRandom! Automatically seeded from system entropy.
        val secureRandom = SecureRandom()
        // Generate a 256-bit key
        keyGenerator.init(KEY_SIZE, secureRandom)
        return keyGenerator.generateKey()
    }

    companion object {
        private const val KEY_SIZE = 256
    }
}
