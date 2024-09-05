package uk.gov.android.securestore.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import uk.gov.android.securestore.AccessControlLevel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Implementation of [CryptoManager] using RSA encryption algorithm to create Public/Private key pair.
 */
internal class RsaCryptoManager : CryptoManager {
    private lateinit var alias: String
    private lateinit var accessControlLevel: AccessControlLevel

    private val keyStore: KeyStore = KeyStore.getInstance(TYPE).apply {
        load(null)
    }

    override fun init(alias: String, acl: AccessControlLevel) {
        accessControlLevel = acl
        this.alias = alias
//        when(acl) {
//            AccessControlLevel.OPEN -> {}
//            AccessControlLevel.PASSCODE,
//            AccessControlLevel.PASSCODE_AND_ANY_BIOMETRICS,
//            AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS -> {
//                createRsaKeyEntry(alias)
//            }
//        }
    }

    override fun encryptText(
        text: String
    ): Pair<String, String> {
        val encryptCipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getKeyEntry(alias).certificate.publicKey)
        }
        val firstEncrypt = encryptWithSymmetric(text)
        val encryptedKey = encryptCipher.doFinal(firstEncrypt.second)
        return Pair(
            Base64.encodeToString(firstEncrypt.first, Base64.DEFAULT),
            Base64.encodeToString(encryptedKey, Base64.DEFAULT)
        )
//        return Pair(firstEncrypt.first.decodeToString(), encryptedKey.decodeToString())
    }

    override fun decryptText(
        key: String,
        text: String,
        cipher: Cipher,
        callback: (result: String?) -> Unit
    ) {
        val encryptedBytes = Base64.decode(text, Base64.DEFAULT)
        val encryptedKey = Base64.decode(key, Base64.DEFAULT)
        val firstDecrypt = cipher.doFinal(encryptedKey)
        callback(decryptWithSymmetric(firstDecrypt, encryptedBytes))
    }

    override fun decryptText(
        key: String,
        text: String,
        callback: (result: String?) -> Unit
    ) {
        val encryptedBytes = Base64.decode(text, Base64.NO_WRAP)
        val encryptedKey = Base64.decode(key, Base64.NO_WRAP)

        val cipher = Cipher.getInstance(TRANSFORMATION)

        initCipherAndDecrypt(
            encryptedKey,
            cipher,
            encryptedBytes,
            callback
        )
    }

    private fun initCipherAndDecrypt(
        key: ByteArray,
        cipher: Cipher,
        encryptedBytes: ByteArray,
        callback: (result: String?) -> Unit
    ) {
        cipher.init(Cipher.DECRYPT_MODE, getKeyEntry(alias).privateKey)
        val firstDecrypt = cipher.doFinal(key)
        callback(decryptWithSymmetric(firstDecrypt, encryptedBytes))
//        callback(cipher.doFinal(encryptedBytes).decodeToString())
    }

    override fun deleteKey() {
        keyStore.deleteEntry(alias)
    }

    override fun getCipher(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getKeyEntry(alias).privateKey)
        return cipher
    }

    private fun encryptSecretKey(key: ByteArray): ByteArray {
        val encryptCipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getKeyEntry(alias).certificate.publicKey)
        }
        return encryptCipher.doFinal(key)
    }

    private fun getKeyEntry(alias: String): PrivateKeyEntry {
        val existingKey = keyStore.getEntry(alias, null) as? PrivateKeyEntry
        return if (existingKey != null) {
            existingKey
        } else {
            createRsaKeyEntry(alias)
            keyStore.getEntry(alias, null) as PrivateKeyEntry
        }
    }

    private fun createRsaKeyEntry(alias: String) {
        val kpgSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(KEY_SIZE)
            .setBlockModes(BLOCK_MODE)
            .setEncryptionPaddings(PADDING)
            .setUserAuthenticationRequired(accessControlLevel != AccessControlLevel.OPEN)
            .setRandomizedEncryptionRequired(true)

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            kpgSpec
                .setUserAuthenticationValidityDurationSeconds(KEY_TIMEOUT)
        } else {
            kpgSpec
                .setUserAuthenticationParameters(
                    KEY_TIMEOUT,
                    getAuthType(accessControlLevel)
                )
        }

        if (accessControlLevel == AccessControlLevel.PASSCODE_AND_ANY_BIOMETRICS) {
            kpgSpec.setInvalidatedByBiometricEnrollment(false)
        }

        println("before rsa key gen")
        KeyPairGenerator.getInstance(ALGORITHM, TYPE).apply {
            initialize(
                kpgSpec.build()
            )
        }.generateKeyPair()
        println("after rsa key gen")
    }

    private fun encryptWithSymmetric(input: String): Pair<ByteArray, ByteArray> {
        // Create and initialize the Cipher
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = createSymmetricKey()
        println("generate symmetric key: ${key.encoded}")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key.encoded, KeyProperties.KEY_ALGORITHM_AES),
        )

        // Encrypt the data
        val encryptionIv = cipher.iv // Store this IV for decryption
        val encryptedData = cipher.doFinal(input.toByteArray())

        // Combine IV and encrypted data (IV needs to be passed with the ciphertext for decryption)
        return Pair(encryptionIv + encryptedData, key.encoded)
    }

    private fun decryptWithSymmetric(key: ByteArray, encryptedData: ByteArray): String {
        // Extract the IV and encrypted data
        val encryptionIv = encryptedData.copyOfRange(0, 12)
        val ciphertext = encryptedData.copyOfRange(12, encryptedData.size)

        // Create and initialize the Cipher for decryption
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, encryptionIv)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, KeyProperties.KEY_ALGORITHM_AES),
            gcmSpec
        )

        // Decrypt the data
        return cipher.doFinal(ciphertext).decodeToString()
    }

    private fun createSymmetricKey(): SecretKey {
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM) // GCM is recommended for AES
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256) // AES-256 key size
            .build()
        // Generate a 256-bit key
        val outputKeyLength = 256

        val secureRandom = SecureRandom()

        // Do *not* seed secureRandom! Automatically seeded from system entropy.
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(secureRandom)
        return keyGenerator.generateKey()
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun getAuthType(accessLevel: AccessControlLevel): Int =
        when (accessLevel) {
            AccessControlLevel.OPEN -> AUTH_TYPE_OPEN
            AccessControlLevel.PASSCODE -> KeyProperties.AUTH_DEVICE_CREDENTIAL
            AccessControlLevel.PASSCODE_AND_ANY_BIOMETRICS,
            AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS ->
                KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
        }

    companion object {
        private const val TYPE = "AndroidKeyStore"
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_ECB
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
        private const val KEY_SIZE = 2048
        private const val KEY_TIMEOUT = 5
        private const val AUTH_TYPE_OPEN = -1
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }
}
