package uk.gov.android.securestore.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import uk.gov.android.securestore.AccessControlLevel
import uk.gov.android.securestore.crypto.limitedmanager.AesCryptoManager
import uk.gov.android.securestore.crypto.limitedmanager.LimitedCryptoManager.EncryptedData
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import javax.crypto.Cipher
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Implementation of [HybridCryptoManager] using RSA encryption algorithm to create Public/Private key pair.
 */
@OptIn(ExperimentalEncodingApi::class)
internal class RsaHybridCryptoManager : HybridCryptoManager {
    private lateinit var alias: String
    private lateinit var accessControlLevel: AccessControlLevel
    private val aesCryptoManager = AesCryptoManager()
    private val keyStore: KeyStore = KeyStore.getInstance(TYPE).apply {
        load(null)
    }

    override fun init(alias: String, acl: AccessControlLevel) {
        accessControlLevel = acl
        this.alias = alias
    }


    override fun encrypt(
        input: String,
        callback: (key: ByteArray) -> String?
    ): EncryptedData {
        val encryptCipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getKeyEntry(alias).certificate.publicKey)
        }

        val encryptedData = aesCryptoManager.encrypt(input) {
            val encryptedKey = encryptCipher.doFinal(it)
            val result = Base64.encode(encryptedKey)
            Log.d("AESKey", it.contentToString() + "for input: $input")
            Log.d("EncryptedKey", result)
            result
        }
        return encryptedData
    }

    override fun decrypt(
        encryptedData: String,
        encryptedKey: String,
        callback: (data: String?) -> Unit
    ) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val encryptedKeyBytes = Base64.decode(encryptedKey)
        val decryptedKey = initCipherAndDecryptKey(
            cipher,
            encryptedKeyBytes
        )
        aesCryptoManager.decrypt(encryptedData, decryptedKey) { callback(it) }
    }

    private fun initCipherAndDecryptKey(
        cipher: Cipher,
        encryptedKey: ByteArray
    ): String {
        cipher.init(Cipher.DECRYPT_MODE, getKeyEntry(alias).privateKey)
        val encodedKey = Base64.encode(cipher.doFinal(encryptedKey))
        return encodedKey
    }

    override fun deleteKey() {
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
        val kpgSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
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
                    getAuthType(accessControlLevel),
                )
        }

        if (accessControlLevel == AccessControlLevel.PASSCODE_AND_ANY_BIOMETRICS) {
            kpgSpec.setInvalidatedByBiometricEnrollment(false)
        }

        KeyPairGenerator.getInstance(ALGORITHM, TYPE).apply {
            initialize(
                kpgSpec.build(),
            )
        }.generateKeyPair()
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun getAuthType(accessLevel: AccessControlLevel): Int =
        when (accessLevel) {
            AccessControlLevel.OPEN -> AUTH_TYPE_OPEN
            AccessControlLevel.PASSCODE -> KeyProperties.AUTH_DEVICE_CREDENTIAL
            AccessControlLevel.PASSCODE_AND_ANY_BIOMETRICS,
            AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS,
            ->
                KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
        }

    companion object {
        private const val TYPE = "AndroidKeyStore"
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_ECB
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
        private const val KEY_SIZE = 2048
        private const val KEY_TIMEOUT = 2
        private const val AUTH_TYPE_OPEN = -1
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }
}
