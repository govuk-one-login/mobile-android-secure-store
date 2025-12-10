package uk.gov.android.securestore.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import uk.gov.android.securestore.AccessControlLevel
import uk.gov.android.securestore.crypto.limitedmanager.AesCryptoManager
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import javax.crypto.Cipher
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Implementation of [HybridCryptoManagerAsync] using RSA encryption algorithm to create Public/Private key pair.
 * It allows for creation of RSA key-pair which would be used to encrypt/ decrypt an AES key that will
 * be used to encrypt/ decrypt the data provided.
 */
@OptIn(ExperimentalEncodingApi::class)
internal class HybridCryptoManagerAsyncImpl : HybridCryptoManagerAsync {
    private lateinit var alias: String
    private lateinit var accessControlLevel: AccessControlLevel
    private lateinit var dispatcher: CoroutineDispatcher
    private val aesCryptoManager = AesCryptoManager()
    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER).apply {
        load(null)
    }

    override fun init(alias: String, acl: AccessControlLevel, dispatcher: CoroutineDispatcher) {
        accessControlLevel = acl
        this.alias = alias
        this.dispatcher = dispatcher
    }

    override suspend fun encrypt(
        input: String,
    ): EncryptedData = withContext(dispatcher) {
        val encryptCipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getKeyEntry(alias).certificate.publicKey)
        }
        val encryptedData = aesCryptoManager.encrypt(input) {
            val encryptedKey = encryptCipher.doFinal(it)
            val result = Base64.encode(encryptedKey)
            result
        }
        encryptedData
    }

    override suspend fun decrypt(
        encryptedData: String,
        key: String,
    ): String = withContext(dispatcher) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val encryptedKeyBytes = Base64.decode(key)
        val decryptedKey = initCipherAndDecryptKey(
            cipher,
            encryptedKeyBytes,
        )
        aesCryptoManager.decrypt(encryptedData, decryptedKey)
    }

    private fun initCipherAndDecryptKey(
        cipher: Cipher,
        encryptedKey: ByteArray,
    ): String {
        cipher.init(Cipher.DECRYPT_MODE, getKeyEntry(alias).privateKey)
        val encodedKey = Base64.encode(cipher.doFinal(encryptedKey))
        return encodedKey
    }

    override suspend fun deleteKey() {
        if (this::alias.isInitialized) {
            withContext(dispatcher) {
                keyStore.deleteEntry(alias)
            }
        }
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

        KeyPairGenerator.getInstance(ALGORITHM, PROVIDER).apply {
            initialize(
                kpgSpec.build(),
            )
        }.generateKeyPair()
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun getAuthType(accessLevel: AccessControlLevel): Int =
        when (accessLevel) {
            AccessControlLevel.OPEN -> AUTH_TYPE_OPEN
            AccessControlLevel.PASSCODE,
            AccessControlLevel.PASSCODE_AND_BIOMETRICS,
            ->
                KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
        }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_ECB
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
        private const val KEY_SIZE = 2048
        private const val KEY_TIMEOUT = 2
        private const val AUTH_TYPE_OPEN = -1
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }
}
