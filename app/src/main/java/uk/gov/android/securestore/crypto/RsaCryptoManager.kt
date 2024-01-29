package uk.gov.android.securestore.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.fragment.app.FragmentActivity
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import javax.crypto.Cipher
import uk.gov.android.securestore.AccessControlLevel
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.authentication.UserAuthenticator

/**
 * Implementation of [CryptoManager] using RSA encryption algorithm to create Public/Private key pair.
 */
internal class RsaCryptoManager(
    private val context: FragmentActivity,
    private val alias: String,
    private val accessControlLevel: AccessControlLevel,
    private val authenticator: Authenticator = UserAuthenticator(context)
) : CryptoManager {
    private val keyStore: KeyStore = KeyStore.getInstance(TYPE).apply {
        load(null)
    }

    override fun encryptText(
        text: String
    ): String {
        val encryptCipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getKeyEntry(alias).certificate.publicKey)
        }

        val encryptedBytes = encryptCipher.doFinal(text.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
    }

    override fun decryptText(
        text: String,
        callback: (result: String?) -> Unit,
        authPromptConfig: AuthenticatorPromptConfiguration?
    ) {
        val encryptedBytes = Base64.decode(text, Base64.NO_WRAP)

        val cipher = Cipher.getInstance(TRANSFORMATION)

        if (accessControlLevel == AccessControlLevel.OPEN) {
            cipher.init(Cipher.DECRYPT_MODE, getKeyEntry(alias).privateKey)
            callback(cipher.doFinal(encryptedBytes).decodeToString())
        } else {
            if (authPromptConfig != null) {
                authenticator.authenticate(
                    accessControlLevel,
                    authPromptConfig,
                    AuthenticatorCallbackHandler(
                        onSuccess = {
                            cipher.init(Cipher.DECRYPT_MODE, getKeyEntry(alias).privateKey)
                            val decryptedBytes = cipher.doFinal(encryptedBytes)
                            callback(decryptedBytes?.decodeToString())
                        }
                    )
                )
            } else {
                throw GeneralSecurityException("No authentication prompt configuration set")
            }
        }
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

        KeyPairGenerator.getInstance(ALGORITHM, TYPE).apply {
            initialize(
                kpgSpec.build()
            )
        }.generateKeyPair()
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun getAuthType(accessLevel: AccessControlLevel): Int =
        when (accessLevel) {
            AccessControlLevel.OPEN -> -1
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
        private const val KEY_SIZE = 4096
        private const val KEY_TIMEOUT = 1000
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }
}
