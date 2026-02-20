package uk.gov.android.securestore.error

import androidx.biometric.BiometricPrompt
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableEntryException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.NoSuchPaddingException

/**
 * Error returned from any methods within [uk.gov.android.securestore.SharedPrefsStoreAsyncV2]
 */
class SecureStorageErrorV2(
    val exception: Exception,
    val type: SecureStoreErrorTypeV2 = SecureStoreErrorTypeV2.RECOVERABLE,
) : Exception(exception) {

    companion object {
        /**
         * Maps any exceptions thrown within the implementation of [uk.gov.android.securestore.SecureStoreAsyncV2] and it is
         * an extension function on [Exception]
         *
         * @return [uk.gov.android.securestore.error.SecureStorageErrorV2]
         */
        fun Throwable.mapToSecureStorageError(): SecureStorageErrorV2 {
            val errorType = when (this) {
                is AEADBadTagException,
                is UnrecoverableKeyException,
                is BadPaddingException,
                is NoSuchAlgorithmException,
                is NoSuchPaddingException,
                is UnsupportedOperationException,
                is InvalidKeyException,
                is UnrecoverableEntryException,
                is KeyStoreException,
                is IllegalStateException,
                is InvalidAlgorithmParameterException,
                is IndexOutOfBoundsException,
                is GeneralSecurityException,
                -> SecureStoreErrorTypeV2.UNRECOVERABLE
                else -> SecureStoreErrorTypeV2.RECOVERABLE
            }
            val exception = when (this) {
                is Exception -> this
                else -> Exception(this)
            }
            val result = SecureStorageErrorV2(
                exception,
                errorType,
            )
            return result
        }

        /**
         * Maps [BiometricPrompt] exceptions into [uk.gov.android.securestore.error.SecureStorageErrorV2]
         *
         * @return [uk.gov.android.securestore.error.SecureStorageErrorV2]
         */
        fun getErrorFromBiometricsError(errorCode: Int, errorMsg: CharSequence): SecureStorageErrorV2 {
            val errorType = when (errorCode) {
                BiometricPrompt.ERROR_USER_CANCELED -> SecureStoreErrorTypeV2.USER_CANCELLED
                BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
                BiometricPrompt.ERROR_NO_BIOMETRICS,
                ->
                    SecureStoreErrorTypeV2.NO_LOCAL_AUTH_ENABLED
                else -> SecureStoreErrorTypeV2.RECOVERABLE
            }
            val exp = SecureStorageErrorV2(
                Exception("$BIOMETRIC_PREFIX $errorCode $errorMsg"),
                errorType,
            )
            return exp
        }

        internal const val BIOMETRIC_PREFIX = "biometric error code "
    }
}

enum class SecureStoreErrorTypeV2 {
    RECOVERABLE,
    UNRECOVERABLE,
    USER_CANCELLED,
    NO_LOCAL_AUTH_ENABLED,
}
