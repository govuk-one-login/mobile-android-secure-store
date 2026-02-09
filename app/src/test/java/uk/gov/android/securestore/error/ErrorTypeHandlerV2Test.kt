package uk.gov.android.securestore.error

import androidx.biometric.BiometricPrompt
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.lang.IllegalStateException
import java.lang.IndexOutOfBoundsException
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.NoSuchPaddingException
import kotlin.test.assertEquals

class ErrorTypeHandlerV2Test {
    @ParameterizedTest
    @MethodSource("getDataForSecureStoreError")
    fun testHandlerWithSecureStoreError(
        error: SecureStorageErrorV2,
        expectedType: SecureStoreErrorTypeV2,
    ) {
        val actualType = ErrorTypeHandlerV2.getErrorType(error)
        assertEquals(expectedType, actualType)
    }

    @ParameterizedTest
    @MethodSource("getDataForErrorCode")
    fun testHandlerWithType(errorCode: Int, expectedType: SecureStoreErrorTypeV2) {
        val actualType = ErrorTypeHandlerV2.getErrorType(errorCode)
        assertEquals(expectedType, actualType)
    }

    companion object {
        @Suppress("LongMethod")
        @JvmStatic
        fun getDataForSecureStoreError(): List<Arguments> {
            return listOf(
                Arguments.of(
                    SecureStorageErrorV2(AEADBadTagException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(UnrecoverableKeyException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(BadPaddingException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(NoSuchAlgorithmException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(NoSuchPaddingException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(java.lang.UnsupportedOperationException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(InvalidKeyException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(UnrecoverableKeyException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(KeyStoreException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(IllegalStateException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(InvalidAlgorithmParameterException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(IndexOutOfBoundsException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(GeneralSecurityException()),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    SecureStorageErrorV2(Exception()),
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
            )
        }

        @Suppress("LongMethod")
        @JvmStatic
        fun getDataForErrorCode(): List<Arguments> {
            return listOf(
                Arguments.of(
                    BiometricPrompt.ERROR_USER_CANCELED,
                    SecureStoreErrorTypeV2.USER_CANCELLED,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_NO_BIOMETRICS,
                    SecureStoreErrorTypeV2.ERROR_NO_DEVICE_CREDENTIAL,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
                    SecureStoreErrorTypeV2.ERROR_NO_DEVICE_CREDENTIAL,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_LOCKOUT,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_CANCELED,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_HW_NOT_PRESENT,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_HW_UNAVAILABLE,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_NO_SPACE,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_TIMEOUT,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_VENDOR,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
            )
        }
    }
}
