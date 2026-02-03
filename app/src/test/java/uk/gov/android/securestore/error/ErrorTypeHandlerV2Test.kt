package uk.gov.android.securestore.error

import android.security.keystore.UserNotAuthenticatedException
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
    @MethodSource("getData")
    fun testHandler(error: SecureStorageErrorV2, expectedType: SecureStoreErrorTypeV2) {
        val actualType = ErrorTypeHandlerV2.getErrorType(error)
        assertEquals(expectedType, actualType)
    }

    companion object {
        @Suppress("LongMethod")
        @JvmStatic
        fun getData(): List<Arguments> {
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
                    SecureStorageErrorV2(UserNotAuthenticatedException()),
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
    }
}
