package uk.gov.android.securestore.error

import android.security.keystore.UserNotAuthenticatedException
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.security.InvalidKeyException
import kotlin.UnsupportedOperationException
import kotlin.test.assertEquals

class ErrorTypeHandlerTest {
    @ParameterizedTest
    @MethodSource("getData")
    fun testHandler(error: SecureStorageError, expectedType: SecureStoreErrorType) {
        val actualType = ErrorTypeHandler.getErrorType(error)
        assertEquals(expectedType, actualType)
    }

    companion object {
        @JvmStatic
        fun getData(): List<Arguments> {
            return listOf(
                Arguments.of(
                    SecureStorageError(InvalidKeyException()),
                    SecureStoreErrorType.USER_CANCELED_BIO_PROMPT,
                ),
                Arguments.of(
                    SecureStorageError(UserNotAuthenticatedException()),
                    SecureStoreErrorType.USER_CANCELED_BIO_PROMPT,
                ),
                Arguments.of(
                    SecureStorageError(UnsupportedOperationException()),
                    SecureStoreErrorType.USER_CANCELED_BIO_PROMPT,
                ),
                Arguments.of(
                    SecureStorageError(Exception()),
                    SecureStoreErrorType.GENERAL,
                ),
            )
        }
    }
}
