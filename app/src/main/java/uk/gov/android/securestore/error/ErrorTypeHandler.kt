package uk.gov.android.securestore.error

import android.security.keystore.UserNotAuthenticatedException

@Deprecated(
    "Replace with ErrorTypeHandlerV2 to allow handling errors correctly - aim to be removed by 20th of April 2026",
    replaceWith = ReplaceWith("java/uk/gov/android/securestore/error/ErrorTypeHandlerV2.kt"),
    level = DeprecationLevel.WARNING
)
object ErrorTypeHandler {
    fun getErrorType(error: SecureStorageError): SecureStoreErrorType {
        return when (error.cause) {
            is UserNotAuthenticatedException,
            is UnsupportedOperationException,
            -> SecureStoreErrorType.USER_CANCELED_BIO_PROMPT
            else -> error.type
        }
    }
}
