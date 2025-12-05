package uk.gov.android.securestore.error

import android.security.keystore.UserNotAuthenticatedException

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
