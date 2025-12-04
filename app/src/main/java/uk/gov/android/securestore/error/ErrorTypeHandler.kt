package uk.gov.android.securestore.error

import android.security.keystore.UserNotAuthenticatedException
import java.security.InvalidKeyException

object ErrorTypeHandler {
    fun getErrorType(error: SecureStorageError): SecureStoreErrorType {
        return when (error.cause) {
            is UserNotAuthenticatedException -> SecureStoreErrorType.USER_CANCELED_BIO_PROMPT
            is InvalidKeyException -> SecureStoreErrorType.USER_CANCELED_BIO_PROMPT
            is UnsupportedOperationException -> SecureStoreErrorType.USER_CANCELED_BIO_PROMPT
            else -> error.type
        }
    }
}
