package uk.gov.android.securestore.error

class SecureStorageError(
    exception: Exception,
    val type: SecureStoreErrorType = SecureStoreErrorType.GENERAL
) : Error(exception)

enum class SecureStoreErrorType {
    GENERAL,
    NOT_FOUND,
    USER_CANCELED_BIO_PROMPT,
    FAILED_BIO_PROMPT
}
