package uk.gov.android.securestore.error

class SecureStorageErrorV2(
    exception: Exception,
    val type: SecureStoreErrorTypeV2 = SecureStoreErrorTypeV2.RECOVERABLE,
) : Error(exception)

enum class SecureStoreErrorTypeV2 {
    RECOVERABLE,
    UNRECOVERABLE,
    USER_CANCELLED,
    ERROR_NO_DEVICE_CREDENTIAL,
}
