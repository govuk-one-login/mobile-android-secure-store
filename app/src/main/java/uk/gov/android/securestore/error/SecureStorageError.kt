package uk.gov.android.securestore.error

@Deprecated(
    "Replace with SecureStorageErrorV2 to allow handling errors correctly - aim to be removed by 20th of April 2026",
    replaceWith = ReplaceWith("java/uk/gov/android/securestore/error/SecureStorageErrorV2.kt"),
    level = DeprecationLevel.WARNING
)
class SecureStorageError(
    exception: Exception,
    val type: SecureStoreErrorType = SecureStoreErrorType.GENERAL,
) : Error(exception)

@Deprecated(
    "Replace with SecureStoreErrorTypeV2 to allow handling errors correctly - aim to be removed by 20th of April 2026",
    replaceWith = ReplaceWith("java/uk/gov/android/securestore/error/SecureStorageErrorV2.kt"),
    level = DeprecationLevel.WARNING
)
enum class SecureStoreErrorType {
    GENERAL,
    NOT_FOUND,
    USER_CANCELED_BIO_PROMPT,
    FAILED_BIO_PROMPT,
}
