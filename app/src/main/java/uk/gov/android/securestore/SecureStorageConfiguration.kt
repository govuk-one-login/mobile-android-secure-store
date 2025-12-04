package uk.gov.android.securestore

@Deprecated(
    message = "This has been replaced by a Secure Storage Configuration with a dispatcher.",
    replaceWith = ReplaceWith("uk.gov.android.securestore.SecureStorageConfigurationAsync"),
    level = DeprecationLevel.WARNING,
)
data class SecureStorageConfiguration(
    val id: String,
    val accessControlLevel: AccessControlLevel,
)
