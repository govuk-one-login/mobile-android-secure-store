package uk.gov.android.securestore

data class SecureStorageConfiguration(
    val id: String,
    val accessControlLevel: AccessControlLevel = AccessControlLevel.OPEN
)
