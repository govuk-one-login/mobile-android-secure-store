package uk.gov.android.securestore

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

data class SecureStorageConfigurationAsync(
    val id: String,
    val accessControlLevel: AccessControlLevel,
    val dispatcher: CoroutineDispatcher = Dispatchers.IO,
)
