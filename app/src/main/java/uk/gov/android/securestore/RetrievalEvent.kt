package uk.gov.android.securestore

import uk.gov.android.securestore.error.SecureStoreErrorType

/**
 * Class to handle the return events when getting data from a [SecureStore]
 */
@Deprecated(
    "This will not be used starting SecureStoreAsyncV2 as it will return a" +
            " Map<String, String?> - aim to be removed by 20th of April 2026",
    replaceWith = ReplaceWith("java/uk/gov/android/securestore/RetrievalEventV2.kt"),
    level = DeprecationLevel.WARNING,
)
sealed class RetrievalEvent {
    /**
     * Successful event, holds the retrieved data value as a [String]
     */
    data class Success(
        val value: Map<String, String>,
    ) : RetrievalEvent()

    /**
     * Failure event, holds the type of failure as [SecureStoreErrorType] and an optional reason
     */
    data class Failed(
        val type: SecureStoreErrorType,
        val reason: String? = null,
    ) : RetrievalEvent() {
        override fun toString(): String {
            return "Secure store retrieval failed: " +
                "\ntype - $type" +
                "\nreason - $reason"
        }
    }
}
