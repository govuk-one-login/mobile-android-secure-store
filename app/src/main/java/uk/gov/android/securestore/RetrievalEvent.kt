package uk.gov.android.securestore

import uk.gov.android.securestore.error.SecureStoreErrorType


@Deprecated(
    "Replace with RetrievalEventV2 to allow handling errors correctly - aim to be removed by 20th of April 2026",
    replaceWith = ReplaceWith("java/uk/gov/android/securestore/RetrievalEventV2.kt"),
    level = DeprecationLevel.WARNING
)/**
 * Class to handle the return events when getting data from a [SecureStore]
 */
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
