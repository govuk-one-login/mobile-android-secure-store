package uk.gov.android.securestore

import uk.gov.android.securestore.error.SecureStoreErrorType

/**
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
    ) : RetrievalEvent()
}
