package uk.gov.android.securestore

import uk.gov.android.securestore.error.SecureStoreErrorType
import uk.gov.android.securestore.error.SecureStoreErrorTypeV2

/**
 * Class to handle the return events when getting data from a [SecureStore]
 */
sealed class RetrievalEventV2 {
    /**
     * Successful event, holds the retrieved data value as a [String]
     */
    data class Success(
        val value: Map<String, String?>,
    ) : RetrievalEventV2()

    /**
     * Failure event, holds the type of failure as [SecureStoreErrorType] and an optional reason
     */
    data class Failed(
        val type: SecureStoreErrorTypeV2,
        val reason: String? = null,
    ) : RetrievalEventV2() {
        override fun toString(): String {
            return "Secure store retrieval failed: " +
                "\ntype - $type" +
                "\nreason - $reason"
        }
    }
}
