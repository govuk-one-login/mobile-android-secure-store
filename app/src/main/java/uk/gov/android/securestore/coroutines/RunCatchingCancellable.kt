package uk.gov.android.securestore.coroutines

import kotlinx.coroutines.CancellationException

/**
 * Like [runCatching] but re-throws [CancellationException] to preserve structured concurrency.
 */
inline fun <T, R> T.runCatchingCancellable(block: T.() -> R): Result<R> = runCatching {
    block()
}.onFailure { e ->
    if (e is CancellationException) throw e
}
