package uk.gov.android.securestore.error

import kotlinx.coroutines.CancellationException
import org.junit.jupiter.api.Test
import uk.gov.android.securestore.error.SecureStorageErrorV2.Companion.getOrThrowSecureStorageError
import uk.gov.android.securestore.error.SecureStorageErrorV2.Companion.mapToSecureStorageError
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SecureStorageErrorV2Test {

    @Test
    fun `getOrThrowSecureStorageError returns value on success`() {
        val result = Result.success("hello")

        val actual = result.getOrThrowSecureStorageError()

        assertEquals("hello", actual)
    }

    @Test
    fun `getOrThrowSecureStorageError re-throws CancellationException`() {
        val cancellationException = CancellationException("cancelled")
        val result = Result.failure<String>(cancellationException)

        val thrown = assertFailsWith<CancellationException> {
            result.getOrThrowSecureStorageError()
        }

        assertEquals(cancellationException, thrown)
    }

    @Test
    fun `getOrThrowSecureStorageError throws SecureStorageErrorV2 for other exceptions`() {
        val exception = RuntimeException("something went wrong")
        val result = Result.failure<String>(exception)

        val thrown = assertFailsWith<SecureStorageErrorV2> {
            result.getOrThrowSecureStorageError()
        }

        assertEquals(exception, thrown.exception)
    }

    @Test
    fun `mapToSecureStorageError fails when given CancellationException`() {
        val cancellationException = CancellationException("cancelled")

        assertFailsWith<IllegalArgumentException> {
            cancellationException.mapToSecureStorageError()
        }
    }
}
