package uk.gov.android.securestore.coroutines

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import org.junit.jupiter.api.Test

class RunCatchingCancellableTest {

    @Test
    fun `CancellationException propagates directly`() {
        val cancellationException = CancellationException("coroutine cancelled")

        assertFailsWith<CancellationException> {
            runCatchingCancellable { throw cancellationException }
        }
    }

    @Test
    fun `regular exception returns failure Result`() {
        val exception = RuntimeException("something went wrong")

        val result = runCatchingCancellable { throw exception }

        assertTrue(result.isFailure)
        assertEquals(exception, result.exceptionOrNull())
    }

    @Test
    fun `successful block returns success Result`() {
        val expected = "hello"

        val result = runCatchingCancellable { expected }

        assertTrue(result.isSuccess)
        assertEquals(expected, result.getOrNull())
    }
}
