package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import androidx.fragment.app.FragmentActivity
import kotlin.test.assertFailsWith
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.isNull
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.crypto.HybridCryptoManagerAsync

@OptIn(ExperimentalCoroutinesApi::class)
class SharedPrefsStoreAsyncCancellationTestV2 {
    private val mockContext: FragmentActivity = mock()
    private val mockSharedPreferences: SharedPreferences = mock()
    private val mockEditor: SharedPreferences.Editor = mock()
    private val mockHybridCryptoManagerAsync: HybridCryptoManagerAsync = mock()
    private val mockAuthenticator: Authenticator = mock()

    private lateinit var sharedPrefsStoreAsync: SecureStoreAsyncV2

    @BeforeEach
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        givenSharedPreferencesIsAvailable()
        givenEncryptedDataIsStored()
        givenAuthenticationSucceeds()

        sharedPrefsStoreAsync = SharedPrefsStoreAsyncV2(
            mockAuthenticator,
            mockHybridCryptoManagerAsync
        )

        givenSecureStoreIsInitialised()
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `upsert propagates CancellationException`() = runTest {
        givenCryptoManagerThrowsCancellationException()

        assertFailsWith<CancellationException> {
            sharedPrefsStoreAsync.upsert("key", "value")
        }
    }

    @Test
    fun `retrieve propagates CancellationException`() = runTest {
        givenCryptoManagerThrowsCancellationException()

        assertFailsWith<CancellationException> {
            sharedPrefsStoreAsync.retrieve("key")
        }
    }

    @Test
    fun `retrieveWithAuthentication propagates CancellationException`() = runTest {
        givenSecureStoreIsInitialised(AccessControlLevel.PASSCODE_AND_BIOMETRICS)
        givenCryptoManagerThrowsCancellationException()

        assertFailsWith<CancellationException> {
            sharedPrefsStoreAsync.retrieveWithAuthentication(
                "key",
                authPromptConfig = AuthenticatorPromptConfiguration("title"),
                context = mock()
            )
        }
    }

    @Test
    fun `deleteAll propagates CancellationException`() = runTest {
        givenCryptoManagerThrowsCancellationException()

        assertFailsWith<CancellationException> {
            sharedPrefsStoreAsync.deleteAll()
        }
    }

    private fun givenSharedPreferencesIsAvailable() {
        whenever(mockContext.getSharedPreferences(any<String>(), eq(Context.MODE_PRIVATE)))
            .thenReturn(mockSharedPreferences)
        whenever(mockSharedPreferences.edit()).thenReturn(mockEditor)
    }

    private fun givenSecureStoreIsInitialised(acl: AccessControlLevel = AccessControlLevel.OPEN) {
        sharedPrefsStoreAsync.init(
            mockContext,
            SecureStorageConfigurationAsync(
                "id",
                acl,
                UnconfinedTestDispatcher()
            )
        )
    }

    private fun givenEncryptedDataIsStored() {
        whenever(mockSharedPreferences.getString(eq("key"), isNull())).thenReturn("encryptedData")
        whenever(mockSharedPreferences.getString(eq("keyKey"), isNull())).thenReturn("encryptedKey")
    }

    private fun givenAuthenticationSucceeds() {
        whenever(mockAuthenticator.authenticate(any(), any(), any())).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
        }
    }

    @Suppress("ThrowsCount")
    private suspend fun givenCryptoManagerThrowsCancellationException() {
        whenever(mockHybridCryptoManagerAsync.encrypt(any()))
            .thenAnswer { throw CancellationException("cancelled") }
        whenever(mockHybridCryptoManagerAsync.decrypt(any(), any()))
            .thenAnswer { throw CancellationException("cancelled") }
        whenever(mockHybridCryptoManagerAsync.deleteKey())
            .thenAnswer { throw CancellationException("cancelled") }
    }
}
