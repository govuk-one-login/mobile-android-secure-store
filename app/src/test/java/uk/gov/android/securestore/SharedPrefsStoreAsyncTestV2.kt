package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestCoroutineScheduler
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.given
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.crypto.EncryptedData
import uk.gov.android.securestore.crypto.HybridCryptoManagerAsync
import uk.gov.android.securestore.error.SecureStorageErrorV2
import uk.gov.android.securestore.error.SecureStoreErrorTypeV2
import java.lang.IllegalStateException
import java.lang.NullPointerException
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableEntryException
import java.security.UnrecoverableKeyException
import java.util.stream.Stream
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.NoSuchPaddingException
import kotlin.IndexOutOfBoundsException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Suppress("UNCHECKED_CAST", "LargeClass")
class SharedPrefsStoreAsyncTestV2 {
    private val mockContext: FragmentActivity = mock()
    private lateinit var mockSharedPreferences: SharedPreferences
    private val mockEditor: SharedPreferences.Editor = mock()
    private val mockHybridCryptoManagerAsync: HybridCryptoManagerAsync = mock()
    private val mockAuthenticator: Authenticator = mock()
    private val activityFragment: FragmentActivity = mock()

    private val storeId = "id"
    private val alias = "test"
    private val value = "testValue"
    private val encryptedKey = "encryptedAESKey"
    private val encryptedValue = "testEncrypted"
    private val alias2 = "test"
    private val value2 = "testValue"
    private val encryptedKey2 = "encryptedAESKey"
    private val encryptedValue2 = "testEncrypted"
    private val encryptedData = EncryptedData(encryptedValue, encryptedKey)
    private val authConfig = AuthenticatorPromptConfiguration(
        "title",
    )

    private lateinit var sharedPrefsStoreAsync: SecureStoreAsyncV2

    @OptIn(ExperimentalCoroutinesApi::class)
    @BeforeEach
    fun setUp() {
        mockSharedPreferences = mock()
        sharedPrefsStoreAsync = SharedPrefsStoreAsyncV2(
            mockAuthenticator,
            mockHybridCryptoManagerAsync,
        )
        whenever(mockContext.getSharedPreferences(eq(storeId), eq(Context.MODE_PRIVATE)))
            .thenReturn(mockSharedPreferences)
        whenever(mockSharedPreferences.edit()).thenReturn(mockEditor)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `test upsert`() = runTest {
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        whenever(
            mockHybridCryptoManagerAsync.encrypt(eq(value)),
        ).thenReturn(encryptedData)

        sharedPrefsStoreAsync.upsert(alias, value)

        verify(mockHybridCryptoManagerAsync).encrypt(eq(value))
        verify(mockEditor).putString(alias, encryptedValue)
        verify(mockEditor).putString(alias + "Key", encryptedKey)
        verify(mockEditor, times(2)).apply()
    }

    @Test
    fun `test delete`() = runTest {
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        sharedPrefsStoreAsync.delete(alias)

        verify(mockEditor).remove(alias)
        verify(mockEditor).apply()
    }

    @Test
    fun `test retrieve`() = runTest {
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenReturn(value)
        val result = sharedPrefsStoreAsync.retrieve(alias)
        assertEquals(mapOf(alias to value), result)
    }

    @Test
    fun `test retrieve throws general secure store error exception`() = runTest {
        val expectedExp = Exception("Error")
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenAnswer { throw expectedExp }

        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.retrieve(alias)
        }

        assertTrue(
            actual.exception.message!!.contains(expectedExp.message!!),
        )
        assertEquals(
            SecureStoreErrorTypeV2.RECOVERABLE,
            actual.type,
        )
    }

    @Test
    fun `test retrieve throws runtime exception`() = runTest {
        val expectedExp = RuntimeException("Error")
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenThrow(expectedExp)

        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.retrieve(alias)
        }
        assertTrue(
            actual.exception.message!!.contains(expectedExp.message!!),
        )
        assertEquals(
            SecureStoreErrorTypeV2.RECOVERABLE,
            actual.type,
        )
    }

    @Test
    fun `test retrieve multiple values`() = runTest {
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)
        whenever(mockSharedPreferences.getString(alias2, null)).thenReturn(encryptedValue2)
        whenever(mockSharedPreferences.getString(alias2 + "Key", null)).thenReturn(encryptedKey2)

        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenReturn(value)

        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue2),
                eq(encryptedKey2),
            ),
        ).thenReturn(value2)

        val result = sharedPrefsStoreAsync.retrieve(alias, alias2)
        assertEquals(mapOf(alias to value, alias2 to value2), result)
    }

    @Test
    fun `test retrieve with authentication`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS, testScheduler)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
        }
        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenReturn(value)

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(mapOf(alias to value), result)
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve multiple values with authentication`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS, testScheduler)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)
        whenever(mockSharedPreferences.getString(alias2, null)).thenReturn(encryptedValue2)
        whenever(mockSharedPreferences.getString(alias2 + "Key", null)).thenReturn(encryptedKey2)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
        }
        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenReturn(value)
        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue2),
                eq(encryptedKey2),
            ),
        ).thenReturn(value2)

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(mapOf(alias to value, alias2 to value2), result)
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with authentication returns null value`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS, testScheduler)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(null)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
        }

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(mapOf(alias to null), result)
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `retrieve non-existent key-value pair`() = runTest {
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        whenever(mockSharedPreferences.getString(eq(alias), any())).thenReturn(null)
        val result = sharedPrefsStoreAsync.retrieve(alias)

        assertEquals(
            mapOf(alias to null),
            result,
        )
    }

    @Test
    fun `test exists when the value is saved`() = runTest {
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        whenever(mockSharedPreferences.contains(alias)).thenReturn(true)

        val result = sharedPrefsStoreAsync.exists(alias)

        assertTrue(result)
    }

    @Test
    fun `test exists when the value is not saved`() = runTest {
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        whenever(mockSharedPreferences.contains(alias)).thenReturn(false)

        val result = sharedPrefsStoreAsync.exists(alias)

        assertFalse(result)
    }

    @Test
    fun `test retrieve throws error from wrong ACL`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS, testScheduler)

        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.retrieve(alias)
        }

        assertTrue(
            actual.exception.message!!.contains(SharedPrefsStoreAsyncV2.REQUIRE_OPEN_ACCESS_LEVEL),
        )
        assertEquals(
            SecureStoreErrorTypeV2.RECOVERABLE,
            actual.type,
        )
    }

    @Test
    fun `test retrieve with auth throws error from wrong ACL`() = runTest {
        initSecureStore(AccessControlLevel.OPEN, testScheduler)

        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.retrieveWithAuthentication(
                alias,
                authPromptConfig = authConfig,
                context = activityFragment,
            )
        }

        assertTrue(
            actual.exception.message!!.contains(SharedPrefsStoreAsyncV2.AUTH_ON_OPEN_STORE_ERROR_MSG),
        )
        assertEquals(SecureStoreErrorTypeV2.RECOVERABLE, actual.type)
    }

    @Test
    fun `test delete all throws error`() = runTest {
        val expectedExp = KeyStoreException("error")
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        given(
            mockHybridCryptoManagerAsync.deleteKey(),
        ).willAnswer { throw expectedExp }

        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.deleteAll()
        }

        assertTrue(
            actual.exception.message!!.contains(expectedExp.message!!),
        )
        assertEquals(
            SecureStoreErrorTypeV2.UNRECOVERABLE,
            actual.type,
        )
    }

    @Test
    fun `test upsert throws error when missing initialisation`() = runTest {
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.upsert(alias, value)
        }

        assertTrue(
            actual.exception is NullPointerException,
        )
        assertEquals(
            SecureStoreErrorTypeV2.RECOVERABLE,
            actual.type,
        )
    }

    @Test
    fun `test retrieve with auth throws error when missing initialisation`() = runTest {
        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.retrieveWithAuthentication(
                alias,
                authPromptConfig = authConfig,
                context = activityFragment,
            )
        }

        assertTrue(
            actual.exception.message!!.contains(SharedPrefsStoreAsyncV2.INIT_ERROR.message!!),
        )
        assertEquals(
            SecureStoreErrorTypeV2.RECOVERABLE,
            actual.type,
        )
    }

    @Test
    fun `test retrieve throws error when missing initialisation`() = runTest {
        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.retrieve(alias)
        }

        assertTrue(
            actual.exception.message!!.contains(SharedPrefsStoreAsyncV2.INIT_ERROR.message!!),
        )
        assertEquals(
            SecureStoreErrorTypeV2.RECOVERABLE,
            actual.type,
        )
    }

    @Test
    fun `tests methods when shared prefs is null or no data stored`() = runTest {
        sharedPrefsStoreAsync.deleteAll()
        sharedPrefsStoreAsync.delete(encryptedKey)

        assertFalse(sharedPrefsStoreAsync.exists(encryptedKey))
    }

    @ParameterizedTest
    @MethodSource("getErrorArgs")
    fun `test upsert throws secure store error`(
        exception: Exception,
        type: SecureStoreErrorTypeV2,
    ) = runTest {
        initSecureStore(AccessControlLevel.OPEN, testScheduler)
        given(
            mockHybridCryptoManagerAsync.encrypt(
                value,
            ),
        ).willAnswer { throw exception }

        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.upsert(alias, value)
        }

        assertTrue(
            actual.exception.message!!.contains(exception.message!!),
        )
        assertEquals(
            type,
            actual.type,
        )
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @ParameterizedTest
    @MethodSource("getErrorArgs")
    fun `test retrieve with auth throws exp and mapping to secure store error`(
        exception: Exception,
        type: SecureStoreErrorTypeV2,
    ) = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS, testScheduler)

        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
        }

        whenever(mockHybridCryptoManagerAsync.decrypt(encryptedValue, encryptedKey))
            .thenThrow(exception)

        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.retrieveWithAuthentication(
                alias,
                authPromptConfig = authConfig,
                context = activityFragment,
            )
            advanceUntilIdle()
        }

        assertEquals(
            exception,
            actual.exception,
        )
        assertEquals(
            type,
            actual.type,
        )

        verify(mockAuthenticator).init(activityFragment)
        verify(mockHybridCryptoManagerAsync).decrypt(any(), any())
        verify(mockAuthenticator).close()
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @ParameterizedTest
    @MethodSource("getBiometricErrorArgs")
    fun `test biometric prompt failure`(
        errCode: Int,
        errString: String,
        errType: SecureStoreErrorTypeV2,
    ) = runTest {
        val expected = SecureStorageErrorV2(
            Exception(
                "${SecureStorageErrorV2.BIOMETRIC_PREFIX} $errCode $errString",
            ),
            errType,
        )
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS, testScheduler)

        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler)
                .onError(errCode, errString)
        }

        val actual = assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.retrieveWithAuthentication(
                alias,
                authPromptConfig = authConfig,
                context = activityFragment,
            )
            advanceUntilIdle()
        }

        assertTrue(
            actual.exception.message!!.contains(expected.exception.message!!),
        )
        assertEquals(
            expected.type,
            actual.type,
        )

        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun initSecureStore(acl: AccessControlLevel, testScheduler: TestCoroutineScheduler) {
        val dispatcher = UnconfinedTestDispatcher(testScheduler)
        Dispatchers.setMain(dispatcher)

        val config = SecureStorageConfigurationAsync(
            storeId,
            acl,
            dispatcher,
        )

        sharedPrefsStoreAsync.init(
            mockContext,
            config,
        )
    }

    companion object {
        private const val NO_PASSCODE = "No device passcode"
        private const val USER_CANCELLED = "User cancelled"
        private const val FACE_NOT_RECOGNISED = "Face scan not recognised"
        private const val FACE_SCAN_TIMEOUT = "Face scan timeout"
        private const val GENERIC_ERROR = "Hardware unavailable"

        @JvmStatic
        fun getBiometricErrorArgs(): Stream<Arguments> =
            Stream.of(
                Arguments.of(
                    BiometricPrompt.ERROR_NO_BIOMETRICS,
                    NO_PASSCODE,
                    SecureStoreErrorTypeV2.ERROR_NO_DEVICE_CREDENTIAL,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
                    NO_PASSCODE,
                    SecureStoreErrorTypeV2.ERROR_NO_DEVICE_CREDENTIAL,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_USER_CANCELED,
                    USER_CANCELLED,
                    SecureStoreErrorTypeV2.USER_CANCELLED,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
                    FACE_NOT_RECOGNISED,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_TIMEOUT,
                    FACE_SCAN_TIMEOUT,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_HW_UNAVAILABLE,
                    GENERIC_ERROR,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
                    GENERIC_ERROR,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_NO_SPACE,
                    GENERIC_ERROR,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_LOCKOUT,
                    GENERIC_ERROR,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                    GENERIC_ERROR,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_VENDOR,
                    GENERIC_ERROR,
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
            )

        @JvmStatic
        fun getErrorArgs(): Stream<Arguments> =
            Stream.of(
                Arguments.of(
                    AEADBadTagException("AEADBadTagException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    UnrecoverableKeyException("UnrecoverableKeyException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    BadPaddingException("BadPaddingException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    NoSuchAlgorithmException("NoSuchAlgorithmException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    NoSuchPaddingException("NoSuchPaddingException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    UnsupportedOperationException("UnsupportedOperationException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    InvalidKeyException("InvalidKeyException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    UnrecoverableEntryException("UnrecoverableEntryException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    KeyStoreException("KeyStoreException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    IllegalStateException("IllegalStateException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    InvalidAlgorithmParameterException("InvalidAlgorithmParameterException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    IndexOutOfBoundsException("IndexOutOfBoundsException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    GeneralSecurityException("GeneralSecurityException"),
                    SecureStoreErrorTypeV2.UNRECOVERABLE,
                ),
                Arguments.of(
                    Exception("Random exception"),
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
            )
    }
}
