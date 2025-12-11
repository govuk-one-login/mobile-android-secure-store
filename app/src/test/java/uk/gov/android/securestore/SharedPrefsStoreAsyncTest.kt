package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
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
import uk.gov.android.securestore.error.SecureStorageError
import uk.gov.android.securestore.error.SecureStoreErrorType
import java.security.GeneralSecurityException
import java.security.KeyStoreException
import java.util.stream.Stream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Suppress("UNCHECKED_CAST", "LargeClass")
class SharedPrefsStoreAsyncTest {
    private val mockContext: FragmentActivity = mock()
    private val mockSharedPreferences: SharedPreferences = mock()
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

    private val sharedPrefsStoreAsync: SecureStoreAsync = SharedPrefsStoreAsync(
        mockAuthenticator,
        mockHybridCryptoManagerAsync,
    )

    @BeforeEach
    fun setUp() {
        whenever(mockContext.getSharedPreferences(eq(storeId), eq(Context.MODE_PRIVATE)))
            .thenReturn(mockSharedPreferences)
        whenever(mockSharedPreferences.edit()).thenReturn(mockEditor)
    }

    @Test
    fun testUpsert() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
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
    fun testDelete() {
        initSecureStore(AccessControlLevel.OPEN)
        sharedPrefsStoreAsync.delete(alias)

        verify(mockEditor).remove(alias)
        verify(mockEditor).apply()
    }

    @Test
    fun testRetrieve() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenReturn(value)
        val result = sharedPrefsStoreAsync.retrieve(alias)
        assertEquals(RetrievalEvent.Success(mapOf(alias to value)), result)
    }

    @Test
    fun testRetrieveThrowsSSException() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenThrow(SecureStorageError(Exception("Error"), SecureStoreErrorType.NOT_FOUND))
        val result = sharedPrefsStoreAsync.retrieve(alias)
        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.NOT_FOUND,
                "java.lang.Exception: Error",
            ),
            result,
        )
    }

    @Test
    fun testRetrieveThrowsGeneral() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenThrow(RuntimeException("Error"))
        val result = sharedPrefsStoreAsync.retrieve(alias)
        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.GENERAL,
                "java.lang.RuntimeException: Error",
            ),
            result,
        )
    }

    @Test
    fun testRetrieveMultiple() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
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
        assertEquals(RetrievalEvent.Success(mapOf(alias to value, alias2 to value2)), result)
    }

    @Test
    fun testRetrieveWithAuthentication() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)
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

        assertEquals(RetrievalEvent.Success(mapOf(alias to value)), result)
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun testRetrieveWithAuthenticationMultiple() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)
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

        assertEquals(RetrievalEvent.Success(mapOf(alias to value, alias2 to value2)), result)
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun testRetrieveWithAuthenticationNull() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)
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

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.NOT_FOUND,
                "authenticate call onSuccess callback throws SecureStorageError " +
                    "java.lang.Exception: test not found",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun testRetrieveWithAuthenticationThrowsSecureStorageError() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(SecureStorageError(Exception("test exception")))

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.GENERAL,
                "authenticate call throws SecureStorageError " +
                    "java.lang.Exception: test exception",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun testRetrieveWithAuthenticationAuthErrorsGeneral() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler)
                .onError(0, "error")
        }

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.GENERAL,
                "biometric error code 0 error",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun testRetrieveWithAuthenticationThrowsException() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(RuntimeException("Error"))

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.GENERAL,
                "authenticate call throws Exception Error",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun testRetrieveWithAuthenticationFaceScanNotRecognised() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

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
                .onError(BiometricPrompt.ERROR_UNABLE_TO_PROCESS, "face scan not recognised")
        }

        sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

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

        assertEquals(RetrievalEvent.Success(mapOf(alias to value)), result)
        verify(mockAuthenticator, times(2)).init(activityFragment)
        verify(mockAuthenticator, times(2)).close()
    }

    @Test
    fun testRetrieveWithAuthenticationFaceScanTimeOut() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

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
                .onError(BiometricPrompt.ERROR_TIMEOUT, "face scan timeout")
        }

        sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

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

        assertEquals(RetrievalEvent.Success(mapOf(alias to value)), result)
        verify(mockAuthenticator, times(2)).init(activityFragment)
        verify(mockAuthenticator, times(2)).close()
    }

    @Test
    fun testRetrieveNonExistentKey() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(eq(alias), any())).thenReturn(null)
        val result = sharedPrefsStoreAsync.retrieve(alias)

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.NOT_FOUND,
                "java.lang.Exception: test not found",
            ),
            result,
        )
    }

    @Test
    fun testExists() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.contains(alias)).thenReturn(true)

        val result = sharedPrefsStoreAsync.exists(alias)

        assertTrue(result)
    }

    @Test
    fun testDoesNotExist() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.contains(alias)).thenReturn(false)

        val result = sharedPrefsStoreAsync.exists(alias)

        assertFalse(result)
    }

    @Test
    fun testUpsertThrowsError() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        given(
            mockHybridCryptoManagerAsync.encrypt(
                value,
            ),
        ).willAnswer { throw GeneralSecurityException() }

        assertFailsWith<SecureStorageError> {
            sharedPrefsStoreAsync.upsert(alias, value)
        }
    }

    @Test
    fun testRetrieveReturnsErrorFromCryptoThrows() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        given(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        )
            .willAnswer {
                throw GeneralSecurityException()
            }

        val result = sharedPrefsStoreAsync.retrieve(alias)

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.NOT_FOUND,
                "java.lang.Exception: test not found",
            ),
            result,
        )
    }

    @Test
    fun testRetrieveThrowsErrorFromWrongACL() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        val result = sharedPrefsStoreAsync.retrieve(alias)

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.GENERAL,
                "Access control level must be OPEN to use this retrieve method",
            ),
            result,
        )
    }

    @Test
    fun testRetrieveWithAuthenticationThrowsErrorFromWrongACL() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        val authConfig = AuthenticatorPromptConfiguration(
            "title",
        )
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.GENERAL,
                "Use retrieve method, access control is set to OPEN, no need for auth",
            ),
            result,
        )
    }

    @Test
    fun testDeleteAllThrowsError() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        given(
            mockHybridCryptoManagerAsync.deleteKey(),
        ).willAnswer { throw KeyStoreException() }
        assertFailsWith<SecureStorageError> {
            sharedPrefsStoreAsync.deleteAll()
        }
    }

    @Test
    fun testUpsertThrowsIfNotInit() = runTest {
        assertFailsWith<SecureStorageError> {
            sharedPrefsStoreAsync.upsert(alias, value)
        }
    }

    @Test
    fun testRetrieveWithAuthThrowsIfNotInit() = runTest {
        val result = sharedPrefsStoreAsync
            .retrieveWithAuthentication(
                alias,
                authPromptConfig = authConfig,
                context = activityFragment,
            )

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.GENERAL,
                "Must call init on SecureStore first!",
            ),
            result,
        )
    }

    @Test
    fun testRetrieveThrowsIfNotInit() = runTest {
        val result = sharedPrefsStoreAsync.retrieve(alias)

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.GENERAL,
                "Must call init on SecureStore first!",
            ),
            result,
        )
    }

    @Test
    fun testMethodsWithNullSharedPrefs() = runTest {
        sharedPrefsStoreAsync.deleteAll()
        sharedPrefsStoreAsync.delete(encryptedKey)

        assertFalse(sharedPrefsStoreAsync.exists(encryptedKey))
    }

    @Test
    fun testRetrievalEventFailedString() {
        val expectedText = "Secure store retrieval failed: " +
            "\ntype - ${SecureStoreErrorType.GENERAL}" +
            "\nreason - reason"
        val actualText = RetrievalEvent.Failed(
            type = SecureStoreErrorType.GENERAL,
            reason = "reason",
        ).toString()
        assertEquals(expectedText, actualText)
    }

    @ParameterizedTest
    @MethodSource("errorTypes")
    fun testRetrieveWithAuthenticationAuthErrorsNonGeneric(
        errorType: Int,
        codeString: String,
    ) = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler)
                .onError(errorType, "error")
        }

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEvent.Failed(
                SecureStoreErrorType.USER_CANCELED_BIO_PROMPT,
                "biometric error code $codeString error",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    private fun initSecureStore(acl: AccessControlLevel) {
        val config = SecureStorageConfigurationAsync(
            storeId,
            acl,
        )

        sharedPrefsStoreAsync.init(
            mockContext,
            config,
        )
    }

    companion object {
        @JvmStatic
        fun errorTypes(): Stream<Arguments> =
            Stream.of(
                Arguments.of(BiometricPrompt.ERROR_USER_CANCELED, "10"),
                Arguments.of(BiometricPrompt.ERROR_NEGATIVE_BUTTON, "13"),
                Arguments.of(BiometricPrompt.ERROR_TIMEOUT, "3"),
                Arguments.of(BiometricPrompt.ERROR_UNABLE_TO_PROCESS, "2"),
                Arguments.of(BiometricPrompt.ERROR_NO_BIOMETRICS, "11"),
                Arguments.of(BiometricPrompt.ERROR_HW_UNAVAILABLE, "1"),
                Arguments.of(BiometricPrompt.ERROR_CANCELED, "5"),
                Arguments.of(BiometricPrompt.ERROR_LOCKOUT, "7"),
                Arguments.of(BiometricPrompt.ERROR_LOCKOUT_PERMANENT, "9"),
            )
    }
}
