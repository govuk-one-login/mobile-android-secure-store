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
import uk.gov.android.securestore.error.SecureStorageErrorV2
import uk.gov.android.securestore.error.SecureStoreErrorTypeV2
import java.lang.IllegalStateException
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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Suppress("UNCHECKED_CAST", "LargeClass")
class SharedPrefsStoreAsyncTestV2 {
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

    private val sharedPrefsStoreAsync: SecureStoreAsyncV2 = SharedPrefsStoreAsyncV2(
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
    fun `test upsert`() = runTest {
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
    fun `test delete`() {
        initSecureStore(AccessControlLevel.OPEN)
        sharedPrefsStoreAsync.delete(alias)

        verify(mockEditor).remove(alias)
        verify(mockEditor).apply()
    }

    @Test
    fun `test retrieve`() = runTest {
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
        assertEquals(RetrievalEventV2.Success(mapOf(alias to value)), result)
    }

    @Test
    fun `test retrieve throws general secure store error exception`() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        whenever(
            mockHybridCryptoManagerAsync.decrypt(
                eq(encryptedValue),
                eq(encryptedKey),
            ),
        ).thenThrow(SecureStorageErrorV2(Exception("Error"), SecureStoreErrorTypeV2.RECOVERABLE))
        val result = sharedPrefsStoreAsync.retrieve(alias)
        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.RECOVERABLE,
                "java.lang.Exception: Error",
            ),
            result,
        )
    }

    @Test
    fun `test retrieve throws runtime exception`() = runTest {
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
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.RECOVERABLE,
                "java.lang.RuntimeException: Error",
            ),
            result,
        )
    }

    @Test
    fun `test retrieve multiple values`() = runTest {
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
        assertEquals(RetrievalEventV2.Success(mapOf(alias to value, alias2 to value2)), result)
    }

    @Test
    fun `test retrieve with authentication`() = runTest {
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

        assertEquals(RetrievalEventV2.Success(mapOf(alias to value)), result)
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve multiple values with authentication`() = runTest {
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

        assertEquals(RetrievalEventV2.Success(mapOf(alias to value, alias2 to value2)), result)
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with authentication returns null value`() = runTest {
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

        assertEquals(RetrievalEventV2.Success(mapOf(alias to null)), result)
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws AEADBadTagException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                AEADBadTagException("AEADBadTagException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "javax.crypto.AEADBadTagException: AEADBadTagException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws UnrecoverableKeyException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                UnrecoverableKeyException("UnrecoverableKeyException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.security.UnrecoverableKeyException: UnrecoverableKeyException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws BadPaddingException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                BadPaddingException("BadPaddingException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "javax.crypto.BadPaddingException: BadPaddingException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws NoSuchAlgorithmException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                NoSuchAlgorithmException("NoSuchAlgorithmException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.security.NoSuchAlgorithmException: NoSuchAlgorithmException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws NoSuchPaddingException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                NoSuchPaddingException("NoSuchPaddingException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "javax.crypto.NoSuchPaddingException: NoSuchPaddingException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws UnsupportedOperationException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                UnsupportedOperationException("UnsupportedOperationException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.lang.UnsupportedOperationException: UnsupportedOperationException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws InvalidKeyException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                InvalidKeyException("InvalidKeyException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.security.InvalidKeyException: InvalidKeyException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws UnrecoverableEntryException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                UnrecoverableEntryException("UnrecoverableEntryException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.security.UnrecoverableEntryException: UnrecoverableEntryException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws KeyStoreException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                KeyStoreException("KeyStoreException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.security.KeyStoreException: KeyStoreException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws IllegalStateException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                IllegalStateException("IllegalStateException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.lang.IllegalStateException: IllegalStateException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws InvalidAlgorithmParameterException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                InvalidAlgorithmParameterException("InvalidAlgorithmParameterException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.security.InvalidAlgorithmParameterException: InvalidAlgorithmParameterException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws IndexOutOfBoundsException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                IndexOutOfBoundsException("IndexOutOfBoundsException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.lang.IndexOutOfBoundsException: IndexOutOfBoundsException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `test retrieve with auth throws GeneralSecurityException`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenThrow(
            SecureStorageErrorV2(
                GeneralSecurityException("GeneralSecurityException"),
            ),
        )

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.UNRECOVERABLE,
                "authenticate call throws SecureStorageError " +
                    "java.security.GeneralSecurityException: GeneralSecurityException",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `retrieve with auth no local auth error`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        whenever(
            mockAuthenticator.authenticate(
                eq(AccessControlLevel.PASSCODE_AND_BIOMETRICS),
                eq(authConfig),
                any(),
            ),
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler)
                .onError(BiometricPrompt.ERROR_NO_BIOMETRICS, "No device passcode")
        }

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.ERROR_NO_DEVICE_CREDENTIAL,
                "biometric error code 11 No device passcode",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `retrieve with auth bimetric prompt cancelled`() = runTest {
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
                .onError(BiometricPrompt.ERROR_USER_CANCELED, "User cancelled")
        }

        val result = sharedPrefsStoreAsync.retrieveWithAuthentication(
            alias,
            authPromptConfig = authConfig,
            context = activityFragment,
        )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.USER_CANCELLED,
                "biometric error code 10 User cancelled",
            ),
            result,
        )
        verify(mockAuthenticator).init(activityFragment)
        verify(mockAuthenticator).close()
    }

    @Test
    fun `retrieve with auth biometrics not recognised`() = runTest {
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

        assertEquals(RetrievalEventV2.Success(mapOf(alias to value)), result)
        verify(mockAuthenticator, times(2)).init(activityFragment)
        verify(mockAuthenticator, times(2)).close()
    }

    @Test
    fun `retrieve with auth biometrics time out`() = runTest {
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

        assertEquals(RetrievalEventV2.Success(mapOf(alias to value)), result)
        verify(mockAuthenticator, times(2)).init(activityFragment)
        verify(mockAuthenticator, times(2)).close()
    }

    @Test
    fun `retrieve non-existent key-value pair`() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(eq(alias), any())).thenReturn(null)
        val result = sharedPrefsStoreAsync.retrieve(alias)

        assertEquals(
            RetrievalEventV2.Success(mapOf(alias to null)),
            result,
        )
    }

    @Test
    fun `test exists when the value is saved`() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.contains(alias)).thenReturn(true)

        val result = sharedPrefsStoreAsync.exists(alias)

        assertTrue(result)
    }

    @Test
    fun `test exists when the value is not saved`() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.contains(alias)).thenReturn(false)

        val result = sharedPrefsStoreAsync.exists(alias)

        assertFalse(result)
    }

    @Test
    fun `test upsert throws secure store error`() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        given(
            mockHybridCryptoManagerAsync.encrypt(
                value,
            ),
        ).willAnswer { throw GeneralSecurityException() }

        assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.upsert(alias, value)
        }
    }

    @Test
    fun `test retrieve throws error from wrong ACL`() = runTest {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)

        val result = sharedPrefsStoreAsync.retrieve(alias)

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.RECOVERABLE,
                "Access control level must be OPEN to use this retrieve method",
            ),
            result,
        )
    }

    @Test
    fun `test retrieve with auth throws error from wrong ACL`() = runTest {
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
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.RECOVERABLE,
                "Use retrieve method, access control is set to OPEN, no need for auth",
            ),
            result,
        )
    }

    @Test
    fun `test delete all throws error`() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        given(
            mockHybridCryptoManagerAsync.deleteKey(),
        ).willAnswer { throw KeyStoreException() }
        assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.deleteAll()
        }
    }

    @Test
    fun `test upsert throws error when missing initialisation`() = runTest {
        assertFailsWith<SecureStorageErrorV2> {
            sharedPrefsStoreAsync.upsert(alias, value)
        }
    }

    @Test
    fun `test retrieve with auth throws error when missing initialisation`() = runTest {
        val result = sharedPrefsStoreAsync
            .retrieveWithAuthentication(
                alias,
                authPromptConfig = authConfig,
                context = activityFragment,
            )

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.RECOVERABLE,
                "Must call init on SecureStore first!",
            ),
            result,
        )
    }

    @Test
    fun `test retrieve throws error when missing initialisation`() = runTest {
        val result = sharedPrefsStoreAsync.retrieve(alias)

        assertEquals(
            RetrievalEventV2.Failed(
                SecureStoreErrorTypeV2.RECOVERABLE,
                "Must call init on SecureStore first!",
            ),
            result,
        )
    }

    @Test
    fun `tests methods when shared prefs is null or no data stored`() = runTest {
        sharedPrefsStoreAsync.deleteAll()
        sharedPrefsStoreAsync.delete(encryptedKey)

        assertFalse(sharedPrefsStoreAsync.exists(encryptedKey))
    }

    @Test
    fun `test event retrieval failed`() {
        val expectedText = "Secure store retrieval failed: " +
            "\ntype - ${SecureStoreErrorTypeV2.RECOVERABLE}" +
            "\nreason - reason"
        val actualText = RetrievalEventV2.Failed(
            type = SecureStoreErrorTypeV2.RECOVERABLE,
            reason = "reason",
        ).toString()
        assertEquals(expectedText, actualText)
    }

    @ParameterizedTest
    @MethodSource("errorTypes")
    fun testRetrieveWithAuthenticationAuthErrorsNonGeneric(
        errorType: Int,
        codeString: String,
        expectedErrorType: SecureStoreErrorTypeV2,
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
            RetrievalEventV2.Failed(
                expectedErrorType,
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
                Arguments.of(
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    "13",
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_TIMEOUT,
                    "3",
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
                    "2",
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_HW_UNAVAILABLE,
                    "1",
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_CANCELED,
                    "5",
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_LOCKOUT,
                    "7",
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                    "9",
                    SecureStoreErrorTypeV2.RECOVERABLE,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_NO_BIOMETRICS,
                    "11",
                    SecureStoreErrorTypeV2.ERROR_NO_DEVICE_CREDENTIAL,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
                    "14",
                    SecureStoreErrorTypeV2.ERROR_NO_DEVICE_CREDENTIAL,
                ),
                Arguments.of(
                    BiometricPrompt.ERROR_USER_CANCELED,
                    "10",
                    SecureStoreErrorTypeV2.USER_CANCELLED,
                ),
            )
    }
}
