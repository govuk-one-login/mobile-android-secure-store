package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.given
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.crypto.EncryptedData
import uk.gov.android.securestore.crypto.HybridCryptoManager
import uk.gov.android.securestore.error.SecureStorageError
import uk.gov.android.securestore.error.SecureStoreErrorType
import java.security.GeneralSecurityException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Suppress("UNCHECKED_CAST")
class SharedPrefsStoreTest {
    private val mockContext: FragmentActivity = mock()
    private val mockSharedPreferences: SharedPreferences = mock()
    private val mockEditor: SharedPreferences.Editor = mock()
    private val mockHybridCryptoManager: HybridCryptoManager = mock()
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

    private val sharedPrefsStore: SecureStore = SharedPrefsStore(
        mockAuthenticator,
        mockHybridCryptoManager,
    )

    @BeforeEach
    fun setUp() {
        whenever(mockContext.getSharedPreferences(eq(storeId), eq(Context.MODE_PRIVATE)))
            .thenReturn(mockSharedPreferences)
        whenever(mockSharedPreferences.edit()).thenReturn(mockEditor)
    }

    @Test
    fun testUpsert() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockHybridCryptoManager.encrypt(eq(value))).thenReturn(encryptedData)

        runBlocking {
            sharedPrefsStore.upsert(alias, value)

            verify(mockHybridCryptoManager).encrypt(eq(value))
            verify(mockEditor).putString(alias, encryptedValue)
            verify(mockEditor).putString(alias + "Key", encryptedKey)
            verify(mockEditor, times(2)).apply()
        }
    }

    @Test
    fun testDeleteAfterInit() {
        initSecureStore(AccessControlLevel.OPEN)
        sharedPrefsStore.delete(alias)

        verify(mockEditor).remove(alias)
        verify(mockEditor).apply()
    }

    @Test
    fun testDeleteNoInit() {
        sharedPrefsStore.delete(alias)

        verifyNoInteractions(mockEditor)
    }

    @Test
    fun testRetrieve() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        runBlocking {
            whenever(
                mockHybridCryptoManager.decrypt(
                    eq(encryptedValue),
                    eq(encryptedKey),
                    any(),
                ),
            ).thenAnswer {
                (it.arguments[2] as (data: String?) -> Unit).invoke(value)
            }
            val result = sharedPrefsStore.retrieve(alias)
            assertEquals(RetrievalEvent.Success(mapOf(alias to value)), result)
        }
    }

    @Test
    fun testRetrieveMultiple() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)
        whenever(mockSharedPreferences.getString(alias2, null)).thenReturn(encryptedValue2)
        whenever(mockSharedPreferences.getString(alias2 + "Key", null)).thenReturn(encryptedKey2)

        runBlocking {
            whenever(
                mockHybridCryptoManager.decrypt(
                    eq(encryptedValue),
                    eq(encryptedKey),
                    any(),
                ),
            ).thenAnswer {
                (it.arguments[2] as (data: String?) -> Unit).invoke(value)
            }

            runBlocking {
                whenever(
                    mockHybridCryptoManager.decrypt(
                        eq(encryptedValue2),
                        eq(encryptedKey2),
                        any(),
                    ),
                ).thenAnswer {
                    (it.arguments[2] as (data: String?) -> Unit).invoke(value2)
                }
            }

            val result = sharedPrefsStore.retrieve(alias, alias2)
            assertEquals(RetrievalEvent.Success(mapOf(alias to value, alias2 to value2)), result)
        }
    }

    @Test
    fun testRetrieveWithAuthentication() {
        initSecureStore(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        runBlocking {
            whenever(
                mockAuthenticator.authenticate(
                    eq(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS),
                    eq(authConfig),
                    any(),
                ),
            ).thenAnswer {
                (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
            }
            whenever(
                mockHybridCryptoManager.decrypt(
                    eq(encryptedValue),
                    eq(encryptedKey),
                    any(),
                ),
            ).thenAnswer {
                (it.arguments[2] as (text: String?) -> Unit).invoke(value)
            }

            val result = sharedPrefsStore.retrieveWithAuthentication(
                alias,
                authPromptConfig = authConfig,
                context = activityFragment,
            )

            assertEquals(RetrievalEvent.Success(mapOf(alias to value)), result)
            verify(mockAuthenticator).init(activityFragment)
            verify(mockAuthenticator).close()
        }
    }

    @Test
    fun testRetrieveWithAuthenticationMultiple() {
        initSecureStore(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)
        whenever(mockSharedPreferences.getString(alias2, null)).thenReturn(encryptedValue2)
        whenever(mockSharedPreferences.getString(alias2 + "Key", null)).thenReturn(encryptedKey2)

        runBlocking {
            whenever(
                mockAuthenticator.authenticate(
                    eq(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS),
                    eq(authConfig),
                    any(),
                ),
            ).thenAnswer {
                (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
            }
            whenever(
                mockHybridCryptoManager.decrypt(
                    eq(encryptedValue),
                    eq(encryptedKey),
                    any(),
                ),
            ).thenAnswer {
                (it.arguments[2] as (text: String?) -> Unit).invoke(value)
            }
            whenever(
                mockHybridCryptoManager.decrypt(
                    eq(encryptedValue2),
                    eq(encryptedKey2),
                    any(),
                ),
            ).thenAnswer {
                (it.arguments[2] as (text: String?) -> Unit).invoke(value2)
            }

            val result = sharedPrefsStore.retrieveWithAuthentication(
                alias,
                authPromptConfig = authConfig,
                context = activityFragment,
            )

            assertEquals(RetrievalEvent.Success(mapOf(alias to value, alias2 to value2)), result)
            verify(mockAuthenticator).init(activityFragment)
            verify(mockAuthenticator).close()
        }
    }

    @Test
    fun testRetrieveWithAuthenticationNull() {
        initSecureStore(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(null)

        runBlocking {
            whenever(
                mockAuthenticator.authenticate(
                    eq(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS),
                    eq(authConfig),
                    any(),
                ),
            ).thenAnswer {
                (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
            }
            whenever(
                mockHybridCryptoManager.decrypt(
                    eq(encryptedValue),
                    eq(encryptedKey),
                    any(),
                ),
            ).thenAnswer {
                (it.arguments[2] as (text: String?) -> Unit).invoke(null)
            }

            val result = sharedPrefsStore.retrieveWithAuthentication(
                alias,
                authPromptConfig = authConfig,
                context = activityFragment,
            )

            assertEquals(RetrievalEvent.Failed(SecureStoreErrorType.NOT_FOUND), result)
            verify(mockAuthenticator).init(activityFragment)
            verify(mockAuthenticator).close()
        }
    }

    @Test
    fun testRetrieveNonExistentKey() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(eq(alias), any())).thenReturn(null)
        runBlocking {
            val result = sharedPrefsStore.retrieve(alias)

            assertEquals(RetrievalEvent.Failed(SecureStoreErrorType.NOT_FOUND), result)
        }
    }

    @Test
    fun testExists() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.contains(alias)).thenReturn(true)

        val result = sharedPrefsStore.exists(alias)

        assertTrue(result)
    }

    @Test
    fun testDoesNotExist() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.contains(alias)).thenReturn(false)

        val result = sharedPrefsStore.exists(alias)

        assertFalse(result)
    }

    @Test
    fun testUpsertThrowsError() {
        initSecureStore(AccessControlLevel.OPEN)
        given(
            mockHybridCryptoManager.encrypt(
                value,
            ),
        ).willAnswer { throw GeneralSecurityException() }

        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.upsert(alias, value)
            }
        }
    }

    @Test
    fun testRetrieveReturnsErrorFromCryptoThrows() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        given(mockHybridCryptoManager.decrypt(eq(encryptedValue), eq(encryptedKey), any()))
            .willAnswer {
                throw GeneralSecurityException()
            }

        runBlocking {
            val result = sharedPrefsStore.retrieve(alias)

            assertEquals(RetrievalEvent.Failed(SecureStoreErrorType.NOT_FOUND), result)
        }
    }

    @Test
    fun testRetrieveThrowsErrorFromWrongACL() {
        initSecureStore(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS)

        runBlocking {
            val result = sharedPrefsStore.retrieve(alias)

            assertEquals(
                RetrievalEvent.Failed(
                    SecureStoreErrorType.GENERAL,
                    "Access control level must be OPEN to use this retrieve method",
                ),
                result,
            )
        }
    }

    @Test
    fun testRetrieveWithAuthenticationThrowsErrorFromWrongACL() = runTest {
        initSecureStore(AccessControlLevel.OPEN)
        val authConfig = AuthenticatorPromptConfiguration(
            "title",
        )
        whenever(mockSharedPreferences.getString(alias, null)).thenReturn(encryptedValue)
        whenever(mockSharedPreferences.getString(alias + "Key", null)).thenReturn(encryptedKey)

        val result = sharedPrefsStore.retrieveWithAuthentication(
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
    fun testUpsertThrowsIfNotInit() {
        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.upsert(alias, value)
            }
        }
    }

    @Test
    fun testRetrieveWithAuthThrowsIfNotInit() {
        runBlocking {
            val result = sharedPrefsStore
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
    }

    @Test
    fun testRetrieveThrowsIfNotInit() {
        runBlocking {
            val result = sharedPrefsStore.retrieve(alias)

            assertEquals(
                RetrievalEvent.Failed(
                    SecureStoreErrorType.GENERAL,
                    "Must call init on SecureStore first!",
                ),
                result,
            )
        }
    }

    @Test
    fun testExistsThrowsIfNotInit() {
        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.exists(alias)
            }
        }
    }

    private fun initSecureStore(acl: AccessControlLevel) {
        val config = SecureStorageConfiguration(
            storeId,
            acl,
        )

        sharedPrefsStore.init(
            mockContext,
            config,
        )
    }
}
