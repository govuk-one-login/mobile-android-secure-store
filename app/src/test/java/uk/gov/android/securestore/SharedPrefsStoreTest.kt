package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import androidx.fragment.app.FragmentActivity
import java.security.GeneralSecurityException
import java.security.KeyStoreException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.given
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.crypto.CryptoManager

@Suppress("UNCHECKED_CAST")
class SharedPrefsStoreTest {
    private val mockContext: FragmentActivity = mock()
    private val mockSharedPreferences: SharedPreferences = mock()
    private val mockEditor: SharedPreferences.Editor = mock()
    private val mockCryptoManager: CryptoManager = mock()
    private val mockAuthenticator: Authenticator = mock()
    private val activityFragment: FragmentActivity = mock()

    private val storeId = "id"
    private val key = "testKey"
    private val value = "testValue"
    private val encryptedValue = "testEncrypted"
    private val authConfig = AuthenticatorPromptConfiguration(
        "title"
    )

    private val sharedPrefsStore: SecureStore = SharedPrefsStore(
        mockAuthenticator,
        mockCryptoManager
    )

    @Before
    fun setUp() {
        whenever(mockContext.getSharedPreferences(eq(storeId), eq(Context.MODE_PRIVATE)))
            .thenReturn(mockSharedPreferences)
        whenever(mockSharedPreferences.edit()).thenReturn(mockEditor)
    }

    @Test
    fun testUpsert() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockCryptoManager.encryptText(value)).thenReturn(encryptedValue)

        runBlocking {
            sharedPrefsStore.upsert(key, value, activityFragment)

            verify(mockCryptoManager).encryptText(value)
            verify(mockEditor).putString(key, encryptedValue)
            verify(mockEditor).apply()
        }
    }

    @Test
    fun testDelete() {
        initSecureStore(AccessControlLevel.OPEN)
        sharedPrefsStore.delete(key, activityFragment)

        verify(mockEditor).putString(key, null)
        verify(mockEditor).apply()
    }

    @Test
    fun testRetrieve() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(key, null)).thenReturn(encryptedValue)

        runBlocking {
            whenever(
                mockCryptoManager.decryptText(
                    eq(encryptedValue),
                    any()
                )
            ).thenAnswer {
                (it.arguments[1] as (text: String?) -> Unit).invoke(value)
            }
            val result = sharedPrefsStore.retrieve(key)
            assertEquals(value, result)
        }
    }

    @Test
    fun testRetrieveWithAuthentication() {
        initSecureStore(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS)
        whenever(mockSharedPreferences.getString(key, null)).thenReturn(encryptedValue)

        runBlocking {
            whenever(
                mockAuthenticator.authenticate(
                    eq(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS),
                    eq(authConfig),
                    any()
                )
            ).thenAnswer {
                (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
            }
            whenever(
                mockCryptoManager.decryptText(
                    eq(encryptedValue),
                    any()
                )
            ).thenAnswer {
                (it.arguments[1] as (text: String?) -> Unit).invoke(value)
            }

            val result = sharedPrefsStore.retrieveWithAuthentication(
                key,
                authConfig,
                activityFragment
            )

            assertEquals(value, result)
            verify(mockAuthenticator).init(activityFragment)
            verify(mockAuthenticator).close()
        }
    }

    @Test
    fun testRetrieveNonExistentKey() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(eq(key), any())).thenReturn(null)
        runBlocking {
            val result = sharedPrefsStore.retrieve(key)

            assertNull(result)
        }
    }

    @Test
    fun testExists() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.contains(key)).thenReturn(true)

        val result = sharedPrefsStore.exists(key)

        assertTrue(result)
    }

    @Test
    fun testDoesNotExist() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.contains(key)).thenReturn(false)

        val result = sharedPrefsStore.exists(key)

        assertFalse(result)
    }

    @Test
    fun testUpsertThrowsError() {
        initSecureStore(AccessControlLevel.OPEN)
        given(
            mockCryptoManager.encryptText(
                value
            )
        ).willAnswer { throw GeneralSecurityException() }

        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.upsert(key, value, activityFragment)
            }
        }
    }

    @Test
    fun testRetrieveThrowsErrorFromCrypto() {
        initSecureStore(AccessControlLevel.OPEN)
        whenever(mockSharedPreferences.getString(key, null)).thenReturn(encryptedValue)
        given(mockCryptoManager.decryptText(eq(encryptedValue), any())).willAnswer {
            throw GeneralSecurityException()
        }

        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.retrieve(key)
            }
        }
    }

    @Test
    fun testRetrieveThrowsErrorFromWrongACL() {
        initSecureStore(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS)

        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.retrieve(key)
            }
        }
    }

    @Test
    fun testRetrieveWithAuthenticationThrowsErrorFromWrongACL() {
        initSecureStore(AccessControlLevel.OPEN)
        val authConfig = AuthenticatorPromptConfiguration(
            "title"
        )

        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.retrieveWithAuthentication(
                    key,
                    authConfig,
                    activityFragment
                )
            }
        }
    }

    @Test
    fun testDeleteThrowsError() {
        initSecureStore(AccessControlLevel.OPEN)
        given(mockCryptoManager.deleteKey()).willAnswer { throw KeyStoreException() }
        assertThrows(SecureStorageError::class.java) {
            sharedPrefsStore.delete(key, activityFragment)
        }
    }

    @Test
    fun testUpsertThrowsIfNotInit() {
        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.upsert(key, value, activityFragment)
            }
        }
    }

    @Test
    fun testRetrieveWithAuthThrowsIfNotInit() {
        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.retrieveWithAuthentication(key, authConfig, activityFragment)
            }
        }
    }

    @Test
    fun testRetrieveThrowsIfNotInit() {
        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.retrieve(key)
            }
        }
    }

    @Test
    fun testExistsThrowsIfNotInit() {
        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.exists(key)
            }
        }
    }

    @Test
    fun testDeleteThrowsIfNotInit() {
        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.delete(key, activityFragment)
            }
        }
    }

    private fun initSecureStore(acl: AccessControlLevel) {
        val config = SecureStorageConfiguration(
            storeId,
            acl
        )

        sharedPrefsStore.init(
            mockContext,
            config
        )
    }
}
