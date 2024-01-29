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
import uk.gov.android.securestore.crypto.CryptoManager

@Suppress("UNCHECKED_CAST")
class SharedPrefsStoreTest {
    private val mockContext: FragmentActivity = mock()
    private val mockSharedPreferences: SharedPreferences = mock()
    private val mockEditor: SharedPreferences.Editor = mock()
    private val mockCryptoManager: CryptoManager = mock()
    private val mockAuthenticator: Authenticator = mock()

    private val config = SecureStorageConfiguration(
        "testStore",
        AccessControlLevel.OPEN
    )
    private val key = "testKey"
    private val value = "testValue"
    private val encryptedValue = "testEncrypted"

    private lateinit var sharedPrefsStore: SharedPrefsStore

    @Before
    fun setUp() {
        whenever(mockContext.getSharedPreferences(eq("testStore"), eq(Context.MODE_PRIVATE)))
            .thenReturn(mockSharedPreferences)
        whenever(mockSharedPreferences.edit()).thenReturn(mockEditor)

        sharedPrefsStore = SharedPrefsStore(
            mockContext,
            config,
            mockAuthenticator,
            mockCryptoManager
        )
    }

    @Test
    fun testUpsert() {
        whenever(mockCryptoManager.encryptText(value)).thenReturn(encryptedValue)

        runBlocking {
            sharedPrefsStore.upsert(key, value)

            verify(mockCryptoManager).encryptText(value)
            verify(mockEditor).putString(key, encryptedValue)
            verify(mockEditor).apply()
        }
    }

    @Test
    fun testDelete() {
        sharedPrefsStore.delete(key)

        verify(mockEditor).putString(key, null)
        verify(mockEditor).apply()
    }

    @Test
    fun testRetrieve() {
        whenever(mockSharedPreferences.getString(key, null)).thenReturn(encryptedValue)

        runBlocking {
            whenever(
                mockCryptoManager.decryptText(
                    eq(encryptedValue),
                    any(),
                    eq(null)
                )
            ).thenAnswer {
                (it.arguments[1] as (text: String?) -> Unit).invoke(value)
            }
            val result = sharedPrefsStore.retrieve(key)
            assertEquals(value, result)
        }
    }

    @Test
    fun testRetrieveNonExistentKey() {
        whenever(mockSharedPreferences.getString(eq(key), any())).thenReturn(null)
        runBlocking {
            val result = sharedPrefsStore.retrieve(key)

            assertNull(result)
        }
    }

    @Test
    fun testExists() {
        whenever(mockSharedPreferences.contains(key)).thenReturn(true)

        val result = sharedPrefsStore.exists(key)

        assertTrue(result)
    }

    @Test
    fun testDoesNotExist() {
        whenever(mockSharedPreferences.contains(key)).thenReturn(false)

        val result = sharedPrefsStore.exists(key)

        assertFalse(result)
    }

    @Test
    fun testUpsertThrowsError() {
        given(
            mockCryptoManager.encryptText(
                value
            )
        ).willAnswer { throw GeneralSecurityException() }

        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.upsert(key, value)
            }
        }
    }

    @Test
    fun testRetrieveThrowsError() {
        whenever(mockSharedPreferences.getString(key, null)).thenReturn(encryptedValue)
        given(mockCryptoManager.decryptText(eq(encryptedValue), any(), eq(null))).willAnswer {
            throw GeneralSecurityException()
        }

        assertThrows(SecureStorageError::class.java) {
            runBlocking {
                sharedPrefsStore.retrieve(key)
            }
        }
    }

    @Test
    fun testDeleteThrowsError() {
        given(mockCryptoManager.deleteKey()).willAnswer { throw KeyStoreException() }

        assertThrows(SecureStorageError::class.java) { sharedPrefsStore.delete(key) }
    }
}
