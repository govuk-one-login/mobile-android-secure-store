package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import uk.gov.android.securestore.crypto.CryptoManager

class SharedPrefsStoreTest {

    private val mockContext: Context = mock()
    private val mockSharedPreferences: SharedPreferences = mock()
    private val mockEditor: SharedPreferences.Editor = mock()
    private val mockCryptoManager: CryptoManager = mock()

    private val storeName = "testStore"
    private val key = "testKey"
    private val value = "testValue"
    private val encryptedValue = "testEncrypted"

    private lateinit var sharedPrefsStore: SharedPrefsStore

    @Before
    fun setUp() {
        whenever(mockContext.getSharedPreferences(eq(storeName), eq(Context.MODE_PRIVATE)))
            .thenReturn(mockSharedPreferences)
        whenever(mockSharedPreferences.edit()).thenReturn(mockEditor)

        sharedPrefsStore = SharedPrefsStore(
            mockContext,
            storeName,
            false,
            mockCryptoManager
        )
    }

    @Test
    fun testUpsert() {
        whenever(mockCryptoManager.encryptText(key, value)).thenReturn(encryptedValue)

        sharedPrefsStore.upsert(key, value)

        verify(mockEditor).putString(key, encryptedValue)
        verify(mockEditor).apply()
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
        whenever(mockCryptoManager.decryptText(key, encryptedValue)).thenReturn(value)

        val result = sharedPrefsStore.retrieve(key)

        assertEquals(value, result)
    }

    @Test
    fun testRetrieveNonExistentKey() {
        whenever(mockSharedPreferences.getString(eq(key), any())).thenReturn(null)

        val result = sharedPrefsStore.retrieve(key)

        assertNull(result)
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
}
