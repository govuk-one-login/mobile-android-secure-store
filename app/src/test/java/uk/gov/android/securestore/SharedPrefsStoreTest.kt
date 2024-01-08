package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`

class SharedPrefsStoreTest {

    private val mockContext: Context = mock()
    private val mockSharedPreferences: SharedPreferences = mock()
    private val mockEditor: SharedPreferences.Editor = mock()

    private val storeName = "testStore"
    private val key = "testKey"
    private val value = "testValue"

    private lateinit var sharedPrefsStore: SharedPrefsStore

    @Before
    fun setUp() {
        `when`(mockContext.getSharedPreferences(eq(storeName), eq(Context.MODE_PRIVATE)))
            .thenReturn(mockSharedPreferences)

        `when`(mockSharedPreferences.edit()).thenReturn(mockEditor)

        sharedPrefsStore = SharedPrefsStore(mockContext, storeName)
    }

    @Test
    fun testUpsert() {
        sharedPrefsStore.upsert(key, value)

        verify(mockEditor).putString(key, value)
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
        `when`(mockSharedPreferences.getString(eq(key), any())).thenReturn(value)

        val result = sharedPrefsStore.retrieve(key)

        assertEquals(value, result)
    }

    @Test
    fun testRetrieveNonExistentKey() {
        `when`(mockSharedPreferences.getString(eq(key), any())).thenReturn(null)

        val result = sharedPrefsStore.retrieve(key)

        assertNull(result)
    }

    @Test
    fun testExists() {
        `when`(mockSharedPreferences.contains(key)).thenReturn(true)

        val result = sharedPrefsStore.exists(key)

        assertTrue(result)
    }

    @Test
    fun testDoesNotExist() {
        `when`(mockSharedPreferences.contains(key)).thenReturn(false)

        val result = sharedPrefsStore.exists(key)

        assertFalse(result)
    }
}
