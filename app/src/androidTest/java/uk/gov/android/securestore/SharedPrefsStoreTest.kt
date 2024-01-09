package uk.gov.android.securestore

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SharedPrefsStoreTest {

    private val storeName = "testStore"
    private val key = "testKey"
    private val value = "testValue"

    private lateinit var sharedPrefsStore: SharedPrefsStore

    @Before
    fun setUp() {
        sharedPrefsStore = SharedPrefsStore(
            ApplicationProvider.getApplicationContext(),
            storeName
        )
    }

    @Test
    fun testUpsertAndRetrieve() {
        sharedPrefsStore.upsert(key, value)

        val result = sharedPrefsStore.retrieve(key)
        assertEquals(value, result)
    }

    @Test
    fun testDeleteAndRetrieveNonExistentKey() {
        sharedPrefsStore.upsert(key, value)

        sharedPrefsStore.delete(key)

        val result = sharedPrefsStore.retrieve(key)
        assertNull(result)
    }

    @Test
    fun testExists() {
        sharedPrefsStore.upsert(key, value)

        val result = sharedPrefsStore.exists(key)

        assertTrue(result)
    }

    @Test
    fun testDoesNotExist() {
        val result = sharedPrefsStore.exists("nonExistentKey")

        assertFalse(result)
    }
}
