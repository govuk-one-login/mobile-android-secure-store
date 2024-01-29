package uk.gov.android.securestore

import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.crypto.RsaCryptoManager

@RunWith(AndroidJUnit4::class)
class SharedPrefsStoreInstrumentationTest {
    private val key = "testKey"
    private val value = "testValue"
    private val config = SecureStorageConfiguration(
        "testStore",
        AccessControlLevel.OPEN
    )

    private lateinit var sharedPrefsStore: SharedPrefsStore

    @JvmField
    @Rule
    val rule: ActivityScenarioRule<TestActivity> = ActivityScenarioRule(TestActivity::class.java)

    @Before
    fun setUp() {
        rule.scenario.onActivity {
            sharedPrefsStore = SharedPrefsStore(
                it,
                config,
                RsaCryptoManager(
                    it,
                    config.id,
                    config.accessControlLevel
                )
            )
        }

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        keyStore.deleteEntry(key)
    }

    @Test
    fun testUpsertAndRetrieve() {
        runBlocking {
            sharedPrefsStore.upsert(key, value)
            val result = sharedPrefsStore.retrieve(
                key,
                AuthenticatorPromptConfiguration(
                    "test",
                    "test",
                    "test"
                )
            )
            assertEquals(value, result)
        }
    }

    @Test
    fun testDeleteAndRetrieveNonExistentKey() {
        runBlocking {
            sharedPrefsStore.upsert(key, value)

            sharedPrefsStore.delete(key)
            val result = sharedPrefsStore.retrieve(key)
            assertNull(result)
        }
    }

    @Test
    fun testExists() {
        runBlocking {
            sharedPrefsStore.upsert(key, value)

            val result = sharedPrefsStore.exists(key)

            assertTrue(result)
        }
    }

    @Test
    fun testDoesNotExist() {
        val result = sharedPrefsStore.exists("nonExistentKey")

        assertFalse(result)
    }
}
