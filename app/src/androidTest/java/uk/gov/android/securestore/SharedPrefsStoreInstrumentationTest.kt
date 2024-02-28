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
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        keyStore.deleteEntry(key)
    }

    @Test
    fun testUpsertAndRetrieve() {
        rule.scenario.onActivity {
            sharedPrefsStore = SharedPrefsStore(
                context = it,
                configuration = config
            )
            runBlocking {
                sharedPrefsStore.upsert(key, value, it)
                val result = sharedPrefsStore.retrieve(
                    key,
                    AuthenticatorPromptConfiguration(
                        "test",
                        "test",
                        "test"
                    ),
                    it
                )
                assertEquals(value, result)
            }
        }
    }

    @Test
    fun testDeleteAndRetrieveNonExistentKey() {
        rule.scenario.onActivity {
            sharedPrefsStore = SharedPrefsStore(
                context = it,
                configuration = config
            )
            runBlocking {
                sharedPrefsStore.upsert(key, value, it)

                sharedPrefsStore.delete(key, it)
                val result = sharedPrefsStore.retrieve(key,
                    AuthenticatorPromptConfiguration(
                        "test",
                        "test",
                        "test"
                    ),
                    it
                )
                assertNull(result)
            }
        }
    }

    @Test
    fun testExists() {
        rule.scenario.onActivity {
            sharedPrefsStore = SharedPrefsStore(
                context = it,
                configuration = config
            )
            runBlocking {
                sharedPrefsStore.upsert(key, value, it)

                val result = sharedPrefsStore.exists(key)

                assertTrue(result)
            }
        }
    }

    @Test
    fun testDoesNotExist() {
        rule.scenario.onActivity {
            sharedPrefsStore = SharedPrefsStore(
                context = it,
                configuration = config
            )
            val result = sharedPrefsStore.exists("nonExistentKey")

            assertFalse(result)
        }
    }
}
