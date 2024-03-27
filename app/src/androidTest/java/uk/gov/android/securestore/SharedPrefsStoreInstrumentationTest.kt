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
import org.mockito.kotlin.mock
import uk.gov.android.securestore.authentication.Authenticator

@RunWith(AndroidJUnit4::class)
class SharedPrefsStoreInstrumentationTest {
    private val key = "testKey"
    private val value = "testValue"
    private val config = SecureStorageConfiguration(
        "testStore",
        AccessControlLevel.OPEN
    )
    private val mockAuthenticator: Authenticator = mock()

    private lateinit var sharedPrefsStore: SharedPrefsStore

    @JvmField
    @Rule
    val rule: ActivityScenarioRule<TestActivity> = ActivityScenarioRule(TestActivity::class.java)

    @Before
    fun setUp() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        keyStore.deleteEntry(key)

        rule.scenario.onActivity {
            sharedPrefsStore = SharedPrefsStore(
                context = it,
                configuration = config,
                authenticator = mockAuthenticator
            )
        }
    }

    @Test
    fun testUpsertAndRetrieve() {
        rule.scenario.onActivity {
            runBlocking {
                sharedPrefsStore.upsert(key, value, it)
                val result = sharedPrefsStore.retrieve(
                    key
                )
                assertEquals(value, result)
            }
        }
    }

    @Test
    fun testDeleteAndRetrieveNonExistentKey() {
        rule.scenario.onActivity {
            runBlocking {
                sharedPrefsStore.upsert(key, value, it)

                sharedPrefsStore.delete(key, it)
                val result = sharedPrefsStore.retrieve(
                    key
                )
                assertNull(result)
            }
        }
    }

    @Test
    fun testExists() {
        rule.scenario.onActivity {
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
            val result = sharedPrefsStore.exists("nonExistentKey")

            assertFalse(result)
        }
    }
}
