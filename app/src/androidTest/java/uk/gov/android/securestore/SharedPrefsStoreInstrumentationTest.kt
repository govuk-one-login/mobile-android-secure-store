package uk.gov.android.securestore

import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration

@RunWith(AndroidJUnit4::class)
class SharedPrefsStoreInstrumentationTest {
    private val key = "testKey"
    private val value = "testValue"
    private val storeId = "id"

    private val mockAuthenticator: Authenticator = mock()

    private val sharedPrefsStore = SharedPrefsStore(
        authenticator = mockAuthenticator
    )

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
        initSecureStore(AccessControlLevel.OPEN)
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
    fun testUpsertAndRetrieveWithAuthThrows() {
        initSecureStore(AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS)
        whenever(
            mockAuthenticator.authenticate(
                any(),
                any(),
                any()
            )
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
        }

        rule.scenario.onActivity {
            runBlocking {
                sharedPrefsStore.upsert(key, value, it)
                assertThrows(SecureStorageError::class.java) {
                    runBlocking {
                        sharedPrefsStore.retrieveWithAuthentication(
                            key,
                            AuthenticatorPromptConfiguration("title"),
                            it
                        )
                    }
                }

                verify(mockAuthenticator, times(2)).init(it)
                verify(mockAuthenticator, times(2)).close()
            }
        }
    }

    @Test
    fun testDeleteAndRetrieveNonExistentKey() {
        initSecureStore(AccessControlLevel.OPEN)
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
        initSecureStore(AccessControlLevel.OPEN)
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
        initSecureStore(AccessControlLevel.OPEN)
        rule.scenario.onActivity {
            val result = sharedPrefsStore.exists("nonExistentKey")

            assertFalse(result)
        }
    }

    private fun initSecureStore(acl: AccessControlLevel) {
        rule.scenario.onActivity {
            sharedPrefsStore.init(
                context = it,
                configuration = SecureStorageConfiguration(
                    storeId,
                    acl
                )
            )
        }
    }
}
