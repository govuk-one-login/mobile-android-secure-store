package uk.gov.android.securestore

import androidx.test.ext.junit.rules.ActivityScenarioRule
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Rule
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import uk.gov.android.securestore.authentication.Authenticator
import uk.gov.android.securestore.authentication.AuthenticatorCallbackHandler
import uk.gov.android.securestore.authentication.AuthenticatorPromptConfiguration
import uk.gov.android.securestore.error.SecureStoreErrorType
import java.security.KeyStore

class SharedPrefsStoreInstrumentationTest {
    private val key = "testKey"
    private val value = "testValue"
    private val storeId = "id"

    private val mockAuthenticator: Authenticator = mock()

    private val sharedPrefsStore = SharedPrefsStore(
        authenticator = mockAuthenticator,
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
                sharedPrefsStore.upsert(key, value)
                val result = sharedPrefsStore.retrieve(
                    key,
                )
                assertEquals(RetrievalEvent.Success(mapOf(key to value)), result)
            }
        }
    }

    @Test
    @Ignore("Currently don't know if we can simulate biometrics on emulator")
    fun testUpsertAndRetrieveWithAuth() {
        initSecureStore(AccessControlLevel.PASSCODE_AND_BIOMETRICS)
        whenever(
            mockAuthenticator.authenticate(
                any(),
                any(),
                any(),
            ),
        ).thenAnswer {
            (it.arguments[2] as AuthenticatorCallbackHandler).onSuccess()
        }

        rule.scenario.onActivity {
            runBlocking {
                sharedPrefsStore.upsert(key, value)
                val result = sharedPrefsStore.retrieveWithAuthentication(
                    key,
                    authPromptConfig = AuthenticatorPromptConfiguration("title"),
                    context = it,
                )

                assertEquals(
                    RetrievalEvent.Failed(
                        SecureStoreErrorType.GENERAL,
                        "android.security.keystore.UserNotAuthenticatedException: User not authenticated",
                    ),
                    result,
                )
            }

            verify(mockAuthenticator).init(it)
            verify(mockAuthenticator).close()
        }
    }

    @Test
    fun testDeleteAndRetrieveNonExistentKeyAfterInit() {
        initSecureStore(AccessControlLevel.OPEN)
        rule.scenario.onActivity {
            runBlocking {
                sharedPrefsStore.upsert(key, value)
                val result1 = sharedPrefsStore.retrieve(
                    key,
                )
                assertEquals(RetrievalEvent.Success(mapOf(key to value)), result1)

                sharedPrefsStore.delete(key)
                val result2 = sharedPrefsStore.retrieve(
                    key,
                )
                assertEquals(
                    RetrievalEvent.Failed(
                        SecureStoreErrorType.NOT_FOUND,
                        "java.lang.Exception: testKey not found",
                    ),
                    result2,
                )
            }
        }
    }

    @Test
    fun testDeleteAll() {
        val anotherValue = "anotherValue"
        val anotherKey = "anotherKey"
        initSecureStore(AccessControlLevel.OPEN)
        rule.scenario.onActivity {
            runBlocking {
                sharedPrefsStore.upsert(key, value)
                sharedPrefsStore.upsert(anotherKey, anotherValue)
                val result1 = sharedPrefsStore.retrieve(
                    key,
                    anotherKey,
                )
                assertEquals(
                    RetrievalEvent.Success(
                        mapOf(
                            key to value,
                            anotherKey to anotherValue,
                        ),
                    ),
                    result1,
                )

                sharedPrefsStore.deleteAll()

                assertFalse(sharedPrefsStore.exists(key))
                assertFalse(sharedPrefsStore.exists(anotherKey))
            }
        }
    }

    @Test
    fun testExists() {
        initSecureStore(AccessControlLevel.OPEN)
        rule.scenario.onActivity {
            runBlocking {
                sharedPrefsStore.upsert(key, value)

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
                    acl,
                ),
            )
        }
    }
}
