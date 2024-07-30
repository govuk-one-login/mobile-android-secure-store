package uk.gov.android.securestore.authentication

import androidx.test.ext.junit.rules.ActivityScenarioRule
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import uk.gov.android.securestore.AccessControlLevel
import uk.gov.android.securestore.TestActivity

class UserAuthenticatorTest {
    @JvmField
    @Rule
    val rule: ActivityScenarioRule<TestActivity> = ActivityScenarioRule(TestActivity::class.java)

    private val authenticator: Authenticator = UserAuthenticator()
    private val authConfig = AuthenticatorPromptConfiguration(
        "title",
        "sub title",
        "description"
    )

    @Test
    fun openAuthFails() {
        rule.scenario.onActivity {
            authenticator.init(it)

            assertThrows(IllegalArgumentException::class.java) {
                authenticator.authenticate(
                    AccessControlLevel.OPEN,
                    authConfig,
                    AuthenticatorCallbackHandler()
                )
            }
        }
    }

    @Test
    fun runPasscodeCheck() {
        rule.scenario.onActivity {
            authenticator.init(it)

            authenticator.authenticate(
                AccessControlLevel.PASSCODE,
                authConfig,
                AuthenticatorCallbackHandler()
            )
        }
    }
}
