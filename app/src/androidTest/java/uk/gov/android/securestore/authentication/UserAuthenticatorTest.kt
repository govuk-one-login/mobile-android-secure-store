package uk.gov.android.securestore.authentication

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties.DIGEST_SHA256
import android.security.keystore.KeyProperties.KEY_ALGORITHM_EC
import android.security.keystore.KeyProperties.PURPOSE_SIGN
import androidx.biometric.BiometricPrompt
import androidx.test.ext.junit.rules.ActivityScenarioRule
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import uk.gov.android.securestore.AccessControlLevel
import uk.gov.android.securestore.TestActivity
import java.security.KeyPairGenerator
import java.security.Signature

class UserAuthenticatorTest {
    @JvmField
    @Rule
    val rule: ActivityScenarioRule<TestActivity> = ActivityScenarioRule(TestActivity::class.java)

    private val authenticator: Authenticator = UserAuthenticator()
    private val authConfig = AuthenticatorPromptConfiguration(
        "title",
        "sub title",
        "description",
    )

    @Test
    fun openAuthFails() {
        rule.scenario.onActivity {
            authenticator.init(it)

            assertThrows(IllegalArgumentException::class.java) {
                authenticator.authenticate(
                    AccessControlLevel.OPEN,
                    authConfig,
                    AuthenticatorCallbackHandler(),
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
                AuthenticatorCallbackHandler(),
            )
        }
    }

    @Test
    fun runPasscodeCheckWithoutInit() {
        rule.scenario.onActivity {
            authenticator.authenticate(
                AccessControlLevel.PASSCODE,
                authConfig,
                AuthenticatorCallbackHandler(),
            )
        }
    }

    @Test
    fun runPasscodeAndBiometricsCheckWithCryptoObject() {
        rule.scenario.onActivity {
            authenticator.init(it)

            authenticator.authenticate(
                AccessControlLevel.PASSCODE_AND_BIOMETRICS,
                authConfig,
                AuthenticatorCallbackHandler(),
                createCryptoObject(),
            )
        }
    }

    @Test
    fun runPasscodeAndBiometricsCheckWithCryptoObjectWithoutInit() {
        rule.scenario.onActivity {
            authenticator.authenticate(
                AccessControlLevel.PASSCODE_AND_BIOMETRICS,
                authConfig,
                AuthenticatorCallbackHandler(),
                createCryptoObject(),
            )
        }
    }

    @Test
    fun runPasscodeAndBiometricsCheckWithCryptoObjectAfterClose() {
        rule.scenario.onActivity {
            authenticator.init(it)
            authenticator.close()

            authenticator.authenticate(
                AccessControlLevel.PASSCODE_AND_BIOMETRICS,
                authConfig,
                AuthenticatorCallbackHandler(),
                createCryptoObject(),
            )
        }
    }

    private fun createCryptoObject(): BiometricPrompt.CryptoObject {
        val keyPair = KeyPairGenerator.getInstance(KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            val params = KeyGenParameterSpec.Builder("test_key", PURPOSE_SIGN)
                .setDigests(DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()
            initialize(params)
            generateKeyPair()
        }
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(keyPair.private) }
        return BiometricPrompt.CryptoObject(signature)
    }
}
