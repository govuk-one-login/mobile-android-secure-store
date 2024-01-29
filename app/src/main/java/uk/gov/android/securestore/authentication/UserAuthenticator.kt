package uk.gov.android.securestore.authentication

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import uk.gov.android.securestore.AccessControlLevel

internal class UserAuthenticator(
    private val context: FragmentActivity
) : Authenticator {
    override fun authenticate(
        accessControlLevel: AccessControlLevel,
        configuration: AuthenticatorPromptConfiguration,
        handler: AuthenticatorCallbackHandler
    ) {
        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(configuration.title)
            .setSubtitle(configuration.subTitle)
            .setDescription(configuration.description)
            .setAllowedAuthenticators(getRequireAuthenticators(accessControlLevel))

        val biometricPrompt = BiometricPrompt(
            context,
            handler
        )

        biometricPrompt.authenticate(
            promptInfoBuilder.build()
        )
    }

    private fun getRequireAuthenticators(accessControl: AccessControlLevel) =
        when (accessControl) {
            AccessControlLevel.OPEN -> -1
            AccessControlLevel.PASSCODE -> DEVICE_CREDENTIAL
            AccessControlLevel.PASSCODE_AND_ANY_BIOMETRICS,
            AccessControlLevel.PASSCODE_AND_CURRENT_BIOMETRICS ->
                BIOMETRIC_STRONG or DEVICE_CREDENTIAL
        }
}
