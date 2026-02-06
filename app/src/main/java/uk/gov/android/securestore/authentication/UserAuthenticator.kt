package uk.gov.android.securestore.authentication

import android.os.Build
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import uk.gov.android.securestore.AccessControlLevel

class UserAuthenticator : Authenticator {
    private var fragmentContext: FragmentActivity? = null
    override fun init(context: FragmentActivity) {
        fragmentContext = context
    }

    @Deprecated(
        "Replace with authenticate() with crypto parameter - aim to be removed by 6th of May 2026",
        replaceWith = ReplaceWith("authenticate(accessControlLevel, configuration, handler, null)"),
        level = DeprecationLevel.WARNING,
    )
    override fun authenticate(
        accessControlLevel: AccessControlLevel,
        configuration: AuthenticatorPromptConfiguration,
        handler: AuthenticatorCallbackHandler,
    ) {
        authenticate(accessControlLevel, configuration, handler, null)
    }

    override fun authenticate(
        accessControlLevel: AccessControlLevel,
        configuration: AuthenticatorPromptConfiguration,
        handler: AuthenticatorCallbackHandler,
        crypto: BiometricPrompt.CryptoObject?,
    ) {
        require(accessControlLevel != AccessControlLevel.OPEN)

        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(configuration.title)
            .setSubtitle(configuration.subTitle)
            .setDescription(configuration.description)
            .setConfirmationRequired(false)

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            promptInfoBuilder
                .setNegativeButtonText("Close")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setDeviceCredentialAllowed(true)
        } else {
            promptInfoBuilder
                .setAllowedAuthenticators(getRequireAuthenticators(accessControlLevel))
        }

        val biometricPrompt = fragmentContext?.let { BiometricPrompt(it, handler) }
        if (crypto != null) {
            biometricPrompt?.authenticate(promptInfoBuilder.build(), crypto)
        } else {
            biometricPrompt?.authenticate(promptInfoBuilder.build())
        }
    }

    private fun getRequireAuthenticators(accessControl: AccessControlLevel) =
        when (accessControl) {
            AccessControlLevel.OPEN -> -1
            AccessControlLevel.PASSCODE -> DEVICE_CREDENTIAL
            AccessControlLevel.PASSCODE_AND_BIOMETRICS ->
                BIOMETRIC_STRONG or DEVICE_CREDENTIAL
        }

    override fun close() {
        fragmentContext = null
    }
}
