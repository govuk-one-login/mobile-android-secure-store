package uk.gov.android.securestore.authentication

import androidx.biometric.BiometricPrompt

data class AuthenticatorCallbackHandler(
    val onSuccess: () -> Unit = {},
    val onError: (
        errorCode: Int,
        errString: CharSequence,
    ) -> Unit = { _, _ -> },
    val onFailure: () -> Unit = {},
) : BiometricPrompt.AuthenticationCallback() {
    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        super.onAuthenticationError(errorCode, errString)
        onError(errorCode, errString)
    }

    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        super.onAuthenticationSucceeded(result)
        onSuccess()
    }

    override fun onAuthenticationFailed() {
        super.onAuthenticationFailed()
        onFailure()
    }
}
