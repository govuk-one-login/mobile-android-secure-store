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
        when (errorCode) {
            // Face Scan operated on a one try flow basis which means that it registers the first scan and call onError() if
            // face is not recognised, instead of onFailure. This check below allows for FaceScan to have the same behaviour as
            // Fingerprint allowing multiple attempts with FaceScan
            BiometricPrompt.ERROR_UNABLE_TO_PROCESS, BiometricPrompt.ERROR_TIMEOUT -> onFailure()
            else -> onError(errorCode, errString)
        }
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
