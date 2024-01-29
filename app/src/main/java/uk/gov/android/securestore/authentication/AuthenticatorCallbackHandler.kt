package uk.gov.android.securestore.authentication

data class AuthenticatorCallbackHandler(
    val onSuccess: () -> Unit = {},
    val onError: (
        errorCode: Int,
        errString: CharSequence
    ) -> Unit = { _, _ -> },
    val onFailure: () -> Unit = {}
)
