package uk.gov.android.securestore.authentication

data class AuthenticatorPromptConfiguration(
    val title: String,
    val subTitle: String? = null,
    val description: String? = null
)
