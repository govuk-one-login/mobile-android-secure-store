package uk.gov.android.securestore.authentication

import uk.gov.android.securestore.AccessControlLevel

/**
 * Class to handle making OS Authentication. Calling a Biometric Prompt
 */
interface Authenticator {
    /**
     * Start an OS authentication prompt
     *
     * @param accessControlLevel The [AccessControlLevel] required to authenticate for
     * @param configuration Configuration for the UI elements of the OS Biometric Prompt
     * @param handler An [AuthenticatorCallbackHandler] to handle success, failure and error states from authentication
     */
    fun authenticate(
        accessControlLevel: AccessControlLevel,
        configuration: AuthenticatorPromptConfiguration,
        handler: AuthenticatorCallbackHandler
    )
}
