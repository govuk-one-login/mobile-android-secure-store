package uk.gov.android.securestore.authentication

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import uk.gov.android.securestore.AccessControlLevel

/**
 * Class to handle making OS Authentication. Calling a Biometric Prompt
 */
interface Authenticator {
    /**
     * Initializing the FragmentContext to be used before initializing the SharedPrefsStore methods.
     */
    fun init(context: FragmentActivity)

    /**
     * Start an OS authentication prompt
     *
     * @param accessControlLevel The [AccessControlLevel] required to authenticate for
     * @param configuration for the UI elements of the OS Biometric Prompt
     * @param handler An [AuthenticatorCallbackHandler] to handle success, failure and error states from authentication
     */
    @Deprecated(
        "Replace with authenticate() with crypto parameter - aim to be removed by 6th of May 2026",
        replaceWith = ReplaceWith("authenticate(accessControlLevel, configuration, handler, null)"),
        level = DeprecationLevel.WARNING,
    )
    fun authenticate(
        accessControlLevel: AccessControlLevel,
        configuration: AuthenticatorPromptConfiguration,
        handler: AuthenticatorCallbackHandler,
    )

    /**
     * Start an OS authentication prompt
     *
     * @param accessControlLevel The [AccessControlLevel] required to authenticate for
     * @param configuration for the UI elements of the OS Biometric Prompt
     * @param handler An [AuthenticatorCallbackHandler] to handle success, failure and error states from authentication
     * @param crypto An [BiometricPrompt.CryptoObject] to be associated with this authentication
     */
    fun authenticate(
        accessControlLevel: AccessControlLevel,
        configuration: AuthenticatorPromptConfiguration,
        handler: AuthenticatorCallbackHandler,
        crypto: BiometricPrompt.CryptoObject?,
    )

    /**
     * Closing the FragmentContext - to be used after initializing the SharedPrefsStore methods have
     * been completed.
     */
    fun close()
}
