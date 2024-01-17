package uk.gov.android.securestore

enum class AccessControlLevel {
    OPEN,
    PASSCODE,
    PASSCODE_AND_ANY_BIOMETRICS,
    PASSCODE_AND_CURRENT_BIOMETRICS
}
