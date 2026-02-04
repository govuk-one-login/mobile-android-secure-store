package uk.gov.android.securestore.error

import android.security.keystore.UserNotAuthenticatedException
import java.lang.IllegalStateException
import java.lang.IndexOutOfBoundsException
import java.lang.UnsupportedOperationException
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableEntryException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.NoSuchPaddingException

object ErrorTypeHandlerV2 {
    fun getErrorType(error: SecureStorageErrorV2): SecureStoreErrorTypeV2 {
        return when (error.cause) {
            is AEADBadTagException,
            is UnrecoverableKeyException,
            is BadPaddingException,
            is UserNotAuthenticatedException,
            is NoSuchAlgorithmException,
            is NoSuchPaddingException,
            is UnsupportedOperationException,
            is InvalidKeyException,
            is UnrecoverableEntryException,
            is KeyStoreException,
            is IllegalStateException,
            is InvalidAlgorithmParameterException,
            is IndexOutOfBoundsException,
            is GeneralSecurityException,
            -> SecureStoreErrorTypeV2.UNRECOVERABLE
            else -> SecureStoreErrorTypeV2.RECOVERABLE
        }
    }
}
