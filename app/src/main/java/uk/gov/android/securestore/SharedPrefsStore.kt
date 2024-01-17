package uk.gov.android.securestore

import android.content.Context
import java.security.GeneralSecurityException
import java.security.KeyStoreException
import uk.gov.android.securestore.crypto.CryptoManager
import uk.gov.android.securestore.crypto.RsaCryptoManager

@Suppress("SwallowedException")
class SharedPrefsStore(
    context: Context,
    configuration: SecureStorageConfiguration,
    private val cryptoManager: CryptoManager = RsaCryptoManager()
) : SecureStore {
    private val sharedPrefs = context.getSharedPreferences(configuration.id, Context.MODE_PRIVATE)

    override fun upsert(key: String, value: String): String {
        try {
            return cryptoManager.encryptText(key, value).also { writeToPrefs(key, it) }
        } catch (e: GeneralSecurityException) {
            throw SecureStorageError(e.message)
        }
    }

    override fun delete(key: String) {
        writeToPrefs(key, null)
        try {
            cryptoManager.deleteKey(key)
        } catch (e: KeyStoreException) {
            throw SecureStorageError(e.message)
        }
    }

    override fun retrieve(key: String): String? {
        try {
            return sharedPrefs.getString(key, null)?.let {
                cryptoManager.decryptText(key, it)
            }
        } catch (e: GeneralSecurityException) {
            throw SecureStorageError(e.message)
        }
    }

    override fun exists(key: String): Boolean {
        return sharedPrefs.contains(key)
    }

    private fun writeToPrefs(key: String, value: String?) {
        with(sharedPrefs.edit()) {
            putString(key, value)
            apply()
        }
    }
}
