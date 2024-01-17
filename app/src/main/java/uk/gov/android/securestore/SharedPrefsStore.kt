package uk.gov.android.securestore

import android.content.Context
import uk.gov.android.securestore.crypto.CryptoManager
import uk.gov.android.securestore.crypto.RsaCryptoManager

class SharedPrefsStore(
    context: Context,
    storeName: String,
    authRequired: Boolean = false,
    private val cryptoManager: CryptoManager = RsaCryptoManager(authRequired)
) : SecureStore {
    private val sharedPrefs = context.getSharedPreferences(storeName, Context.MODE_PRIVATE)

    override fun upsert(key: String, value: String): String {
        return cryptoManager.encryptText(key, value).also { writeToPrefs(key, it) }
    }

    override fun delete(key: String) {
        writeToPrefs(key, null)
        cryptoManager.deleteKey(key)
    }

    override fun retrieve(key: String): String? {
        return sharedPrefs.getString(key, null)?.let {
            cryptoManager.decryptText(key, it)
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
