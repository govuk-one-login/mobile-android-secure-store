package uk.gov.android.securestore

import android.content.Context

class SharedPrefsStore(
    context: Context,
    storeName: String
) : SecureStore {
    private val sharedPrefs = context.getSharedPreferences(storeName, Context.MODE_PRIVATE)

    override fun upsert(key: String, value: String) {
        writeToPrefs(key, value)
    }

    override fun delete(key: String) {
        writeToPrefs(key, null)
    }

    override fun retrieve(key: String): String? {
        return sharedPrefs.getString(key, null)
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
