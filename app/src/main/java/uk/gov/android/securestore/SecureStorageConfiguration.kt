package uk.gov.android.securestore

import android.content.Context
import android.content.SharedPreferences

data class SecureStorageConfiguration(
    private val id: String,
    val accessControlLevel: AccessControlLevel
) {
    fun getSharedPrefs(ctx: Context): SharedPreferences {
        return ctx.getSharedPreferences(id, Context.MODE_PRIVATE)
    }
}
