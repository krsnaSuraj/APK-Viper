package com.apkviper.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "apk_viper_settings")

class SettingsDataStore(private val context: Context) {

    companion object {
        val AUTO_UPDATE = booleanPreferencesKey("auto_update")
        val LAST_UPDATE_TIMESTAMP = longPreferencesKey("last_update_timestamp")
        val YARA_RULE_COUNT = longPreferencesKey("yara_rule_count")
        val HASH_DB_SIZE = longPreferencesKey("hash_db_size")
        val INTEL_IPS = longPreferencesKey("intel_ip_count")
        val INTEL_DOMAINS = longPreferencesKey("intel_domain_count")
        val TRUSTED_SIGNERS = stringSetPreferencesKey("trusted_signers")
    }

    val autoUpdate: Flow<Boolean> = context.dataStore.data.map { it[AUTO_UPDATE] ?: true }
    val lastUpdateTimestamp: Flow<Long> = context.dataStore.data.map { it[LAST_UPDATE_TIMESTAMP] ?: 0L }
    val yaraRuleCount: Flow<Long> = context.dataStore.data.map { it[YARA_RULE_COUNT] ?: 0L }
    val hashDbSize: Flow<Long> = context.dataStore.data.map { it[HASH_DB_SIZE] ?: 0L }
    val intelIpCount: Flow<Long> = context.dataStore.data.map { it[INTEL_IPS] ?: 0L }
    val intelDomainCount: Flow<Long> = context.dataStore.data.map { it[INTEL_DOMAINS] ?: 0L }
    val trustedSigners: Flow<Set<String>> = context.dataStore.data.map { it[TRUSTED_SIGNERS] ?: emptySet() }

    suspend fun setAutoUpdate(enabled: Boolean) {
        context.dataStore.edit { it[AUTO_UPDATE] = enabled }
    }

    suspend fun addTrustedSigner(certSha256: String) {
        val c = certSha256.lowercase().replace(":", "")
        context.dataStore.edit { it[TRUSTED_SIGNERS] = (it[TRUSTED_SIGNERS] ?: emptySet()) + c }
    }

    suspend fun removeTrustedSigner(certSha256: String) {
        val c = certSha256.lowercase().replace(":", "")
        context.dataStore.edit { it[TRUSTED_SIGNERS] = (it[TRUSTED_SIGNERS] ?: emptySet()) - c }
    }

    suspend fun updateSignatureStatus(yaraCount: Long, hashCount: Long, ipCount: Long, domainCount: Long) {
        context.dataStore.edit {
            it[LAST_UPDATE_TIMESTAMP] = System.currentTimeMillis()
            it[YARA_RULE_COUNT] = yaraCount
            it[HASH_DB_SIZE] = hashCount
            it[INTEL_IPS] = ipCount
            it[INTEL_DOMAINS] = domainCount
        }
    }
}
