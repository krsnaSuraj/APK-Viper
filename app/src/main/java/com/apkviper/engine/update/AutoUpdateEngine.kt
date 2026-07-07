package com.apkviper.engine.update

import android.content.Context
import com.apkviper.engine.advanced.ThreatIntelDB
import com.apkviper.engine.malware.KnownMalwareDB
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.concurrent.TimeUnit

class AutoUpdateEngine(private val context: Context) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    // Fallback: use bundled rules when remote is unavailable
    private val bundledYara: String by lazy {
        try {
            context.assets.open("yara_rules/default.yar").bufferedReader().use { it.readText() }
        } catch (e: Exception) { "" }
    }

    private val ruleSources = listOf(
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_crime_teams.yar",
    )

    // Always fall back to bundled data when remote feeds are unavailable
    private val bundledHashes: List<KnownMalwareDB.MalwareEntry> by lazy {
        KnownMalwareDB.getAllEntries()
    }

    data class UpdateResult(
        val yaraRulesUpdated: Boolean,
        val yaraRuleCount: Int,
        val hashesUpdated: Boolean,
        val hashCount: Int,
        val intelUpdated: Boolean,
        val intelCount: Int,
        val errors: List<String> = emptyList()
    )

    suspend fun checkAndUpdate(): UpdateResult = withContext(Dispatchers.IO) {
        val errors = mutableListOf<String>()
        val firstPair = try {
            val r = updateYaraRules(); r.first to if (r.second > 0) r.second else countBundledRules()
        } catch (e: Exception) { errors.add("YARA: ${e.message}"); false to countBundledRules() }

        val secondPair = try {
            val r = updateMalwareHashes(); r.first to (if (r.second > 0) r.second else bundledHashes.size)
        } catch (e: Exception) { errors.add("Hashes: ${e.message}"); false to bundledHashes.size }

        val thirdPair = try {
            val r = updateThreatIntel(); r.first to r.second
        } catch (e: Exception) { errors.add("Intel: ${e.message}"); false to 0 }

        UpdateResult(firstPair.first, firstPair.second, secondPair.first, secondPair.second,
            thirdPair.first, ThreatIntelDB.getIpCount() + ThreatIntelDB.getDomainCount(), errors)
    }

    private suspend fun updateYaraRules(): Pair<Boolean, Int> {
        var anyDownloaded = false
        var totalCount = 0
        val maxSize = 10 * 1024 * 1024

        for (url in ruleSources) {
            try {
                val request = Request.Builder().url(url).header("Accept", "text/plain").build()
                val response = client.newCall(request).execute()
                if (!response.isSuccessful) continue
                val body = response.body ?: continue

                val tempFile = File(context.cacheDir, "yara_dl_${url.hashCode()}.tmp")
                val bodyStream = body.byteStream()
                val fos = java.io.FileOutputStream(tempFile)
                var totalBytes = 0L
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (bodyStream.read(buffer).also { bytesRead = it } != -1) {
                    totalBytes += bytesRead
                    if (totalBytes > maxSize) { fos.close(); bodyStream.close(); tempFile.delete(); break }
                    fos.write(buffer, 0, bytesRead)
                }
                fos.close()
                bodyStream.close()
                if (totalBytes > maxSize) continue

                val count = countRulesInFile(tempFile)
                if (count > 0) {
                    val cacheFile = File(context.filesDir, "yara_rules_cache.yar")
                    tempFile.copyTo(cacheFile, overwrite = true)
                    totalCount += count
                    anyDownloaded = true
                }
                tempFile.delete()
            } catch (_: Exception) {}
        }

        if (!anyDownloaded) {
            val cacheFile = File(context.filesDir, "yara_rules_cache.yar")
            if (bundledYara.isNotBlank() && (!cacheFile.exists() || cacheFile.length() == 0L)) {
                cacheFile.writeText(bundledYara)
                totalCount = countRulesInText(bundledYara)
            }
        }
        return Pair(anyDownloaded, totalCount)
    }

    private fun countBundledRules(): Int {
        return countRulesInText(bundledYara)
    }

    private fun countRulesInFile(file: File): Int {
        if (!file.exists() || file.length() == 0L) return 0
        var count = 0
        file.bufferedReader(charset = Charsets.UTF_8).use { r ->
            var line: String?
            while (r.readLine().also { line = it } != null) {
                if (line?.startsWith("rule ") == true || line?.startsWith("rule\t") == true) count++
            }
        }
        return count
    }

    private fun countRulesInText(text: String): Int {
        if (text.isBlank()) return 0
        return text.lines().count { it.trimStart().startsWith("rule ") || it.trimStart().startsWith("rule\t") }
    }

    private suspend fun updateMalwareHashes(): Pair<Boolean, Int> {
        try {
            val request = Request.Builder().url("https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/malware_hashes.txt")
                .header("Accept", "text/plain").build()
            val response = client.newCall(request).execute()
            if (!response.isSuccessful) return Pair(false, 0)
            val body = response.body?.string() ?: return Pair(false, 0)

            val lines = body.lines().filter { it.length == 64 && it.all { c -> c.isLetterOrDigit() } }
            if (lines.isNotEmpty()) {
                val entries = lines.map { KnownMalwareDB.MalwareEntry(it, "Remote Hash Feed", "Community", com.apkviper.model.Severity.CRITICAL) }
                KnownMalwareDB.updateFromRemote(entries)
                return Pair(true, entries.size)
            }
        } catch (_: Exception) {}
        return Pair(false, 0)
    }

    private suspend fun updateThreatIntel(): Pair<Boolean, Int> {
        try {
            val request = Request.Builder().url("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt")
                .header("Accept", "text/plain").build()
            val response = client.newCall(request).execute()
            if (!response.isSuccessful) return Pair(false, 0)
            val body = response.body?.string() ?: return Pair(false, 0)

            val ips = body.lines().filter { it.matches(Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\s+\\d+$")) }
                .map { it.substringBefore(" ") }
                .take(500)
            if (ips.isNotEmpty()) {
                ThreatIntelDB.updateIps(ips)
                return Pair(true, ips.size)
            }
        } catch (_: Exception) {}
        return Pair(false, 0)
    }

    fun getDynamicRules(): String {
        val D = "${'$'}"
        return """
rule Dynamic_ZeroDay_CryptoMiner {
    meta:
        description = "Dynamic behavioral detection for unknown crypto miners"
        family = "ZeroDay"
        severity = "critical"
    strings:
        ${D}thread = "ThreadPoolExecutor"
        ${D}hash = "MessageDigest"
        ${D}alg1 = "SHA-256"
        ${D}alg2 = "CryptoNight"
        ${D}alg3 = "RandomX"
        ${D}loop = "while(true)"
        ${D}socket = "Socket"
        ${D}cpu = "Runtime.getRuntime().availableProcessors"
        ${D}ncpu = "/proc/cpuinfo"
        ${D}thermal = "/sys/class/thermal"
    condition:
        3 of them
}

rule Dynamic_ZeroDay_Infostealer {
    meta:
        description = "Dynamic behavioral detection for unknown infostealers"
        family = "ZeroDay"
        severity = "critical"
    strings:
        ${D}data1 = "getDeviceId"
        ${D}data2 = "getSubscriberId"
        ${D}data3 = "getLastKnownLocation"
        ${D}data4 = "ContactsContract"
        ${D}data5 = "getAccounts"
        ${D}send1 = "HttpURLConnection"
        ${D}send2 = "OkHttpClient"
        ${D}send3 = "socket"
        ${D}encode = "Base64"
        ${D}zipstr = "GZIPOutputStream"
        ${D}json = "JSONObject"
    condition:
        (${D}send1 or ${D}send2 or ${D}send3) and (${D}encode or ${D}zipstr) and (${D}data1 or ${D}data2 or ${D}data3 or ${D}data4 or ${D}data5)
}

rule Dynamic_ZeroDay_SilentInstaller {
    meta:
        description = "Detects apps that silently install other packages"
        family = "ZeroDay"
        severity = "critical"
    strings:
        ${D}perm1 = "INSTALL_PACKAGES"
        ${D}perm2 = "REQUEST_INSTALL_PACKAGES"
        ${D}cmd1 = "pm install"
        ${D}cmd2 = "installPackage"
        ${D}dex1 = "DexClassLoader"
        ${D}dex2 = "PathClassLoader"
        ${D}ref = "Class.forName"
        ${D}invoke = "Method.invoke"
        ${D}apk = ".apk"
        ${D}write = "FileOutputStream"
        ${D}download = "URL.openConnection"
    condition:
        (${D}dex1 or ${D}dex2) and (${D}cmd1 or ${D}cmd2) and (${D}write or ${D}download)
}
"""
    }
}
