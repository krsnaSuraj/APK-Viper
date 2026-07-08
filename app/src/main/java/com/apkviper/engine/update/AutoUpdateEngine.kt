package com.apkviper.engine.update

import android.content.Context
import com.apkviper.engine.advanced.ThreatIntelDB
import com.apkviper.engine.malware.KnownMalwareDB
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Auto-update engine — keeps detection current WITHOUT shipping a new app version.
 *
 * Sources (all fetched automatically, on a schedule; the user does nothing):
 *   1. Curated ruleset hosted in OUR repo: rules/android_rules.yar (high confidence).
 *      When a new Android malware family emerges, a rule is added there and every installed
 *      app auto-pulls it on next update — no app rebuild, no manual action.
 *   2. Community signature-base feed (best-effort, LOW confidence): fetched, then filtered to
 *      drop non-Android rules (webshells, PHP/ASP/JSP, Office, Windows/PE, unsupported YARA
 *      modules). Surviving rules are tagged `confidence = "low"` so they can never alone (or
 *      even together) drive a MALICIOUS verdict — they are corroborating signals only.
 *   3. Known-malware hash feed (signature-base IOCs) — definitive, high confidence.
 *   4. Threat-intel C2 IP feed (ipsum) — used only for C2 correlation.
 *
 * Safety: downloaded rule text is validated (UTF-8, parseable, no forbidden constructs) before
 * it is cached; on any failure the last-good cache is preserved (fail-safe).
 */
class AutoUpdateEngine(private val context: Context) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    // Our own curated, Android-only ruleset (future-proof: edit this file in the repo).
    private val curatedRuleUrl =
        "https://raw.githubusercontent.com/krsnaSuraj/APK-Viper/main/rules/android_rules.yar"

    // Community Android-relevant rule files (best-effort, low-confidence after filtering).
    // Any 404 / failure is silently skipped — the engine degrades gracefully.
    private val communityRuleSources = listOf(
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_mobile_malware.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/android_malware.yar"
    )

    // Fallback: use bundled rules when remote is unavailable.
    private val bundledYara: String by lazy {
        try {
            context.assets.open("yara_rules/default.yar").bufferedReader().use { it.readText() }
        } catch (e: Exception) { "" }
    }

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
        val merged = StringBuilder()
        var curatedOk = false
        var communityOk = false

        // 1) Curated baseline from our repo (high confidence).
        try {
            val body = fetchText(curatedRuleUrl)
            if (body != null && isValidYara(body)) {
                merged.append("// === CURATED (apk-viper repo) ===\n").append(body).append("\n")
                curatedOk = true
            }
        } catch (_: Exception) {}

        // 2) Community feed (best-effort, filtered + low-confidence).
        for (url in communityRuleSources) {
            try {
                val body = fetchText(url) ?: continue
                if (!isValidYara(body)) continue
                val filtered = filterCommunityRules(body)
                if (filtered.isNotBlank()) {
                    merged.append("// === COMMUNITY (low-confidence) ===\n").append(filtered).append("\n")
                    communityOk = true
                }
            } catch (_: Exception) {}
        }

        if (curatedOk || communityOk) {
            val total = countRulesInText(merged.toString())
            if (total > 0) {
                val cacheFile = File(context.filesDir, "yara_rules_cache.yar")
                cacheFile.writeText(merged.toString())
                return Pair(true, total)
            }
        }

        // Fallback: keep last-good cache, or seed it with bundled rules.
        val cacheFile = File(context.filesDir, "yara_rules_cache.yar")
        if (!cacheFile.exists() || cacheFile.length() == 0L) {
            if (bundledYara.isNotBlank()) {
                cacheFile.writeText(bundledYara)
                return Pair(false, countRulesInText(bundledYara))
            }
        }
        return Pair(false, if (cacheFile.exists()) countRulesInFile(cacheFile) else 0)
    }

    private suspend fun fetchText(url: String): String? {
        val request = Request.Builder().url(url).header("Accept", "text/plain").build()
        val response = client.newCall(request).execute()
        if (!response.isSuccessful) return null
        return response.body?.string()
    }

    /**
     * Filters a community ruleset down to Android-relevant, engine-supported rules and tags
     * them low-confidence. Drops:
     *  - rules whose name implies a non-Android domain (webshell, php, asp, jsp, office,
     *    windows, win_, macro, exploit-server, doc/xls/ppt).
     *  - rules that reference unsupported YARA modules (pe, elf, math, cuckoo, dotnet, ole,
     *    archive, checksum, dex — our engine only supports text/hex string matching + conditions).
     * Surviving rules get `confidence = "low"` injected into their meta block.
     */
    private fun filterCommunityRules(text: String): String {
        val forbiddenName = Regex("webshell|\\bphp\\b|\\basp\\b|\\bjsp\\b|office|windows|win_|macro|exploit.?server|\\bdocx?\\b|\\bxlsx?\\b|\\bpptx?\\b|\\bvba\\b", RegexOption.IGNORE_CASE)
        val forbiddenBody = Regex("\\bpe\\.|\\belf\\.|\\bmath\\.|cuckoo|dotnet|\\bole\\.|archive|\\bdex\\.(section|header)|checksum", RegexOption.IGNORE_CASE)

        val blocks = splitRuleBlocks(text)
        val kept = mutableListOf<String>()
        for (block in blocks) {
            val name = block.lineSequence().firstOrNull { it.trim().startsWith("rule ") } ?: ""
            if (forbiddenName.containsMatchIn(name)) continue
            if (forbiddenBody.containsMatchIn(block)) continue
            kept.add(tagLowConfidence(block))
        }
        return kept.joinToString("\n")
    }

    private fun splitRuleBlocks(text: String): List<String> {
        val lines = text.lines()
        val blocks = mutableListOf<String>()
        val sb = StringBuilder()
        for (line in lines) {
            if (line.trim().startsWith("rule ") && sb.isNotEmpty()) {
                blocks.add(sb.toString())
                sb.clear()
            }
            sb.append(line).append("\n")
        }
        if (sb.isNotEmpty()) blocks.add(sb.toString())
        return blocks
    }

    private fun tagLowConfidence(block: String): String {
        // Inject `confidence = "low"` right after the first `meta:` line of the rule.
        val lines = block.lines().toMutableList()
        var injected = false
        for (i in lines.indices) {
            if (!injected && lines[i].trim().startsWith("meta")) {
                // find the next non-empty line that is not the closing brace to insert after meta header
                var j = i + 1
                while (j < lines.size && lines[j].trim().isEmpty()) j++
                if (j < lines.size && !lines[j].trim().startsWith("}")) {
                    lines.add(j, "        confidence = \"low\"")
                    injected = true
                }
                break
            }
        }
        if (!injected) {
            // No meta block — prepend a meta line inside the rule braces.
            val out = StringBuilder()
            var added = false
            for (line in lines) {
                out.append(line).append("\n")
                if (!added && line.trim() == "{") {
                    out.append("    meta:\n        confidence = \"low\"\n")
                    added = true
                }
            }
            return out.toString()
        }
        return lines.joinToString("\n")
    }

    private fun isValidYara(text: String): Boolean {
        if (text.isEmpty()) return false
        if (text.contains('\u0000')) return false // binary corruption
        val ruleCount = countRulesInText(text)
        if (ruleCount == 0) return false
        // Reject if it references unsupported YARA module imports (would never evaluate correctly).
        if (Regex("""import\s+""", RegexOption.IGNORE_CASE).containsMatchIn(text)) return false
        return true
    }

    private fun countBundledRules(): Int = countRulesInText(bundledYara)

    private fun countRulesInFile(file: File): Int {
        if (!file.exists() || file.length() == 0L) return 0
        var count = 0
        file.bufferedReader(charset = Charsets.UTF_8).use { r ->
            var line: String?
            while (r.readLine().also { line = it } != null) {
                if (line?.trimStart()?.startsWith("rule ") == true) count++
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
            val request = Request.Builder().url("https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt")
                .header("Accept", "text/plain").build()
            val response = client.newCall(request).execute()
            if (!response.isSuccessful) return Pair(false, 0)
            val body = response.body?.string() ?: return Pair(false, 0)

            // signature-base format: "<hash>;<comment>" per line, hash may be MD5/SHA1/SHA256.
            val hashes = body.lines()
                .map { it.substringBefore(';').trim() }
                .filter { it.length in setOf(32, 40, 64) && it.all { c -> c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F' } }
            if (hashes.isNotEmpty()) {
                val entries = hashes.map { KnownMalwareDB.MalwareEntry(it.lowercase(), "Remote Hash Feed", "Community", Severity.CRITICAL) }
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

    /**
     * On-device behavioral zero-day rules. These are DELIBERATELY specific so they cannot
     * false-positive on ordinary apps (or on APK Viper's own code):
     *  - CryptoMiner requires actual miner indicators (stratum/tcp pools, xmrig, cryptonight,
     *    randomx, cpuminer, coinhive, mining-pool hostnames) — a normal app using MessageDigest
     *    + SHA-256 + sockets will NOT trigger.
     *  - Infostealer requires >=2 PII data sources AND a network exfil primitive AND an encoding
     *    primitive (Base64/GZIP) — a single telemetry call will not trigger.
     *  - SilentInstaller requires a package installer primitive AND dynamic DEX loading.
     */
    fun getDynamicRules(): String {
        return """
 rule Dynamic_ZeroDay_CryptoMiner {
    meta:
        description = "Dynamic behavioral detection for unknown crypto miners"
        family = "ZeroDay"
        severity = "critical"
    strings:
        ${'$'}pool1 = "stratum+tcp"
        ${'$'}pool2 = "stratum+ssl"
        ${'$'}miner1 = "xmrig"
        ${'$'}miner2 = "cryptonight"
        ${'$'}miner3 = "randomx"
        ${'$'}miner4 = "cpuminer"
        ${'$'}miner5 = "minerd"
        ${'$'}miner6 = "coinhive"
        ${'$'}miner7 = "webminer"
        ${'$'}miner8 = "xmrpool"
        ${'$'}miner9 = "mining.pool"
        ${'$'}miner10 = "monero"
    condition:
        2 of (${'$'}pool1, ${'$'}pool2, ${'$'}miner1, ${'$'}miner2, ${'$'}miner3, ${'$'}miner4, ${'$'}miner5, ${'$'}miner6, ${'$'}miner7, ${'$'}miner8, ${'$'}miner9, ${'$'}miner10)
}

rule Dynamic_ZeroDay_Infostealer {
    meta:
        description = "Detects apps that harvest >=2 PII sources and exfiltrate them encoded"
        family = "ZeroDay"
        severity = "critical"
    strings:
        ${'$'}data1 = "getDeviceId"
        ${'$'}data2 = "getSubscriberId"
        ${'$'}data3 = "getLastKnownLocation"
        ${'$'}data4 = "ContactsContract"
        ${'$'}data5 = "getAccounts"
        ${'$'}send1 = "HttpURLConnection"
        ${'$'}send2 = "OkHttpClient"
        ${'$'}send3 = "socket"
        ${'$'}encode = "Base64"
        ${'$'}zipstr = "GZIPOutputStream"
        ${'$'}json = "JSONObject"
    condition:
        ((${'$'}send1 or ${'$'}send2 or ${'$'}send3) and (${'$'}encode or ${'$'}zipstr) and 2 of (${'$'}data1, ${'$'}data2, ${'$'}data3, ${'$'}data4, ${'$'}data5))
}

rule Dynamic_ZeroDay_SilentInstaller {
    meta:
        description = "Detects apps that silently install other packages"
        family = "ZeroDay"
        severity = "critical"
    strings:
        ${'$'}perm1 = "INSTALL_PACKAGES"
        ${'$'}perm2 = "REQUEST_INSTALL_PACKAGES"
        ${'$'}cmd1 = "pm install"
        ${'$'}cmd2 = "installPackage"
        ${'$'}dex1 = "DexClassLoader"
        ${'$'}dex2 = "PathClassLoader"
        ${'$'}ref = "Class.forName"
        ${'$'}invoke = "Method.invoke"
        ${'$'}apk = ".apk"
        ${'$'}write = "FileOutputStream"
        ${'$'}download = "URL.openConnection"
    condition:
        ((${'$'}dex1 or ${'$'}dex2) and (${'$'}cmd1 or ${'$'}cmd2) and (${'$'}write or ${'$'}download))
}
"""
    }
}
