package com.apkviper.engine.network

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class NetworkAnalyzer {

    data class C2Pattern(val name: String, val pattern: Regex, val severity: Severity)

    private val c2Patterns = listOf(
        C2Pattern("Pastebin", Regex("""pastebin\.com/raw/""", RegexOption.IGNORE_CASE), Severity.CRITICAL),
        C2Pattern("Ngrok", Regex("""ngrok\.io""", RegexOption.IGNORE_CASE), Severity.CRITICAL),
        C2Pattern("Serveo", Regex("""serveo\.net""", RegexOption.IGNORE_CASE), Severity.CRITICAL),
        C2Pattern("LocalTunnel", Regex("""localtunnel\.me""", RegexOption.IGNORE_CASE), Severity.CRITICAL),
        C2Pattern("Tor hidden service", Regex("""\.onion""", RegexOption.IGNORE_CASE), Severity.CRITICAL),
        C2Pattern("Dynamic DNS", Regex("""dynu\.com|dnsdynamic|dyndns""", RegexOption.IGNORE_CASE), Severity.HIGH),
        C2Pattern("No-IP", Regex("""no-ip\.com""", RegexOption.IGNORE_CASE), Severity.HIGH),
        C2Pattern("DuckDNS", Regex("""duckdns\.org""", RegexOption.IGNORE_CASE), Severity.HIGH),
        C2Pattern("Discord webhook", Regex("""discord(?:app)?\.com/api/webhooks""", RegexOption.IGNORE_CASE), Severity.HIGH),
        C2Pattern("Telegram bot", Regex("""t\.me/bot|telegram\.org/bot""", RegexOption.IGNORE_CASE), Severity.HIGH),
    )

    private val safeHttpDomains = setOf(
        "example.com", "example.org", "example.net", "localhost", "127.0.0.1"
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val allCode = decompiled.allSourceText ?: run {
            val estimatedSize = (decompiled.javaSource.values + decompiled.smaliSource.values).sumOf { it.length }
            if (estimatedSize > 50_000_000) {
                android.util.Log.w("NetworkAnalyzer", "Source too large ($estimatedSize bytes), skipping")
                return emptyList()
            }
            (decompiled.javaSource.values + decompiled.smaliSource.values).joinToString("\n")
        }

        for (c2 in c2Patterns) {
            if (c2.pattern.containsMatchIn(allCode)) {
                findings.add(Finding(
                    category = FindingCategory.NETWORK,
                    severity = c2.severity,
                    title = "${c2.name} C2 Server",
                    description = "C2 domain pattern '${c2.name}' found in code"
                ))
            }
        }

        if (Regex("""trustallcerts|ALLOW_ALL_HOSTNAME""", RegexOption.IGNORE_CASE).containsMatchIn(allCode)) {
            findings.add(Finding(
                category = FindingCategory.NETWORK,
                severity = Severity.HIGH,
                title = "SSL Pinning Bypass",
                description = "Code disables SSL certificate validation"
            ))
        }

        if (Regex("""HostnameVerifier""", RegexOption.IGNORE_CASE).containsMatchIn(allCode) &&
            Regex("""return\s+true""", RegexOption.IGNORE_CASE).containsMatchIn(allCode) &&
            findings.none { it.title == "SSL Pinning Bypass" }) {
            findings.add(Finding(
                category = FindingCategory.NETWORK,
                severity = Severity.HIGH,
                title = "SSL Pinning Bypass",
                description = "HostnameVerifier always returns true"
            ))
        }

        val httpUrls = Regex("""http://[^\s"'<>]+""", RegexOption.IGNORE_CASE).findAll(allCode)
        for (url in httpUrls) {
            val domain = url.value.removePrefix("http://").substringBefore("/").substringBefore("?").lowercase()
            if (domain !in safeHttpDomains && domain.contains(".")) {
                findings.add(Finding(
                    category = FindingCategory.NETWORK,
                    severity = Severity.MEDIUM,
                    title = "Suspicious HTTP Endpoint",
                    description = "Unencrypted HTTP connection to $domain"
                ))
            }
        }

        return findings.toList()
    }
}
