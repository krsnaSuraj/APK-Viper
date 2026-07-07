package com.apkviper.engine.static

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class StringExtractor {

    // Noise patterns — compiler toolchain URLs and internal IPs that are NOT threats
    private val noiseUrlPatterns = listOf(
        Regex(".*googlesource\\.com/toolchain.*"),
        Regex(".*googlesource\\.com/.*"),
        Regex(".*crashpad\\.chromium\\.org.*"),
        Regex(".*chromium\\.googlesource\\.com.*"),
        Regex(".*llvm\\.org.*"),
        Regex(".*gcc\\.gnu\\.org.*"),
        Regex(".*sourceware\\.org.*"),
        Regex(".*android\\.googlesource\\.com.*"),
        Regex(".*freedesktop\\.org.*"),
        Regex(".*schemas\\.android\\.com.*"),
        Regex(".*schemas\\.xmlsoap\\.org.*"),
        Regex(".*w3\\.org.*"),
        Regex(".*apache\\.org.*"),
    )

    private val noiseIpPatterns = listOf(
        Regex("""^127\.0\.0\.\d+$"""),
        Regex("""^0\.0\.0\.0$"""),
        Regex("""^255\.255\.255\.255$"""),
        Regex("""^10\.\d+\.\d+\.\d+$"""),
        Regex("""^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$"""),
        Regex("""^192\.168\.\d+\.\d+$"""),
        Regex("""^169\.254\.\d+\.\d+$"""),
        Regex("""^0\.0\.0\.\d+$"""),
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val allCode = decompiled.allSourceText ?: (decompiled.javaSource.values + decompiled.smaliSource.values).joinToString("\n")

        // URLs — exclude noise (toolchain, schema, internal)
        val urlPattern = Regex("""https?://[^\s"'<>]+""")
        val allUrls = urlPattern.findAll(allCode).map { it.value }.distinct().toList()
        val realUrls = allUrls.filter { url ->
            noiseUrlPatterns.none { pattern -> pattern.matches(url) }
        }
        if (realUrls.isNotEmpty()) {
            findings.add(Finding(
                category = FindingCategory.STRING, severity = Severity.LOW,
                title = "${realUrls.size} External URL(s) found",
                description = realUrls.take(5).joinToString("\n")
            ))
        }

        // IPs — exclude loopback, private, internal
        val ipPattern = Regex("""\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""")
        val allIps = ipPattern.findAll(allCode).map { it.value }.distinct().toList()
        val realIps = allIps.filter { ip ->
            noiseIpPatterns.none { pattern -> pattern.matches(ip) }
        }
        if (realIps.isNotEmpty()) {
            findings.add(Finding(
                category = FindingCategory.STRING, severity = Severity.MEDIUM,
                title = "${realIps.size} Hardcoded IP(s) found",
                description = realIps.take(5).joinToString("\n"),
                details = if (realIps.size > 5) "... and ${realIps.size - 5} more" else null
            ))
        }

        // Hardcoded secrets (API keys, tokens, passwords)
        val secretPattern = Regex("""(api[_-]?key|apikey|secret[_-]?key|password|token|auth[_-]?token)\s*[=:]\s*['"][^'"]{6,}['"]""", RegexOption.IGNORE_CASE)
        val secrets = secretPattern.findAll(allCode).map { it.value }.distinct().toList()
        if (secrets.isNotEmpty()) {
            findings.add(Finding(
                category = FindingCategory.STRING, severity = Severity.HIGH,
                title = "${secrets.size} Hardcoded Secret(s)",
                description = secrets.take(3).joinToString("\n"),
                details = "Hardcoded credentials are a security vulnerability"
            ))
        }

        // Base64 blobs (>80 chars — likely encoded data, not short tokens)
        val base64Pattern = Regex("""[A-Za-z0-9+/]{80,}={0,2}""")
        val base64Count = base64Pattern.findAll(allCode).count()
        if (base64Count > 5) {
            findings.add(Finding(
                category = FindingCategory.STRING, severity = Severity.MEDIUM,
                title = "$base64Count Base64-encoded blobs",
                description = "Large Base64 strings may indicate encoded assets or hidden payloads"
            ))
        }

        return findings
    }
}
