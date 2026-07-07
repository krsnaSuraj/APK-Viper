package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class ShizukuDetector {

    companion object {
        private const val MAX_SOURCE_SIZE = 50 * 1024 * 1024
    }

    private val shizukuPatterns = listOf(
        "moe.shizuku.api" to "Shizuku API Usage",
        "moe.shizuku.manager" to "Shizuku Manager Reference",
        "ShizukuProvider" to "Shizuku ContentProvider",
        "ShizukuBinderWrapper" to "Shizuku Binder Wrapper",
        "Shizuku.bindUserService" to "Shizuku Service Binding",
        "Shizuku.checkSelfPermission" to "Shizuku Permission Check",
        "Shizuku.requestPermission" to "Shizuku Permission Request",
        "RemoteProcess" to "Shizuku Remote Process",
        "shizuku_uid" to "Shizuku UID Check",
    )

    private val susShellCommands = listOf(
        "pm grant", "pm revoke", "appops set", "cmd appops",
        "settings put", "settings delete", "content call",
        "am force-stop", "am start", "input keyevent",
        "service call", "dumpsys", "monkey -p"
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val allCode = decompiled.allSourceText ?: run {
            val combined = (decompiled.javaSource.values + decompiled.smaliSource.values)
            if (combined.sumOf { it.length } > MAX_SOURCE_SIZE) {
                (decompiled.javaSource.values.take(200) + decompiled.smaliSource.values.take(100)).joinToString("\n")
            } else {
                combined.joinToString("\n")
            }
        }

        var shizukuMatches = 0
        for ((pattern, _) in shizukuPatterns) {
            if (allCode.contains(pattern, ignoreCase = true)) {
                shizukuMatches++
            }
        }

        if (shizukuMatches >= 2) {
            val criticalOps = susShellCommands.count { allCode.contains(it, ignoreCase = true) }
            val severity = if (criticalOps >= 3) Severity.CRITICAL else Severity.HIGH

            findings.add(Finding(
                category = FindingCategory.CODE,
                severity = severity,
                title = "Shizuku / Rootless Privilege Escalation",
                description = "App uses Shizuku API ($shizukuMatches patterns) for root-level operations without root access",
                details = buildString {
                    append("Shizuku enables apps to run shell commands with system privileges via ADB.")
                    if (criticalOps > 0) append(" Dangerous shell operations detected: $criticalOps.")
                }
            ))
        }

        val anyShizuku = shizukuPatterns.any { (pattern, _) -> allCode.contains(pattern, ignoreCase = true) }
        if (anyShizuku && shizukuMatches < 2) {
            findings.add(Finding(
                category = FindingCategory.CODE,
                severity = Severity.MEDIUM,
                title = "Shizuku API Reference Detected",
                description = "App references Shizuku API but may use it legitimately for system tools"
            ))
        }

        return findings
    }
}
