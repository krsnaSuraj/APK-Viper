package com.apkviper.engine.static

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class CodeAnalyzer {

    private data class PatternInfo(val description: String, val severity: Severity)

    private val dangerousPatterns = listOf(
        "Runtime.getRuntime().exec" to PatternInfo("Command execution via Runtime.exec", Severity.HIGH),
        "ProcessBuilder" to PatternInfo("Command execution via ProcessBuilder", Severity.HIGH),
        "DexClassLoader" to PatternInfo("Dynamic DEX loading from file", Severity.HIGH),
        "addJavascriptInterface" to PatternInfo("JavaScript interface exposed in WebView (XSS risk)", Severity.HIGH),
        "loadUrl(\"javascript:" to PatternInfo("JavaScript injection in WebView", Severity.HIGH),
        "DevicePolicyManager" to PatternInfo("Device admin capabilities requested", Severity.MEDIUM),
        "killBackgroundProcesses" to PatternInfo("Background process killing", Severity.MEDIUM),
        "getRunningAppProcesses" to PatternInfo("Process enumeration", Severity.MEDIUM),
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val combined = (decompiled.javaSource.entries + decompiled.smaliSource.entries)
            .associate { it.key to it.value }

        combined.forEach { (filename, code) ->
            dangerousPatterns.forEach { (pattern, info) ->
                if (code.contains(pattern)) {
                    findings.add(Finding(
                        category = FindingCategory.CODE,
                        severity = info.severity,
                        title = info.description,
                        description = "Found in $filename",
                        file = filename
                    ))
                }
            }
        }

        return findings
    }
}
