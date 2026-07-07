package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class AccessibilityChainAnalyzer {

    companion object {
        private const val MAX_SOURCE_SIZE = 50 * 1024 * 1024
    }

    private val toxicCombinations = listOf(
        Triple("Accessibility + Overlay + Network", listOf(
            "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "INTERNET"
        ), Severity.CRITICAL),
        Triple("Accessibility + Notification Listener + Network", listOf(
            "BIND_ACCESSIBILITY_SERVICE", "BIND_NOTIFICATION_LISTENER_SERVICE", "INTERNET"
        ), Severity.CRITICAL),
        Triple("Accessibility + SMS + Network", listOf(
            "BIND_ACCESSIBILITY_SERVICE", "READ_SMS", "INTERNET"
        ), Severity.CRITICAL),
        Triple("Accessibility + Install Packages + Network", listOf(
            "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES", "INTERNET"
        ), Severity.CRITICAL),
        Triple("Overlay + Notification Listener + Install Packages", listOf(
            "SYSTEM_ALERT_WINDOW", "BIND_NOTIFICATION_LISTENER_SERVICE", "REQUEST_INSTALL_PACKAGES"
        ), Severity.HIGH),
        Triple("Accessibility + Camera + Network", listOf(
            "BIND_ACCESSIBILITY_SERVICE", "CAMERA", "INTERNET"
        ), Severity.HIGH),
        Triple("Accessibility + Location + Network", listOf(
            "BIND_ACCESSIBILITY_SERVICE", "ACCESS_FINE_LOCATION", "INTERNET"
        ), Severity.HIGH),
    )

    private val accessibilityApis = listOf(
        "performGlobalAction", "getRootInActiveWindow",
        "findAccessibilityNodeInfosByText",
        "findAccessibilityNodeInfosByViewId",
        "getWindows", "onAccessibilityEvent",
        "AccessibilityNodeInfo", "dispatchGesture",
        "getSource", "getPackageName",
        "getText", "getContentDescription"
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val manifest = decompiled.manifest.lowercase()
        val allCode = decompiled.allSourceText?.lowercase() ?: run {
            if (decompiled.javaSource.values.sumOf { it.length } > MAX_SOURCE_SIZE) {
                decompiled.javaSource.values.take(200).joinToString(" ").lowercase()
            } else {
                decompiled.javaSource.values.joinToString(" ").lowercase()
            }
        }

        val presentPerms = manifest.split(Regex("\\s+")).filter { it.startsWith("android.permission.") }
            .map { it.removePrefix("android.permission.") }.toSet()

        for ((chainName, requiredPerms, severity) in toxicCombinations) {
            val permsFound = requiredPerms.filter { it.lowercase() in presentPerms.map { p -> p.lowercase() } }
            if (permsFound.size >= 2) {
                val apiEvidence = accessibilityApis.count { allCode.contains(it, ignoreCase = true) }
                val finalSeverity = if (apiEvidence >= 3 && permsFound.size >= 2) {
                    if (severity == Severity.HIGH) Severity.HIGH else Severity.CRITICAL
                } else Severity.MEDIUM

                findings.add(Finding(
                    category = FindingCategory.BEHAVIORAL,
                    severity = finalSeverity,
                    title = "Accessibility Abuse Chain: $chainName",
                    description = "Combines ${permsFound.size}/3 dangerous permissions (${
                        permsFound.joinToString(", ")
                    }) with $apiEvidence accessibility API calls",
                    details = buildString {
                        appendLine("This permission combination is the hallmark of modern Android malware.")
                        appendLine("Legitimate apps almost never combine accessibility with these permissions.")
                        if (apiEvidence >= 3) {
                            appendLine("Confirmed accessibility API usage in code — not just a declared permission.")
                        }
                    }
                ))
            }
        }

        return findings
    }
}
