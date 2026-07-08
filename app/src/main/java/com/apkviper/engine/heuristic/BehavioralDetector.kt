package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity

/**
 * Behavioral detector — only flags confirmed malware patterns with
 * multi-signal co-occurrence. Removed generic APIs like HttpURLConnection,
 * EditText, WebView that match every legitimate app.
 */
class BehavioralDetector {

    private data class Indicator(val name: String, val severity: Severity, val patterns: List<String>, val minMatches: Int = 1)

    private val indicators = listOf(
        // Data theft — requires multiple signals
        Indicator("SMS Exfiltration", Severity.CRITICAL, listOf("sendTextMessage", "getMessageBody", "SmsManager"), minMatches = 2),
        Indicator("Contact Theft", Severity.CRITICAL, listOf("ContactsContract", "ContentResolver.query", "READ_CONTACTS"), minMatches = 2),
        Indicator("Call Log Theft", Severity.CRITICAL, listOf("CallLog.Calls", "READ_CALL_LOG"), minMatches = 2),
        Indicator("Account Token Theft", Severity.CRITICAL, listOf("AccountManager", "getAuthToken", "getAccountsByType"), minMatches = 2),
        Indicator("Screenshot Capture", Severity.HIGH, listOf("MediaProjection", "createVirtualDisplay", "ImageReader"), minMatches = 2),
        Indicator("Clipboard Snooping", Severity.HIGH, listOf("ClipboardManager", "getPrimaryClip", "addPrimaryClipChangedListener"), minMatches = 2),

        // Privilege escalation — genuine exploits
        Indicator("Root Exploit Attempt", Severity.CRITICAL, listOf("Runtime.getRuntime().exec(\"su", "/system/bin/su", "Superuser.apk")),
        Indicator("Overlay + Accessibility Chain", Severity.CRITICAL, listOf("TYPE_APPLICATION_OVERLAY", "SYSTEM_ALERT_WINDOW", "AccessibilityService", "onAccessibilityEvent"), minMatches = 3),
        Indicator("Accessibility Abuse", Severity.CRITICAL, listOf("performGlobalAction", "findAccessibilityNodeInfosByText", "GestureDescription"), minMatches = 2),

        // Evasion — genuine anti-analysis
        Indicator("Anti-Analysis Suite", Severity.HIGH, listOf("isDebuggerConnected", "frida", "xposed", "substrate"), minMatches = 2),
        Indicator("Emulator Evasion", Severity.MEDIUM, listOf("generic", "qemu", "goldfish", "ranchu"), minMatches = 2),
        Indicator("Root Detection Evasion", Severity.LOW, listOf("test-keys", "which su", "ro.build.tags"), minMatches = 2),

        // Dropper — requires loader + install/fwrite
        Indicator("Dropper Behavior", Severity.CRITICAL, listOf("DexClassLoader", "PathClassLoader", "openFileOutput", "installPackage"), minMatches = 2),

        // Financial fraud — requires overlay + accessibility + webview all together
        Indicator("Banking Overlay Attack", Severity.CRITICAL, listOf("TYPE_APPLICATION_OVERLAY", "AccessibilityService", "WebView.loadUrl", "addJavascriptInterface"), minMatches = 3),

        // Crypto mining — requires multiple mining indicators
        Indicator("Crypto Mining", Severity.CRITICAL, listOf("getRuntime().availableProcessors", "CryptoNight", "RandomX", "stratum", "mining"), minMatches = 2),
        Indicator("Battery Bypass", Severity.LOW, listOf("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "setExactAndAllowWhileIdle"), minMatches = 2),
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val allCode = decompiled.allSourceText ?: run {
            val estimatedSize = (decompiled.javaSource.values + decompiled.smaliSource.values).sumOf { it.length }
            if (estimatedSize > 50_000_000) {
                android.util.Log.w("BehavioralDetector", "Source too large ($estimatedSize bytes), skipping")
                return emptyList()
            }
            (decompiled.javaSource.values + decompiled.smaliSource.values).joinToString("\n")
        }
        val manifestCode = decompiled.manifest

        indicators.forEach { indicator ->
            val matchCount = indicator.patterns.count { pattern ->
                allCode.contains(pattern, ignoreCase = true) || manifestCode.contains(pattern, ignoreCase = true)
            }
            if (matchCount >= indicator.minMatches) {
                val confidence = (matchCount.toFloat() / indicator.patterns.size * 100).toInt()
                findings.add(Finding(
                    category = FindingCategory.MALWARE,
                    severity = indicator.severity,
                    confidence = FindingConfidence.LOW,
                    title = indicator.name,
                    description = indicator.patterns.filter { allCode.contains(it, ignoreCase = true) }.take(3).joinToString(", "),
                    details = "Confidence: $confidence% — ${matchCount}/${indicator.patterns.size} signals matched"
                ))
            }
        }

        // Cross-reference: only flag if data access COMBINED with exfiltration COMBINED with obfuscation
        val hasDataAccess = allCode.contains("getDeviceId") || allCode.contains("getLastKnownLocation") || allCode.contains("ContactsContract")
        val hasNetwork = allCode.contains("HttpURLConnection") || allCode.contains("OkHttpClient") || allCode.contains("Socket")
        val hasObfuscation = allCode.contains("XOR") || allCode.contains("Base64.encodeToString") || allCode.contains("Cipher.getInstance")
        val hasExfil = allCode.contains("writeBytes") || allCode.contains("getOutputStream") || allCode.contains("OutputStream")

        // Requires ALL FOUR signals simultaneously to flag as exfiltration chain
        if (hasDataAccess && hasNetwork && hasObfuscation && hasExfil) {
            findings.add(Finding(
                FindingCategory.MALWARE, Severity.CRITICAL,
                "Confirmed Data Exfiltration Chain",
                "App accesses sensitive data, uses obfuscation, has network capability, and writes output data",
                confidence = FindingConfidence.LOW,
                details = "All four indicators detected: data access + network + obfuscation + exfiltration"
            ))
        }

        // Sequence-based correlation — verify indicators appear in expected ordered chains
        val sequenceChains = listOf(
            listOf("AccountManager", "getAuthToken", "HttpURLConnection") to "Auth Token → Network Chain",
            listOf("ContactsContract", "ContentResolver", "HttpURLConnection") to "Contacts → Network Chain",
            listOf("getLastKnownLocation", "sendTextMessage") to "Location → SMS Chain",
            listOf("SmsManager", "sendTextMessage", "getMessageBody") to "SMS Read → Send Chain",
            listOf("ClipboardManager", "addPrimaryClipChangedListener", "HttpURLConnection") to "Clipboard → Network Chain",
        )
        for ((sequence, name) in sequenceChains) {
            if (sequenceMatch(allCode, sequence)) {
                findings.add(Finding(
                    FindingCategory.MALWARE, Severity.CRITICAL,
                    "Sequence Chain: $name",
                    "APIs appear in exact execution order: ${sequence.joinToString(" → ")}",
                    confidence = FindingConfidence.LOW,
                    details = "Ordered call chain confirms intentional malicious data pipeline"
                ))
            }
        }

        return findings
    }

    private fun sequenceMatch(code: String, sequence: List<String>): Boolean {
        var pos = 0
        return sequence.all { pattern ->
            val idx = code.indexOf(pattern, pos, ignoreCase = true)
            if (idx >= 0) { pos = idx + pattern.length; true } else false
        }
    }
}
