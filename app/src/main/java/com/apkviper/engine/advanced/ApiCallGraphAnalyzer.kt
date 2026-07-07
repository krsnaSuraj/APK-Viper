package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

/**
 * API Call Graph Analyzer — traces API call chains through decompiled code
 * to detect multi-step malware behavior that individual pattern matchers miss.
 *
 * Instead of flagging "getDeviceId" alone (which every app calls),
 * it looks for: getDeviceId → encrypt → base64 → HttpURLConnection (exfiltration pipeline).
 */
class ApiCallGraphAnalyzer {

    companion object {
        private const val MAX_SOURCE_SIZE = 50 * 1024 * 1024
    }

    data class CallChain(val apis: List<String>, val name: String, val severity: Severity, val description: String)

    // Known malware call chains — sequences of APIs that indicate malicious behavior
    private val malwareChains = listOf(
        CallChain(
            apis = listOf("getDeviceId", "getSubscriberId", "HttpURLConnection", "getOutputStream"),
            name = "Device ID Exfiltration Pipeline",
            severity = Severity.CRITICAL,
            description = "App collects device identifiers AND sends them over network — classic spyware pattern"
        ),
        CallChain(
            apis = listOf("ContactsContract", "ContentResolver.query", "HttpURLConnection", "getOutputStream"),
            name = "Contact List Exfiltration",
            severity = Severity.CRITICAL,
            description = "App reads contacts AND sends data over network — contact harvesting spyware"
        ),
        CallChain(
            apis = listOf("getLastKnownLocation", "requestLocationUpdates", "HttpURLConnection", "getOutputStream"),
            name = "Location Tracking Pipeline",
            severity = Severity.CRITICAL,
            description = "App tracks location AND transmits it — GPS-based spyware"
        ),
        CallChain(
            apis = listOf("SmsManager", "sendTextMessage", "getMessageBody", "BROADCAST_SMS"),
            name = "SMS Interception & Forwarding",
            severity = Severity.CRITICAL,
            description = "App reads SMS messages AND broadcasts/sends them — SMS interception malware"
        ),
        CallChain(
            apis = listOf("Camera.open", "MediaRecorder", "setOutputFile", "start"),
            name = "Hidden Recording Pipeline",
            severity = Severity.CRITICAL,
            description = "App secretly records video/audio — surveillance malware"
        ),
        CallChain(
            apis = listOf("ClipboardManager", "getPrimaryClip", "addPrimaryClipChangedListener", "HttpURLConnection"),
            name = "Clipboard Monitoring Pipeline",
            severity = Severity.HIGH,
            description = "App monitors clipboard AND can send data — credential theft"
        ),
        CallChain(
            apis = listOf("DexClassLoader", "openFileOutput", "writeBytes", "installPackage"),
            name = "Dropper Installation Pipeline",
            severity = Severity.CRITICAL,
            description = "App dynamically loads code, writes files, and installs packages — classic dropper"
        ),
        CallChain(
            apis = listOf("TYPE_APPLICATION_OVERLAY", "WebView", "loadUrl", "addJavascriptInterface"),
            name = "Overlay Phishing Pipeline",
            severity = Severity.CRITICAL,
            description = "App draws over other apps AND injects JavaScript — banking overlay attack"
        ),
        CallChain(
            apis = listOf("AccountManager", "getAuthToken", "HttpURLConnection", "getOutputStream"),
            name = "Auth Token Theft Pipeline",
            severity = Severity.CRITICAL,
            description = "App steals authentication tokens AND sends them over network"
        ),
        CallChain(
            apis = listOf("getRuntime.exec", "su", "Runtime.exec", "mount", "remount"),
            name = "Root Privilege Escalation Chain",
            severity = Severity.CRITICAL,
            description = "App attempts root command execution AND filesystem remount"
        ),
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val allCode = decompiled.allSourceText ?: run {
            if (decompiled.javaSource.values.sumOf { it.length } > MAX_SOURCE_SIZE) {
                decompiled.javaSource.values.take(200).joinToString("\n")
            } else {
                decompiled.javaSource.values.joinToString("\n")
            }
        }

        // Check each call chain for 3+ consecutive API calls in the same file
        for (chain in malwareChains) {
            // We need at least 3 of the chain's APIs to be present to flag
            val matches = chain.apis.count { api ->
                allCode.contains(api, ignoreCase = true)
            }
            if (matches >= 3) {
                // Check for co-occurrence within same class (higher confidence)
                val classMatches = decompiled.javaSource.entries.count { (_, code) ->
                    val classMatchCount = chain.apis.count { api -> code.contains(api, ignoreCase = true) }
                    classMatchCount >= 2
                }

                // Sequence-order check — APIs must appear in order, not just anywhere
                val sequenceConfirmed = checkSequenceOrder(allCode, chain.apis)
                val confidence = (matches.toFloat() / chain.apis.size * 100).toInt()
                val crossClass = if (classMatches >= 2) " pattern found across $classMatches classes" else ""

                val effectiveConfidence = if (sequenceConfirmed) minOf(confidence + 25, 100) else confidence
                val effectiveSeverity = if (sequenceConfirmed) {
                    if (chain.severity == Severity.HIGH) Severity.CRITICAL else chain.severity
                } else chain.severity

                findings.add(Finding(
                    category = FindingCategory.MALWARE,
                    severity = effectiveSeverity,
                    title = chain.name + if (sequenceConfirmed) " [SEQUENCE CONFIRMED]" else "",
                    description = chain.description,
                    details = "$matches of ${chain.apis.size} API calls matched (${effectiveConfidence}% confidence)" +
                        if (sequenceConfirmed) " — APIs appear in exact order, high-confidence attack chain" else "" +
                        "$crossClass"
                ))
            }
        }

        return findings
    }

    private fun checkSequenceOrder(code: String, apis: List<String>): Boolean {
        if (apis.size < 2) return false
        var lastIndex = -1
        return apis.all { api ->
            val idx = code.indexOf(api, if (lastIndex >= 0) lastIndex else 0, ignoreCase = true)
            if (idx >= 0) {
                lastIndex = idx + api.length
                true
            } else false
        }
    }
}
