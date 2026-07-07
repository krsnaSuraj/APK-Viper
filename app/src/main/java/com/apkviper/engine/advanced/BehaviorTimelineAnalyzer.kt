package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class BehaviorTimelineAnalyzer {

    data class BehaviorChain(val name: String, val steps: List<String>, val severity: Severity)

    private val chains = listOf(
        BehaviorChain("Boot Persistence → Network → Data Exfil", listOf(
            "RECEIVE_BOOT_COMPLETED", "INTERNET", "READ_EXTERNAL_STORAGE"
        ), Severity.HIGH),
        BehaviorChain("SMS Interception → Network → Process Data", listOf(
            "RECEIVE_SMS", "INTERNET", "SEND_SMS"
        ), Severity.CRITICAL),
        BehaviorChain("Camera → Network → Storage Write", listOf(
            "CAMERA", "INTERNET", "WRITE_EXTERNAL_STORAGE"
        ), Severity.HIGH),
        BehaviorChain("Microphone → Network → Background", listOf(
            "RECORD_AUDIO", "INTERNET", "RECEIVE_BOOT_COMPLETED"
        ), Severity.CRITICAL),
        BehaviorChain("Location → Network → Foreground Service", listOf(
            "ACCESS_FINE_LOCATION", "INTERNET", "FOREGROUND_SERVICE"
        ), Severity.HIGH),
        BehaviorChain("Contacts → Network → SMS Send", listOf(
            "READ_CONTACTS", "INTERNET", "SEND_SMS"
        ), Severity.CRITICAL),
        BehaviorChain("Install Packages → Boot → Network", listOf(
            "REQUEST_INSTALL_PACKAGES", "RECEIVE_BOOT_COMPLETED", "INTERNET"
        ), Severity.HIGH),
        BehaviorChain("Overlay → Accessibility → Network", listOf(
            "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "INTERNET"
        ), Severity.CRITICAL),
        BehaviorChain("Notification Listener → Network → Boot", listOf(
            "BIND_NOTIFICATION_LISTENER_SERVICE", "INTERNET", "RECEIVE_BOOT_COMPLETED"
        ), Severity.HIGH),
        BehaviorChain("Account Manager → Network → SMS", listOf(
            "GET_ACCOUNTS", "INTERNET", "SEND_SMS"
        ), Severity.MEDIUM)
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val manifest = decompiled.manifest.lowercase()
        val javaSource = decompiled.allSourceText?.lowercase() ?: run {
            val estimatedSize = decompiled.javaSource.values.sumOf { it.length }
            if (estimatedSize > 50_000_000) {
                android.util.Log.w("BehaviorTimelineAnalyzer", "Source too large ($estimatedSize bytes), skipping")
                return emptyList()
            }
            decompiled.javaSource.values.joinToString(" ").lowercase()
        }

        for (chain in chains) {
            val manifestMatches = chain.steps.count { step ->
                val perm = "android.permission.${step.lowercase()}"
                manifest.contains(perm) || manifest.contains(step.lowercase())
            }
            val apiMatches = chain.steps.count { step ->
                when (step) {
                    "INTERNET" -> javaSource.contains("httpurlconnection") || javaSource.contains("okhttp") ||
                        javaSource.contains("socket(") || javaSource.contains("url.openconnection")
                    "SEND_SMS" -> javaSource.contains("sendtextmessage") || javaSource.contains("smssender")
                    "RECEIVE_SMS" -> javaSource.contains("smsreceiver") || javaSource.contains("onreceive")
                    "FOREGROUND_SERVICE" -> javaSource.contains("startforeground")
                    "WRITE_EXTERNAL_STORAGE" -> javaSource.contains("fileoutputstream") || javaSource
                        .contains("outputstream")
                    "REQUEST_INSTALL_PACKAGES" -> javaSource.contains("installpackage")
                    "ACCESS_FINE_LOCATION" -> javaSource.contains("locationmanager") || javaSource.contains("fusedlocation")
                    "READ_CONTACTS" -> javaSource.contains("contentresolver") && javaSource.contains("contacts")
                    "CAMERA" -> javaSource.contains("camera.open") || javaSource.contains("mediarecorder")
                    "RECORD_AUDIO" -> javaSource.contains("audiorecord") || javaSource.contains("mediarecorder.audio")
                    "SYSTEM_ALERT_WINDOW" -> javaSource.contains("windowmanager") || javaSource.contains("addview")
                    "BIND_ACCESSIBILITY_SERVICE" -> javaSource.contains("accessibilityservice") || javaSource.contains("onaccessibilityevent")
                    "BIND_NOTIFICATION_LISTENER_SERVICE" -> javaSource.contains("notificationlistener") || javaSource.contains("onnotificationposted")
                    "GET_ACCOUNTS" -> javaSource.contains("accountmanager") || javaSource.contains("getaccounts")
                    else -> false
                }
            }
            val total = manifestMatches + apiMatches
            if (total >= chain.steps.size) {
                findings.add(Finding(
                    category = FindingCategory.BEHAVIORAL,
                    severity = chain.severity,
                    title = "Behavior Chain: ${chain.name}",
                    description = "Matched ${total}/${chain.steps.size} steps: ${chain.steps.joinToString(" → ")}"
                ))
            }
        }

        return findings
    }
}
