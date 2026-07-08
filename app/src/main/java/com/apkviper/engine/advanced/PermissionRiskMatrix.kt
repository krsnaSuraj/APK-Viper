package com.apkviper.engine.advanced

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class PermissionRiskMatrix {

    data class ComboPattern(
        val permissions: Set<String>,
        val riskLabel: String,
        val description: String,
        val score: Int,  // 0-100 risk contribution
        val severity: Severity
    )

    private val dangerousCombos = listOf(
        // Privacy harvesters
        ComboPattern(setOf("READ_SMS", "RECEIVE_BOOT_COMPLETED", "INTERNET"),
            "SMS Harvester", "Reads SMS on boot and sends via network. Classic spyware pattern.", 95, Severity.CRITICAL),
        ComboPattern(setOf("READ_CONTACTS", "INTERNET", "READ_PHONE_STATE"),
            "Contact Exfiltration", "Reads contacts and phone state with network access. Data harvesting.", 85, Severity.HIGH),
        ComboPattern(setOf("ACCESS_FINE_LOCATION", "INTERNET", "RECEIVE_BOOT_COMPLETED"),
            "Boot-time Location Tracker", "Tracks location on device start and exfiltrates. Stalkerware indicator.", 90, Severity.HIGH),
        ComboPattern(setOf("CAMERA", "RECORD_AUDIO", "INTERNET"),
            "A/V Surveillance", "Access camera and mic simultaneously with network. Surveillance risk.", 88, Severity.HIGH),
        ComboPattern(setOf("READ_CALL_LOG", "READ_SMS", "INTERNET"),
            "Communication Intercept", "Reads call logs and SMS with network access. Comms interception.", 92, Severity.CRITICAL),
        ComboPattern(setOf("READ_EXTERNAL_STORAGE", "INTERNET", "RECEIVE_BOOT_COMPLETED"),
            "Storage Scraper", "Reads storage on boot with network. File exfiltration.", 75, Severity.MEDIUM),
        ComboPattern(setOf("ACCESS_COARSE_LOCATION", "ACCESS_FINE_LOCATION", "CAMERA", "RECORD_AUDIO"),
            "Full Surveillance Suite", "Location + camera + mic. Complete surveillance capability.", 98, Severity.CRITICAL),

        // Financial fraud
        ComboPattern(setOf("READ_SMS", "INTERNET", "SEND_SMS"),
            "SMS Fraud Relay", "Reads and sends SMS with internet. Banking OTP interception.", 96, Severity.CRITICAL),
        ComboPattern(setOf("RECEIVE_SMS", "SEND_SMS", "READ_PHONE_STATE"),
            "SMS Manipulation", "Sends/receives SMS and reads phone state. Toll fraud indicator.", 88, Severity.HIGH),
        ComboPattern(setOf("SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"),
            "Overlay Attack", "Draws overlays with accessibility control. Banking overlay Trojan.", 99, Severity.CRITICAL),
        ComboPattern(setOf("BIND_ACCESSIBILITY_SERVICE", "INTERNET"),
            "Accessibility Keylogger", "Accessibility service with network. Keystroke interception.", 95, Severity.CRITICAL),

        // Remote access / RAT
        ComboPattern(setOf("INTERNET", "ACCESS_NETWORK_STATE", "CAMERA", "RECORD_AUDIO", "READ_EXTERNAL_STORAGE"),
            "Full RAT Capability", "Remote access with camera, mic, storage. Complete device control.", 97, Severity.CRITICAL),
        ComboPattern(setOf("INTERNET", "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE"),
            "Network Manipulator", "Reads and modifies Wi-Fi state. MITM capability.", 70, Severity.MEDIUM),
        ComboPattern(setOf("PROCESS_OUTGOING_CALLS", "READ_PHONE_STATE", "INTERNET"),
            "Call Interception", "Intercepts outgoing calls with network. Call monitoring.", 82, Severity.HIGH),

        // Persistence
        ComboPattern(setOf("RECEIVE_BOOT_COMPLETED", "WAKE_LOCK", "FOREGROUND_SERVICE"),
            "Persistent Background Agent", "Auto-starts on boot with wakelock and foreground service. Hard to kill.", 78, Severity.HIGH),
        ComboPattern(setOf("RECEIVE_BOOT_COMPLETED", "REQUEST_INSTALL_PACKAGES", "INTERNET"),
            "Auto-Update Dropper", "Starts on boot and installs packages. Dropper/loader pattern.", 93, Severity.CRITICAL),
        ComboPattern(setOf("WRITE_SETTINGS", "SYSTEM_ALERT_WINDOW", "RECEIVE_BOOT_COMPLETED"),
            "System Hijack", "Modifies settings and overlays on boot. OS subversion.", 94, Severity.CRITICAL),

        // Privacy invasive (low-medium severity)
        ComboPattern(setOf("READ_CONTACTS", "READ_SMS", "READ_CALL_LOG"),
            "Address Book Harvest", "Reads all communication records. Full contact exfiltration possible.", 70, Severity.MEDIUM),
        ComboPattern(setOf("ACCESS_FINE_LOCATION", "CAMERA", "READ_EXTERNAL_STORAGE"),
            "Geo-tagged Media", "Location + camera + storage. Geo-tagged photo/video collection.", 65, Severity.MEDIUM),

        // Banking Trojans (Anubis, Cerberus, etc.)
        ComboPattern(setOf("BIND_ACCESSIBILITY_SERVICE", "SEND_SMS", "READ_CONTACTS", "INTERNET"),
            "Banking Trojan Profile", "Accessibility + SMS + contacts + network. Classic banking trojan stack (Anubis/Cerberus pattern).", 99, Severity.CRITICAL),
        ComboPattern(setOf("BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "SEND_SMS"),
            "Overlay SMS Trojan", "Accessibility overlay + SMS sending. OTP theft via overlay.", 98, Severity.CRITICAL),
        ComboPattern(setOf("READ_SMS", "SEND_SMS", "BIND_ACCESSIBILITY_SERVICE", "RECEIVE_BOOT_COMPLETED"),
            "Persistent SMS Trojan", "Persistent SMS read/send with accessibility. Auto-start banking trojan.", 97, Severity.CRITICAL),
        ComboPattern(setOf("BIND_NOTIFICATION_LISTENER_SERVICE", "SEND_SMS", "INTERNET"),
            "Notification SMS Grabber", "Reads notifications and SMS. OTP interception via notification listener.", 93, Severity.CRITICAL),
        ComboPattern(setOf("MANAGE_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES", "INTERNET"),
            "Storage Dropper", "Full storage access + install packages + network. Malware downloader.", 95, Severity.CRITICAL),

        // Crypto/ads
        ComboPattern(setOf("WAKE_LOCK", "FOREGROUND_SERVICE", "INTERNET", "ACCESS_NETWORK_STATE"),
            "Persistent Network Worker", "Keeps device awake with network access. Crypto-miner or ad-fraud.", 80, Severity.HIGH),
        ComboPattern(setOf("RECEIVE_BOOT_COMPLETED", "WAKE_LOCK", "VIBRATE", "INTERNET"),
            "Background CPU Consumer", "Boot-start with wakelock. Sustained background operation.", 72, Severity.MEDIUM),
        ComboPattern(setOf("ACCESS_FINE_LOCATION", "INTERNET", "RECEIVE_BOOT_COMPLETED", "CAMERA", "RECORD_AUDIO"),
            "Stalkerware Suite", "Location + camera + mic + boot + network. Complete stalkerware indicator.", 98, Severity.CRITICAL),
        ComboPattern(setOf("SEND_SMS", "RECEIVE_SMS", "READ_SMS", "INTERNET"),
            "SMS Relay Hub", "Full SMS control with network. Premium SMS fraud or SMS forwarder.", 94, Severity.CRITICAL),
        ComboPattern(setOf("MANAGE_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION", "CAMERA", "INTERNET"),
            "Media Exfiltration Suite", "Storage + location + camera. Full media theft capability.", 88, Severity.HIGH),
    )

    fun analyze(requestedPermissions: List<String>, exportedServiceCount: Int, appPurpose: String = "GENERAL"): List<Finding> {
        val findings = mutableListOf<Finding>()
        val permSet = requestedPermissions.map { it.trim() }.toSet()
        val normalizedSet = permSet.map { it.removePrefix("android.permission.") }.toSet()

        for (combo in dangerousCombos) {
            // Adaptive: skip known-safe combos for genuine app purposes
            when (appPurpose) {
                "FILE_MANAGER" -> if (combo.riskLabel == "Storage Dropper") continue
                "CAMERA_APP" -> if (combo.riskLabel == "A/V Surveillance") continue
                "BROWSER" -> if (combo.riskLabel == "Network Manipulator") continue
            }

            val normalizedCombo = combo.permissions.map { it.removePrefix("android.permission.") }
            val matchCount = normalizedCombo.count { it in normalizedSet }
            // Require at least 3/4 of the combo, or all if combo <= 3
            val threshold = if (normalizedCombo.size <= 3) normalizedCombo.size else (normalizedCombo.size * 0.75).toInt().coerceAtLeast(2)
            if (matchCount >= threshold) {
                // Downgrade severity one level if match is exactly at minimum threshold (partial overlap)
                val severity = if (matchCount == threshold && normalizedCombo.size > 3) {
                    when (combo.severity) {
                        Severity.CRITICAL -> Severity.HIGH
                        Severity.HIGH -> Severity.MEDIUM
                        Severity.MEDIUM -> Severity.LOW
                        else -> Severity.INFO
                    }
                } else {
                    combo.severity
                }
                findings.add(Finding(
                    category = FindingCategory.MANIFEST,
                    severity = severity,
                    title = combo.riskLabel,
                    description = "${combo.description} | Matched ${matchCount}/${normalizedCombo.size} permissions"
                ))
            }
        }

        // Standalone dangerous permission multipliers
        val highRiskSingles = listOf("BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
            "REQUEST_INSTALL_PACKAGES", "WRITE_SETTINGS", "BIND_DEVICE_ADMIN")
        val singleMatches = highRiskSingles.count { it in normalizedSet }

        if (singleMatches > 0) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = if (singleMatches >= 2) Severity.HIGH else Severity.MEDIUM,
                title = "Privileged Permission Usage",
                description = "Uses $singleMatches high-privilege permissions without additional context"
            ))
        }

        // Lot of permissions with many services = suspicious
        if (requestedPermissions.size >= 15 && exportedServiceCount >= 5) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.MEDIUM,
                title = "Over-privileged App",
                description = "${requestedPermissions.size} permissions with $exportedServiceCount exported services"
            ))
        }

        return findings
    }

    fun getPrivacyRiskScore(findings: List<Finding>): Int {
        val matrixFindings = findings.filter { it.category == FindingCategory.MANIFEST &&
            (it.title.contains("SMS") || it.title.contains("Contact") || it.title.contains("Location") ||
             it.title.contains("Surveillance") || it.title.contains("Harvest") || it.title.contains("Overlay") ||
             it.title.contains("Accessibility") || it.title.contains("RAT") || it.title.contains("Fraud")) }
        if (matrixFindings.isEmpty()) return 0
        var total = 0
        for (f in matrixFindings) {
            total += when(f.severity) { Severity.CRITICAL -> 35; Severity.HIGH -> 25; Severity.MEDIUM -> 15; else -> 5 }
        }
        return total.coerceIn(0, 100)
    }
}
