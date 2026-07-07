package com.apkviper.engine.advanced

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class BackgroundResourceMonitor {

    data class ServiceProfile(
        val name: String,
        val isExported: Boolean,
        val hasForegroundType: Boolean,
        val hasStopWithTask: Boolean,
        val intentFilters: List<String>,
        val rawXml: String
    )

    fun analyze(
        manifestXml: String,
        requestedPermissions: List<String>,
        services: List<ServiceProfile>,
        receivers: List<String>
    ): List<Finding> {
        val findings = mutableListOf<Finding>()
        val normalizedPerms = requestedPermissions.map { it.removePrefix("android.permission.") }.toSet()

        val hasWakeLock = normalizedPerms.any { it == "WAKE_LOCK" }
        val hasBoot = normalizedPerms.any { it == "RECEIVE_BOOT_COMPLETED" }
        val hasDataSync = normalizedPerms.any { it == "FOREGROUND_SERVICE_DATA_SYNC" }
        val hasNetwork = normalizedPerms.any { it == "INTERNET" } || normalizedPerms.any { it == "ACCESS_NETWORK_STATE" }
        val hasVibrate = normalizedPerms.any { it == "VIBRATE" }
        val hasAlarm = normalizedPerms.any { it == "SET_ALARM" }
        val hasPackageInstall = normalizedPerms.any { it == "REQUEST_INSTALL_PACKAGES" }

        // 1. Excessive background services
        if (services.size >= 5 && hasNetwork) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.MEDIUM,
                title = "High Service Count",
                description = "${services.size} background services with network access. Potential resource abuse for mining/ad-fraud."
            ))
        }

        // 2. START_STICKY service pattern detection
        val stickyServices = services.filter { it.rawXml.contains("START_STICKY", ignoreCase = true) }
        if (stickyServices.isNotEmpty()) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = if (stickyServices.size >= 3) Severity.HIGH else Severity.MEDIUM,
                title = "Sticky Services Detected",
                description = "${stickyServices.size} services use START_STICKY — persist after being killed. Common in crypto-miners and ad-fraud."
            ))
        }

        // 3. Wakelock + boot + network = persistent miner/clicker profile
        if (hasWakeLock && hasBoot && hasNetwork) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.HIGH,
                title = "Persistent Background Worker",
                description = "Keeps CPU awake on boot with network. Crypto-miner or click-fraud signature."
            ))
        }

        // 4. Wakelock + vibrate + network (common click-fraud pattern)
        if (hasWakeLock && hasVibrate && hasNetwork && services.size >= 2) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.MEDIUM,
                title = "Click Fraud Indicators",
                description = "Wakelock + vibrate + network + multiple services. Automated click/mobile ad-fraud pattern."
            ))
        }

        // 5. Data sync foreground service without user-visible notification
        if (hasDataSync && services.isNotEmpty()) {
            val syncServices = services.filter { it.hasForegroundType && it.rawXml.contains("dataSync", ignoreCase = true) }
            if (syncServices.size >= 2) {
                findings.add(Finding(
                    category = FindingCategory.MANIFEST,
                    severity = Severity.MEDIUM,
                    title = "Data Sync Abuse",
                    description = "${syncServices.size} data-sync foreground services. Background data exfiltration vector."
                ))
            }
        }

        // 6. Battery optimization bypass: alarm + wakelock + network
        if (hasAlarm && hasWakeLock && hasNetwork) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.HIGH,
                title = "Battery Optimization Bypass",
                description = "Uses alarms + wakelock + network to bypass battery optimization. Persistent background operation."
            ))
        }

        // 7. Boot receivers with many services
        val bootReceivers = receivers.count {
            it.contains("BOOT_COMPLETED", ignoreCase = true)
        }
        if (bootReceivers >= 2 && services.size >= 3) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.HIGH,
                title = "Multi-Receiver Boot Hooks",
                description = "$bootReceivers boot receivers with ${services.size} services. Designed for stealth persistence."
            ))
        }

        // 8. Exported services without proper protection
        val exportedServices = services.filter { it.isExported }
        if (exportedServices.size >= 3 && !hasBoot) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.MEDIUM,
                title = "Exported Services Exposure",
                description = "${exportedServices.size} exported services with no obvious protection. External apps can bind to them."
            ))
        }

        // 9. Install packages + boot = dropper persistence
        if (hasPackageInstall && hasBoot) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.CRITICAL,
                title = "Auto-Install Dropper",
                description = "Can install packages on boot. Self-reinstalling malware or staged payload dropper."
            ))
        }

        // 10. Very high service-to-activity ratio
        val activityCount = Regex("""<activity""").findAll(manifestXml).count()
        if (services.size > activityCount * 2 && services.size >= 4) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.MEDIUM,
                title = "Service-Dominant Architecture",
                description = "${services.size} services vs $activityCount activities. App is primarily background workers with minimal UI."
            ))
        }

        return findings
    }

}
