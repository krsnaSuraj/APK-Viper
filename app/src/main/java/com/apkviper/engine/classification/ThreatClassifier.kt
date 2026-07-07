package com.apkviper.engine.classification

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

data class ClassificationResult(
    val classification: String? = null,
    val remediations: List<String> = emptyList()
)

class ThreatClassifier {

    fun classify(findings: List<Finding>): ClassificationResult {
        val classification = classifyThreatType(findings)
        val remediations = generateRemediations(findings, classification)
        return ClassificationResult(classification, remediations)
    }

    private fun classifyThreatType(findings: List<Finding>): String? {
        var score = 0
        for (finding in findings) {
            score += when (finding.severity) {
                Severity.CRITICAL -> 10; Severity.HIGH -> 6; Severity.MEDIUM -> 3; Severity.LOW -> 1; else -> 0
            }
        }
        if (score < 5) return null

        val titles = findings.map { it.title.lowercase() }.toSet()
        val categories = findings.map { it.category }.toSet()

        // Ransomware / Storage Encrypter
        val hasFileCoder = titles.any { it.contains("filecoder") || it.contains("ransom") }
        // Entropy value starting with "7." indicates high entropy associated with encrypted payloads
        val hasHighEntropy = titles.any { it.contains("entropy") && it.contains("7.") }
        val hasMprotect = findings.any { f ->
            f.description.lowercase().contains("mprotect") || f.title.lowercase().contains("mprotect")
        }
        if (hasFileCoder || (hasHighEntropy && hasMprotect)) {
            return "Ransomware / Storage Encrypter — this payload likely encrypts local files and demands payment"
        }

        // Reverse Shell / RCE — requires same finding to have both connectivity and system execution
        val rceFinding = findings.any { f ->
            val t = f.title.lowercase()
            val d = f.description.lowercase()
            val hasConnect = d.contains("connect") || t.contains("socket") || t.contains("connect")
            val hasSystem = d.contains("system") || t.contains("exec") || t.contains("command")
            val hasNativeExec = t.contains("dlopen") || t.contains("dlsym") || t.contains("native library")
            hasConnect && (hasSystem || hasNativeExec)
        }
        if (rceFinding) {
            return "Remote Access Trojan (RAT) / Reverse Shell — enables remote command execution on the device"
        }

        // Banking Trojan — requires same finding to show both overlay attack and SMS interception
        val bankingFinding = findings.any { f ->
            val t = f.title.lowercase()
            val d = f.description.lowercase()
            val hasOverlay = f.category == FindingCategory.PACKER && (t.contains("overlay") || t.contains("phishing"))
            val hasSmsPerms = d.contains("sms") || t.contains("sms")
            hasOverlay && hasSmsPerms
        }
        if (bankingFinding) {
            return "Banking Trojan — uses overlay attacks to steal credentials and intercepts SMS for 2FA bypass"
        }

        // Spyware / Stalkerware — requires same finding to show surveillance + persistence
        val spywareFinding = findings.any { f ->
            val t = f.title.lowercase()
            val hasLocation = t.contains("location") || t.contains("track")
            val hasCamera = t.contains("camera") || t.contains("record_audio") || t.contains("mic")
            val hasBoot = t.contains("boot")
            (hasLocation || hasCamera) && hasBoot
        }
        if (spywareFinding) {
            return "Spyware / Stalkerware — surveils location, camera, or microphone with boot persistence"
        }

        // Data Exfiltrator — requires same finding to show network + storage concern
        val dataExfilFinding = findings.any { f ->
            f.category == FindingCategory.NETWORK && (f.title.lowercase().contains("read_external") || f.title.lowercase().contains("storage"))
        }
        if (dataExfilFinding) {
            return "Data Exfiltration Trojan — reads local files and transmits via network"
        }

        // Dropper / Downloader — requires same finding to show dex loading + install capability
        val dropperFinding = findings.any { f ->
            val t = f.title.lowercase()
            val d = f.description.lowercase()
            val hasDexLoader = t.contains("dex class loader") || t.contains("dynamic dex")
            val hasInstallPerms = d.contains("install_packages") || t.contains("install_pack")
            hasDexLoader && hasInstallPerms
        }
        if (dropperFinding) {
            return "Dropper / Downloader — downloads and installs additional payloads from remote servers"
        }

        // Keylogger / Clipper — requires same finding to show accessibility + clipboard monitoring
        val keyloggerFinding = findings.any { f ->
            val t = f.title.lowercase()
            val d = f.description.lowercase()
            val hasAccessibilityService = t.contains("accessibilityservice") || t.contains("event")
            val hasClipboard = d.contains("clipboard") || t.contains("clipboard")
            hasAccessibilityService && hasClipboard
        }
        if (keyloggerFinding) {
            return "Keylogger / Clipboard Hijacker — monitors input events and clipboard content for credential theft"
        }

        // DNS/Tunnel C2
        val hasDnsTunnel = titles.any { it.contains("dns") && it.contains("tunnel") }
        val hasC2Infra = titles.any { it.contains("c2") || it.contains("command") }
        if (hasDnsTunnel || hasC2Infra) {
            return "C2-Enabled Backdoor — maintains persistent command channel to attacker infrastructure"
        }

        // Generic malware — use severity score
        return when {
            score >= 30 -> "Malicious Payload — multiple high-severity indicators detected across ${categories.size} analysis categories"
            score >= 15 -> "Suspicious Application — anomalous behavior warrants further investigation"
            else -> null
        }
    }

    private fun generateRemediations(findings: List<Finding>, @Suppress("UNUSED_PARAMETER") classification: String?): List<String> {
        val titles = findings.map { it.title.lowercase() }.toSet()
        val descriptions = findings.map { it.description.lowercase() }.joinToString(" ")
        val categories = findings.map { it.category }.toSet()
        val criticalCount = findings.count { it.severity == Severity.CRITICAL }

        val remediations = mutableListOf<String>()

        // OS-level persistence
        val hasBootReceiver = titles.any { it.contains("boot") } || descriptions.contains("receive_boot_completed")
        if (hasBootReceiver) {
            remediations.add("This app establishes boot persistence. Do not just close it — clear app data, then perform full uninstallation via Settings > Apps.")
        }

        // Device admin abuse
        if (titles.any { it.contains("device admin") || it.contains("devicepolicy") }) {
            remediations.add("The app has device admin privileges. Revoke admin access in Settings > Security > Device admin apps BEFORE uninstalling.")
        }

        // Accessibility abuse
        if (titles.any { it.contains("accessibility") }) {
            remediations.add("This app abuses Accessibility Service. Disable it in Settings > Accessibility before uninstalling.")
        }

        // Network C2
        val hasC2 = categories.contains(FindingCategory.NETWORK) && criticalCount > 0
        if (hasC2 || descriptions.contains("c2")) {
            remediations.add("Network isolation recommended — enable airplane mode, then revoke network permissions before removing the app.")
        }

        // Dynamic loading
        if (titles.any { it.contains("dynamic dex") || it.contains("dex class loader") } || descriptions.contains("dexclassloader")) {
            remediations.add("Performs runtime code loading. Clear app cache/data AND uninstall — cached payloads may persist after removal.")
        }

        // Native library tampering
        if (titles.any { it.contains("encrypted native") || it.contains("native payload") || it.contains("unpacking") }) {
            remediations.add("Contains encrypted native payload with unpacking stubs. Wipe the device if sensitive data was accessible to this app.")
        }

        // SMS interception
        if (descriptions.contains("read_sms") || descriptions.contains("receive_sms")) {
            remediations.add("Can intercept SMS messages (including 2FA codes). Change passwords for all accounts accessed on this device.")
        }

        // Location tracking
        if (titles.any { it.contains("location") } || descriptions.contains("access_fine_location")) {
            remediations.add("Tracks device location. Check account login history for unauthorized access to location-linked services.")
        }

        // Overlay / Phishing
        if (titles.any { it.contains("overlay") || it.contains("phishing") }) {
            remediations.add("Uses screen overlay to steal credentials. Change passwords for all apps that were used while this app was installed.")
        }

        // General high-severity
        val highCount = findings.count { it.severity == Severity.HIGH }
        if (criticalCount >= 2 || (criticalCount + highCount) >= 5) {
            if (remediations.isEmpty()) {
                remediations.add("Multiple critical security indicators. Consider factory reset if sensitive data (passwords, financial info) was accessible.")
            }
        }

        // Always include basic step
        val appName = findings.firstOrNull()?.let { f ->
            f.title.substringBefore(" — ").take(30)
        } ?: "this app"
        remediations.add("Uninstall immediately via Settings > Apps > \"$appName\" > Uninstall.")

        return remediations.distinct().take(5)
    }
}
