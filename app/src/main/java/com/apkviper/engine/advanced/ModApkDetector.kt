package com.apkviper.engine.advanced

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

class ModApkDetector {

    data class ModRiskAssessment(
        val riskScore: Int,
        val repackaged: Boolean,
        val newPermissions: List<String>,
        val newComponents: List<String>,
        val newDangerousApis: List<String>,
        val newNativeLibs: List<String>,
        val suggestion: String
    )

    data class CrossValidationResult(
        val indicatorTypes: Set<String>,
        val hasMixedIndicators: Boolean,
        val corroboratingFindings: List<String>,
        val contradictoryFindings: List<String>
    )

    companion object {
        private val DEBUG_KEY_FINGERPRINTS = setOf(
            "0AA07C0F297B4AE834DC85A17EEA8C2CF9380FF7",
            "3CEF14D21B5B7E103B3DAB6BDC1C69349F5F3A5E",
            "F39548B469B4B115B91FC74CBFE8F2BBA6E75B22",
            "5019C87C7B3EEEE8DC251535A0E9FD1D1F08A584",
            "61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81",
            "A40DA80A59D170CAA950CF15C18C454D47A39B26",
        )

        private val WHITELISTED_MOD_PACKAGES = setOf(
            "com.apkpure.aegon",
            "com.apkmirror.helper",
            "com.android.vending",
            "com.aurora.store",
            "com.aurora.adroid",
            "com.fdroid.fdroid",
            "com.fdroid.fdroid.gadget",
            "org.fdroid.fdroid",
            "com.android.vending.billing.InAppBillingService",
            "com.lucky.luckygames",
            "com.luckypatcher",
            "com.lps.modpatcher",
            "com.chelpus.lackypatch",
            "com.modxda.games",
            "com.platinmods",
            "com.andnix.modpatcher",
            "com.dimonvideo.luckypatcher",
            "com.android.modding",
        )

        // Package patterns that indicate legitimate mod platforms (not malware)
        private val LEGIT_MOD_PACKAGE_PATTERNS = listOf(
            Regex("""com\.(apkpure|apkmirror|aurora|fdroid|luckypatcher|platinmods)\..*""", RegexOption.IGNORE_CASE),
            Regex(""".*\.(mod|patch|patcher)""", RegexOption.IGNORE_CASE),
        )

        // Signature patterns for known legitimate mod distributors
        private val KNOWN_GOOD_MOD_SIGNERS = setOf(
            "APKPure", "APKMirror", "Aurora Store", "F-Droid",
        )

        private val DANGEROUS_PERMISSION_MARKERS = listOf(
            "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "READ_CONTACTS",
            "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION", "BIND_ACCESSIBILITY_SERVICE",
            "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
            "BIND_NOTIFICATION_LISTENER_SERVICE",
            "MANAGE_EXTERNAL_STORAGE", "WRITE_SETTINGS"
        )

        private val HARMLESS_PERMISSIONS = setOf(
            "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
            "VIBRATE", "WAKE_LOCK", "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
        )

        private val DANGEROUS_API_CLASSES = listOf(
            "Landroid/telephony/TelephonyManager;->getDeviceId",
            "Landroid/telephony/TelephonyManager;->getSubscriberId",
            "Landroid/telephony/SmsManager;->sendTextMessage",
            "Ljava/lang/Runtime;->exec",
            "Ldalvik/system/DexClassLoader;-><init>",
            "Ldalvik/system/PathClassLoader;-><init>",
            "Landroid/app/admin/DevicePolicyManager",
            "Landroid/view/accessibility/AccessibilityService",
            "Landroid/accounts/AccountManager;->getAuthToken",
            "Ljavax/crypto/Cipher;->doFinal",
        )

        private val LOW_RISK_API_CLASSES = setOf(
            "getDeviceId", "getSubscriberId", "doFinal",
        )
    }

    fun assess(context: Context, apkFile: File, decompiled: DecompileResult, originalSignature: String?): ModRiskAssessment {
        var riskScore = 0
        val newApis = mutableListOf<String>()

        // String Offset Order anomaly detection for repackaging
        val sooAnomaly = detectSooAnomaly(apkFile)
        if (sooAnomaly > 0.10f) {
            riskScore += (sooAnomaly * 40).toInt().coerceIn(5, 35)
        }

        // Package name based whitelist — known safe mod platforms
        val packageName = try {
            context.packageManager.getPackageArchiveInfo(apkFile.absolutePath, 0)?.packageName ?: ""
        } catch (_: Exception) { "" }
        if (packageName in WHITELISTED_MOD_PACKAGES) {
            return ModRiskAssessment(
                riskScore = 0, repackaged = false,
                newPermissions = emptyList(),
                newComponents = emptyList(), newDangerousApis = emptyList(),
                newNativeLibs = emptyList(),
                suggestion = "Whitelisted app package — no mod risk detected"
            )
        }
        // Match known mod pattern packages
        if (packageName.isNotEmpty() && LEGIT_MOD_PACKAGE_PATTERNS.any { it.matches(packageName) }) {
            val patternMatch = LEGIT_MOD_PACKAGE_PATTERNS.firstOrNull { it.matches(packageName) }
            if (patternMatch != null) {
                return ModRiskAssessment(
                    riskScore = 5, repackaged = false,
                    newPermissions = emptyList(),
                    newComponents = emptyList(), newDangerousApis = emptyList(),
                    newNativeLibs = emptyList(),
                    suggestion = "Known mod platform package — minimal risk"
                )
            }
        }

        val currentSignature = extractSignerFingerprint(context, apkFile)
        val currentSignerName = extractSignerName(context, apkFile)
        val repackaged = originalSignature != null && currentSignature != null && originalSignature != currentSignature

        if (repackaged) {
            val isKnownGoodSigner = currentSignerName != null &&
                KNOWN_GOOD_MOD_SIGNERS.any { currentSignerName.contains(it, ignoreCase = true) }
            if (isKnownGoodSigner) {
                riskScore += 5
            } else if (currentSignature != null && isDebugKey(currentSignature)) {
                riskScore += 20
            } else if (currentSignature != null && !isDebugKey(currentSignature)) {
                riskScore += 10
            }
        }

        val currentPerms = extractPermissions(decompiled.manifest)
        val dangerousAdded = currentPerms.filter { it in DANGEROUS_PERMISSION_MARKERS }
        riskScore += dangerousAdded.size * 30

        val components = extractComponents(decompiled.manifest)
        val exportedNew = components.filter { it.contains("exported", ignoreCase = true) && it.contains("true", ignoreCase = true) }
        riskScore += exportedNew.size * 25

        val allCode = decompiled.allSourceText ?: decompiled.javaSource.values.joinToString("\n")
        for (api in DANGEROUS_API_CLASSES) {
            val shortName = api.substringAfterLast(";->")
            if (allCode.contains(shortName, ignoreCase = true)) {
                if (shortName !in LOW_RISK_API_CLASSES || dangerousAdded.size >= 2) {
                    newApis.add(shortName)
                    riskScore += 40
                }
            }
        }

        if (newApis.any { it.contains("DexClassLoader") || it.contains("PathClassLoader") || it.contains("Class.forName") }) {
            riskScore += 50
        }

        val newLibs = decompiled.nativeLibs.filter { lib ->
            val lower = lib.lowercase()
            lower.contains("mod") || lower.contains("hack") || lower.contains("cheat") ||
            lower.contains("inject") || lower.contains("hook")
        }
        riskScore += newLibs.size * 35

        // Only count non-HTTP patterns as C2 signals to reduce false positives from legitimate web requests
        val c2Patterns = listOf("socket", "connect", "getInputStream")
        val c2Count = c2Patterns.count { allCode.contains(it, ignoreCase = true) }
        if (c2Count >= 3) riskScore += 30

        val suggestion = when {
            riskScore >= 100 -> "Highly likely malware disguised as a mod — contains dangerous API combinations and malicious behavior"
            riskScore >= 51 -> "Suspicious mod — examine before use, contains moderate-risk indicators"
            riskScore >= 21 -> "Likely safe mod with ad-removal or premium unlock — low risk indicators"
            else -> "Safe mod — resource-only changes with no dangerous additions"
        }

        return ModRiskAssessment(
            riskScore = riskScore,
            repackaged = repackaged,
            newPermissions = emptyList(),
            newComponents = emptyList(),
            newDangerousApis = newApis,
            newNativeLibs = newLibs,
            suggestion = suggestion
        )
    }

    fun isLikelyGenuineMod(riskScore: Int, newPermissions: List<String>, newApis: List<String>): Boolean {
        if (riskScore < 50) return true
        val onlyHarmlessPerms = newPermissions.all { it in HARMLESS_PERMISSIONS }
        val hasDangerousApis = newApis.any {
            it.contains("DexClassLoader") || it.contains("PathClassLoader") || it.contains("exec")
        }
        return onlyHarmlessPerms && !hasDangerousApis
    }

    fun crossValidate(
        newPermissions: List<String>,
        newDangerousApis: List<String>,
        newNativeLibs: List<String>,
        newComponents: List<String>,
        existingFindings: List<Finding>
    ): CrossValidationResult {
        val indicatorTypes = mutableSetOf<String>()
        if (newPermissions.isNotEmpty()) indicatorTypes.add("permission")
        if (newDangerousApis.isNotEmpty()) indicatorTypes.add("api")
        if (newNativeLibs.isNotEmpty()) indicatorTypes.add("native")
        if (newComponents.isNotEmpty()) indicatorTypes.add("component")

        val corroborating = existingFindings
            .filter { it.severity >= Severity.MEDIUM && it.category != FindingCategory.BEHAVIORAL }
            .map { it.category.name }
            .distinct()

        return CrossValidationResult(
            indicatorTypes = indicatorTypes,
            hasMixedIndicators = indicatorTypes.size > 1,
            corroboratingFindings = corroborating,
            contradictoryFindings = emptyList()
        )
    }

    fun getConfidence(assessment: ModRiskAssessment): Float {
        val indicatorTypes = listOfNotNull(
            "permission".takeIf { assessment.newPermissions.isNotEmpty() },
            "api".takeIf { assessment.newDangerousApis.isNotEmpty() },
            "native".takeIf { assessment.newNativeLibs.isNotEmpty() },
            "component".takeIf { assessment.newComponents.isNotEmpty() }
        )
        val numTypes = indicatorTypes.size
        if (numTypes == 0) return 0.9f

        val hasMaliciousSignals = assessment.newDangerousApis.any {
            it.contains("SmsManager") || it.contains("getDeviceId") ||
            it.contains("getSubscriberId") || it.contains("exec")
        } || assessment.newPermissions.any {
            it in DANGEROUS_PERMISSION_MARKERS && it !in HARMLESS_PERMISSIONS
        }
        val hasGenuineSignals = isLikelyGenuineMod(
            assessment.riskScore, assessment.newPermissions, assessment.newDangerousApis
        )

        return when {
            hasGenuineSignals && hasMaliciousSignals -> 0.4f
            numTypes == 1 -> 0.5f
            hasMaliciousSignals && !hasGenuineSignals && numTypes >= 2 -> 0.85f
            hasGenuineSignals && !hasMaliciousSignals && numTypes >= 2 -> 0.75f
            hasGenuineSignals -> 0.7f
            else -> 0.6f
        }
    }

    fun generateFindings(
        assessment: ModRiskAssessment,
        sooAnomaly: Float = 0f,
        existingFindings: List<Finding> = emptyList()
    ): List<Finding> {
        val findings = mutableListOf<Finding>()

        val sooFinding = assessSooRisk(sooAnomaly)
        if (sooFinding != null) findings.add(sooFinding)

        if (assessment.repackaged) {
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.INFO,
                title = "Repackaged APK Detected",
                description = "App has been re-signed with a different certificate than the original"
            ))
        }

        val hasAccessibilityPerm = assessment.newPermissions.any { it == "BIND_ACCESSIBILITY_SERVICE" }
        val hasAccessibilityApi = assessment.newDangerousApis.any {
            it.contains("AccessibilityService") || it.contains("accessibility")
        }
        val effectiveRisk = when {
            hasAccessibilityPerm && !hasAccessibilityApi && assessment.riskScore > 30 ->
                (assessment.riskScore * 0.7f).toInt().coerceAtLeast(30)
            else -> assessment.riskScore
        }

        val isGenuine = isLikelyGenuineMod(
            effectiveRisk, assessment.newPermissions, assessment.newDangerousApis
        )
        val crossVal = crossValidate(
            assessment.newPermissions,
            assessment.newDangerousApis, assessment.newNativeLibs,
            assessment.newComponents, existingFindings
        )

        val crossValNote = if (crossVal.hasMixedIndicators) {
            " | Cross-validation: indicators span ${crossVal.indicatorTypes.size} categories"
        } else ""
        val genuineModNote = if (isGenuine && effectiveRisk >= 21) {
            " | GENUINE_MOD: Likely genuine mod with expected modifications"
        } else ""

        if (effectiveRisk >= 100) {
            val severity = if (isGenuine && effectiveRisk < 150) Severity.HIGH else Severity.CRITICAL
            findings.add(Finding(
                category = FindingCategory.MALWARE,
                severity = severity,
                title = "Malicious Mod — ${assessment.riskScore} Risk Score",
                description = assessment.suggestion + genuineModNote,
                details = "New dangerous APIs: ${assessment.newDangerousApis.joinToString(", ")}, New components: ${assessment.newComponents.joinToString(", ")}" + crossValNote
            ))
        } else if (effectiveRisk >= 51) {
            val severity = if (isGenuine) Severity.MEDIUM else Severity.HIGH
            findings.add(Finding(
                category = FindingCategory.BEHAVIORAL,
                severity = severity,
                title = "Suspicious Mod — ${assessment.riskScore} Risk Score",
                description = assessment.suggestion + genuineModNote + crossValNote
            ))
        } else if (effectiveRisk >= 21) {
            findings.add(Finding(
                category = FindingCategory.BEHAVIORAL,
                severity = Severity.LOW,
                title = "Ad-Removal Mod Detected",
                description = assessment.suggestion + genuineModNote + crossValNote
            ))
        }

        return findings
    }

    private fun extractSignerFingerprint(context: Context, apkFile: File): String? {
        return try {
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageArchiveInfo(
                    apkFile.absolutePath,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageArchiveInfo(
                    apkFile.absolutePath,
                    PackageManager.GET_SIGNATURES
                )
            } ?: return null

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val signingInfo = info.signingInfo ?: return null
                val certs = signingInfo.apkContentsSigners ?: return null
                if (certs.isEmpty()) return null
                val digest = MessageDigest.getInstance("SHA-1")
                val certBytes = certs[0].toByteArray()
                val encoded = digest.digest(certBytes)
                encoded.joinToString("") { "%02X".format(it) }
            } else {
                @Suppress("DEPRECATION")
                val sigs = info.signatures ?: return null
                if (sigs.isEmpty()) return null
                val digest = MessageDigest.getInstance("SHA-1")
                val sigBytes = sigs[0].toByteArray()
                val encoded = digest.digest(sigBytes)
                encoded.joinToString("") { "%02X".format(it) }
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun extractSignerName(context: Context, apkFile: File): String? {
        return try {
            val info = context.packageManager.getPackageArchiveInfo(
                apkFile.absolutePath,
                PackageManager.GET_SIGNATURES
            ) ?: return null
            @Suppress("DEPRECATION")
            val sigs = info.signatures ?: return null
            if (sigs.isEmpty()) return null
            val cert = java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(sigs[0].toByteArray().inputStream())
            val dn = (cert as java.security.cert.X509Certificate).issuerX500Principal.name
            if (dn.length > 3 && dn.length < 200) dn else null
        } catch (e: Exception) {
            null
        }
    }

    private fun isDebugKey(fingerprint: String): Boolean {
        return fingerprint in DEBUG_KEY_FINGERPRINTS
    }

    private fun extractPermissions(manifest: String): List<String> {
        val perms = mutableListOf<String>()
        val permRegex = Regex("""android\.permission\.([A-Z_]+)""")
        for (match in permRegex.findAll(manifest)) {
            perms.add(match.groupValues[1])
        }
        return perms.distinct()
    }

    private fun extractComponents(manifest: String): List<String> {
        val comps = mutableListOf<String>()
        val compRegex = Regex("""<(activity|service|receiver|provider)[^>]*>""", RegexOption.IGNORE_CASE)
        for (match in compRegex.findAll(manifest)) {
            comps.add(match.value)
        }
        return comps
    }

    fun getSoxFingerprint(apkFile: File): String? {
        return try {
            ZipFile(apkFile).use { zip ->
                val dexEntries = zip.entries().asSequence()
                    .filter { !it.isDirectory && it.name.endsWith(".dex") }
                    .sortedBy { it.name }
                    .toList()
                if (dexEntries.isEmpty()) return null

                val digest = MessageDigest.getInstance("SHA-256")
                for (entry in dexEntries) {
                    val strings = extractStringOffsets(zip, entry.name)
                    for (offset in strings) {
                        digest.update(java.nio.ByteBuffer.allocate(8).putLong(offset).array())
                    }
                }
                digest.digest().joinToString("") { "%02x".format(it) }
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * String Offset Order (SOO) anomaly detection.
     * Repackaged APKs (via apktool etc.) often have disrupted alphabetical ordering
     * of string identifiers in DEX files. Returns anomaly ratio 0.0-1.0.
     * Based on AndroidSOO research (Gonzalez et al.).
     */
    fun detectSooAnomaly(apkFile: File): Float {
        return try {
            ZipFile(apkFile).use { zip ->
                val dexEntries = zip.entries().asSequence()
                    .filter { !it.isDirectory && it.name.endsWith(".dex") }
                    .sortedBy { it.name }
                    .toList()
                if (dexEntries.isEmpty()) return@use 0f

                var totalOffsets = 0
                var outOfOrder = 0

                for (entry in dexEntries) {
                    val data = zip.getInputStream(entry).readBytes()
                    if (data.size < 40) continue

                    val strOff = ((data[8].toInt() and 0xFF).toLong() shl 32) or
                        ((data[9].toInt() and 0xFF).toLong() shl 24) or
                        ((data[10].toInt() and 0xFF).toLong() shl 16) or
                        ((data[11].toInt() and 0xFF).toLong() shl 8) or
                        (data[12].toInt() and 0xFF).toLong()
                    val strSize = ((data[13].toInt() and 0xFF).toLong() shl 32) or
                        ((data[14].toInt() and 0xFF).toLong() shl 24) or
                        ((data[15].toInt() and 0xFF).toLong() shl 16) or
                        ((data[16].toInt() and 0xFF).toLong() shl 8) or
                        (data[17].toInt() and 0xFF).toLong()

                    val count = (strSize / 4).toInt().coerceAtMost(5000)
                    if (count < 10) continue

                    val offsets = mutableListOf<Pair<Long, Long>>()
                    for (i in 0 until count) {
                        val pos = (strOff + i * 4).toInt()
                        if (pos + 4 > data.size) break
                        val off = ((data[pos].toInt() and 0xFF).toLong() shl 24) or
                            ((data[pos + 1].toInt() and 0xFF).toLong() shl 16) or
                            ((data[pos + 2].toInt() and 0xFF).toLong() shl 8) or
                            (data[pos + 3].toInt() and 0xFF).toLong()
                        offsets.add(off to i.toLong())
                    }

                    for (i in 1 until offsets.size) {
                        totalOffsets++
                        if (offsets[i].first < offsets[i - 1].first) {
                            outOfOrder++
                        }
                    }
                }

                if (totalOffsets == 0) 0f else outOfOrder.toFloat() / totalOffsets.toFloat()
            }
        } catch (e: Exception) {
            0f
        }
    }

    fun assessSooRisk(sooAnomaly: Float): Finding? {
        return when {
            sooAnomaly > 0.25f -> Finding(
                category = FindingCategory.PACKER,
                severity = Severity.HIGH,
                title = "String Offset Order Anomaly — Repackaging Detected",
                description = "DEX string ordering shows ${"%.1f".format(sooAnomaly * 100)}% out-of-order entries — strong indicator of repackaging via apktool or similar tools",
                details = "SOO anomaly ratio: ${"%.3f".format(sooAnomaly)}. Values above 0.25 indicate repackaging."
            )
            sooAnomaly > 0.10f -> Finding(
                category = FindingCategory.PACKER,
                severity = Severity.MEDIUM,
                title = "String Offset Order Slight Anomaly",
                description = "DEX string ordering shows ${"%.1f".format(sooAnomaly * 100)}% out-of-order — possible repackaging",
                details = "SOO anomaly ratio: ${"%.3f".format(sooAnomaly)}"
            )
            else -> null
        }
    }

    private fun extractStringOffsets(zip: ZipFile, dexPath: String): List<Long> {
        try {
            val entry = zip.getEntry(dexPath) ?: return emptyList()
            val data = zip.getInputStream(entry).readBytes()
            if (data.size < 40) return emptyList()

            val stringIdsOffset = ((data[8].toInt() and 0xFF).toLong() shl 32) or
                ((data[9].toInt() and 0xFF).toLong() shl 24) or
                ((data[10].toInt() and 0xFF).toLong() shl 16) or
                ((data[11].toInt() and 0xFF).toLong() shl 8) or
                (data[12].toInt() and 0xFF).toLong()

            val stringIdsSize = ((data[13].toInt() and 0xFF).toLong() shl 32) or
                ((data[14].toInt() and 0xFF).toLong() shl 24) or
                ((data[15].toInt() and 0xFF).toLong() shl 16) or
                ((data[16].toInt() and 0xFF).toLong() shl 8) or
                (data[17].toInt() and 0xFF).toLong()

            val offsets = mutableListOf<Long>()
            val count = (stringIdsSize / 4).toInt().coerceAtMost(10000)
            for (i in 0 until count) {
                val pos = (stringIdsOffset + i * 4).toInt()
                if (pos + 4 > data.size) break
                val off = ((data[pos].toInt() and 0xFF).toLong() shl 24) or
                    ((data[pos + 1].toInt() and 0xFF).toLong() shl 16) or
                    ((data[pos + 2].toInt() and 0xFF).toLong() shl 8) or
                    (data[pos + 3].toInt() and 0xFF).toLong()
                offsets.add(off)
            }
            return offsets
        } catch (e: Exception) {
            return emptyList()
        }
    }
}
