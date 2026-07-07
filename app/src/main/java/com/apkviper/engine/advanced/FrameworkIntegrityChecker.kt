package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

/**
 * Framework Integrity Checker — detects malware masquerading as legitimate SDKs.
 * Checks if an app claiming to be a known vendor actually uses their official
 * signing certificate or if it's a self-signed debug cert riding on reputation.
 */
class FrameworkIntegrityChecker {

    // Known vendor certificate subject organization names (O=)
    private val knownVendorOrgs = mapOf(
        "O=Google" to "Google",
        "O=Samsung" to "Samsung",
        "O=Facebook" to "Meta",
        "O=Twitter" to "Twitter/X",
        "O=Spotify" to "Spotify",
        "O=Netflix" to "Netflix",
        "O=Adobe" to "Adobe",
    )

    // Size baselines for common framework libs (bytes) — approximate release sizes
    private val frameworkSizeBaselines = mapOf(
        "libil2cpp.so" to 15_000_000L..60_000_000L, // Unity IL2CPP
        "libunity.so" to 5_000_000L..25_000_000L,    // Unity engine
        "libflutter.so" to 5_000_000L..30_000_000L,  // Flutter engine
        "libreactnativejni.so" to 500_000L..10_000_000L, // React Native
    )

    // Well-known package prefixes from legit vendors
    private val vendorPackagePrefixes = mapOf(
        "com.google." to "Google",
        "com.android." to "Android OS",
        "com.samsung." to "Samsung",
        "com.facebook." to "Meta",
        "com.instagram" to "Meta",
        "com.whatsapp" to "Meta",
        "com.twitter." to "Twitter/X",
        "com.spotify." to "Spotify",
        "com.netflix." to "Netflix",
    )

    fun analyze(decompiled: DecompileResult, apkFile: File): List<Finding> {
        val findings = mutableListOf<Finding>()
        val packageName = extractPackageName(decompiled.manifest)

        // 1. Check if package name claims to be a known vendor
        val claimedVendor = vendorPackagePrefixes.entries.find { (prefix, _) ->
            packageName.startsWith(prefix)
        }

        if (claimedVendor != null) {
            // Verify the signing certificate
            val certResult = checkCertificate(apkFile)
            if (certResult != null) {
                if (certResult.isDebug || certResult.isSelfSigned) {
                    findings.add(Finding(
                        category = FindingCategory.CERTIFICATE,
                        severity = Severity.CRITICAL,
                        title = "SDK Masquerading: Fake ${claimedVendor.value} App",
                        description = "App claims to be '${claimedVendor.key}*' (${claimedVendor.value}) but uses a ${if (certResult.isDebug) "debug" else "self-signed"} certificate",
                        details = "This is a Trojan masquerading as ${claimedVendor.value}. Subject: ${certResult.subject.take(80)}"
                    ))
                } else {
                    // Has proper cert but check if it matches a known vendor organization
                    val knownOrg = knownVendorOrgs.entries.find { (orgStr, _) ->
                        certResult.subject.contains(orgStr, ignoreCase = true)
                    }
                    if (knownOrg == null) {
                        findings.add(Finding(
                            category = FindingCategory.CERTIFICATE,
                            severity = Severity.HIGH,
                            title = "Unverified Vendor Certificate",
                            description = "App claims to be '${claimedVendor.key}*' but certificate subject doesn't match known ${claimedVendor.value} organization",
                            details = "Cert Subject: ${certResult.subject.take(80)}"
                        ))
                    }
                }
            }
        }

        // 2. Check framework lib sizes against baselines
        val nativeLibs = decompiled.nativeLibs
        ZipFile(apkFile).use { zip ->
            for (libPath in nativeLibs) {
                val libFileName = libPath.substringAfterLast('/')
                val baseline = frameworkSizeBaselines[libFileName] ?: continue

                try {
                    val entry = zip.getEntry(libPath) ?: continue
                    val size = entry.size

                    if (size !in baseline) {
                        val sizeMB = "%.1f".format(size.toDouble() / 1_000_000)
                        val expectedRange = "${"%.1f".format(baseline.first.toDouble() / 1_000_000)}-${"%.1f".format(baseline.last.toDouble() / 1_000_000)}MB"

                        val verdict = if (size < baseline.first) "TAMPERED (too small — stripped/dummied)" else "SUSPICIOUS (too large — possible payload injection)"

                        findings.add(Finding(
                            category = FindingCategory.NATIVE,
                            severity = Severity.HIGH,
                            title = "Framework Tampering: $libFileName",
                            description = "$libFileName is ${sizeMB}MB (expected $expectedRange) — $verdict",
                            details = "Attackers sometimes replace legitimate frameworks with modified versions containing malware",
                            file = libPath
                        ))
                    }
                } catch (_: Exception) {
                    continue
                }
            }
        }

        // 3. Check if auto-generated package names are used as a disguise
        if (packageName.matches(Regex("com\\.[a-z]{2,4}\\.[a-z]{2,4}\\.[a-z]{4,6}$")) &&
            vendorPackagePrefixes.none { (k, _) -> packageName.startsWith(k) }) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.LOW,
                title = "Generic/Auto-generated Package Name",
                description = "Package name '$packageName' appears auto-generated — common in malware to avoid identification"
            ))
        }

        return findings
    }

    data class CertInfo(
        val subject: String,
        val issuer: String,
        val isDebug: Boolean,
        val isSelfSigned: Boolean,
        val sha256: String,
        val notBefore: Long,
        val notAfter: Long
    )

    private fun checkCertificate(apkFile: File): CertInfo? {
        return try {
            ZipFile(apkFile).use { zip ->
                // Find RSA/DSA/EC signature file
                val certEntry = zip.entries().asSequence()
                    .find { it.name.startsWith("META-INF/") && (it.name.endsWith(".RSA") || it.name.endsWith(".DSA") || it.name.endsWith(".EC")) }
                    ?: return null

                val certBytes = zip.getInputStream(certEntry).readBytes()
                val certFactory = CertificateFactory.getInstance("X.509")
                val generated = certFactory.generateCertificate(java.io.ByteArrayInputStream(certBytes))
                val cert = generated as? X509Certificate ?: return null

                val digest = MessageDigest.getInstance("SHA-256")
                val sha256 = digest.digest(cert.encoded).joinToString("") { "%02x".format(it) }

                val subject = cert.subjectX500Principal.name
                val issuer = cert.issuerX500Principal.name
                val isSelfSigned = subject == issuer
                val isDebug = subject.contains("Android Debug", ignoreCase = true) ||
                    subject.contains("debug", ignoreCase = true) ||
                    issuer.contains("Android Debug", ignoreCase = true)

                CertInfo(
                    subject = subject,
                    issuer = issuer,
                    isDebug = isDebug,
                    isSelfSigned = isSelfSigned,
                    sha256 = sha256,
                    notBefore = cert.notBefore.time,
                    notAfter = cert.notAfter.time
                )
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun extractPackageName(manifest: String): String {
        val regex = Regex("""package="([^"]+)"""")
        return regex.find(manifest)?.groupValues?.getOrNull(1) ?: "unknown"
    }
}
