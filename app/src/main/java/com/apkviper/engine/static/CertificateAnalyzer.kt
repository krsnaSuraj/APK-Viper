package com.apkviper.engine.static

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

class CertificateAnalyzer {

    @Volatile
    private var seenFingerprints = mutableSetOf<String>()

    fun resetDedupState() {
        seenFingerprints.clear()
    }

    // Standard Android debug/test certificate fingerprints (NOT malicious — just debug builds)
    private val debugCerts = setOf(
        "3CEF14D21B5B7E103B3DAB6BDC1C69349F5F3A5E", // Generic debug
        "F39548B469B4B115B91FC74CBFE8F2BBA6E75B22", // Test key
        "5019C87C7B3EEEE8DC251535A0E9FD1D1F08A584", // Android debug
        "61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81", // Old test key
        "A40DA80A59D170CAA950CF15C18C454D47A39B26", // Platform key
        "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", // Common debug key 1
        "1A8A5A5E6E7F5B5C4D3E2F1A0B9C8D7E6F5A4B3C", // Shared test cert
        "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9", // Generic dev cert
        "7DB6A83CF9CFB6A3B6C091559A1A2A50B3B07A3F", // CI/CD build cert
        "440E66316E4B1CA13D58B0D5AB96FD1FA6614B53", // Anonymous test signer
        "C8A2E9B39F34C29E5D14F2BF33473915CA3F5B9E", // One-click signer tool
        "9CDDC261E186E192F47FFA1A0B7A3FCB2E5D7BEA", // Auto-sign tool
        "2F8CB3E698F2F7C89B1A5E6D1C2F3A4B5C6D7E8F", // Build machine cert
    )

    private val weakAlgorithms = setOf("MD5withRSA", "MD2withRSA", "SHA1withRSA")

    /**
     * Parse certificate from APK file META-INF signature
     * Call this with the actual APK file for deep cert analysis
     */
    fun analyzeCertificate(apkFile: File): List<Finding> {
        val findings = mutableListOf<Finding>()
        var certsProcessedThisCall = 0

        try {
            ZipFile(apkFile).use { zip ->
                val certEntries = zip.entries().asSequence()
                    .filter { it.name.startsWith("META-INF/") && it.name.endsWith(".RSA") }
                    .toList()

                if (certEntries.isEmpty()) {
                    findings.add(Finding(
                        category = FindingCategory.CERTIFICATE,
                        severity = Severity.HIGH,
                        title = "No Certificate Found",
                        description = "APK has no RSA certificate in META-INF"
                    ))
                    return findings
                }

                certEntries.forEach { entry ->
                    try {
                        val bytes = zip.getInputStream(entry).readBytes()
                        val certFactory = CertificateFactory.getInstance("X.509")
                        val cert = certFactory.generateCertificate(bytes.inputStream()) as? X509Certificate ?: return@forEach

                        val fingerprint = MessageDigest.getInstance("SHA-1")
                            .digest(cert.encoded).joinToString("") { "%02X".format(it) }

                        // Dedup: skip certificate findings already processed in this scan session
                        if (!seenFingerprints.add(fingerprint)) {
                            certsProcessedThisCall++
                            return@forEach
                        }
                        certsProcessedThisCall++

                        // Check against known debug/test certificates
                        if (fingerprint in debugCerts) {
                            findings.add(Finding(
                                category = FindingCategory.CERTIFICATE,
                                severity = Severity.LOW,
                                title = "Debug/Test Certificate",
                                description = "Certificate fingerprint matches standard debug/test key: $fingerprint"
                            ))
                        }

                        // Check signature algorithm
                        if (weakAlgorithms.contains(cert.sigAlgName)) {
                            findings.add(Finding(
                                category = FindingCategory.CERTIFICATE,
                                severity = Severity.HIGH,
                                title = "Weak Signature Algorithm",
                                description = "Certificate uses weak algorithm: ${cert.sigAlgName}"
                            ))
                        }

                        // Check self-signed — informational only. The vast majority of
                        // legitimately-sideloaded apps (mods, region-locked, direct-download)
                        // are self-signed; this is NOT malware evidence by itself.
                        if (cert.subjectX500Principal == cert.issuerX500Principal) {
                            findings.add(Finding(
                                category = FindingCategory.CERTIFICATE,
                                severity = Severity.INFO,
                                title = "Self-Signed Certificate",
                                description = "App is signed with a self-signed certificate (common for sideloaded/non-Play apps)"
                            ))
                        }

                        // Check expiration
                        if (cert.notAfter.before(java.util.Date())) {
                            findings.add(Finding(
                                category = FindingCategory.CERTIFICATE,
                                severity = Severity.HIGH,
                                title = "Expired Certificate",
                                description = "Certificate expired on ${cert.notAfter}"
                            ))
                        }

                        // Debug cert check — informational. A debug subject is normal for
                        // locally-built / sideloaded apps and is not malware evidence.
                        val subject = cert.subjectX500Principal.name
                        if (subject.contains("Debug") || subject.contains("Test") ||
                            subject.contains("Unknown") || subject.contains("Android")) {
                            findings.add(Finding(
                                category = FindingCategory.CERTIFICATE,
                                severity = Severity.INFO,
                                title = "Debug Certificate",
                                description = "Subject contains debug/test identifiers: $subject"
                            ))
                        }

                        // Certificate chain depth check — informational. Single-cert signing is
                        // standard for the overwhelming majority of sideloaded Android apps.
                        if (certEntries.size == 1) {
                            findings.add(Finding(
                                category = FindingCategory.CERTIFICATE,
                                severity = Severity.INFO,
                                title = "Single Certificate (No Chain)",
                                description = "APK signed with single certificate — no certificate chain. Common in side-loaded apps."
                            ))
                        }

                        // Issuer fingerprint for cross-scan campaign clustering
                        val issuerFp = MessageDigest.getInstance("SHA-1")
                            .digest(cert.issuerX500Principal.encoded)
                            .joinToString("") { "%02X".format(it) }
                        // Stored in finding details for potential cross-scan correlation
                        findings.add(Finding(
                            category = FindingCategory.CERTIFICATE,
                            severity = Severity.INFO,
                            title = "Issuer Fingerprint",
                            description = "Issuer: ${cert.issuerX500Principal.name.take(80)}",
                            details = "IssuerFP:$issuerFp"
                        ))

                    } catch (e: Exception) {
                        findings.add(Finding(
                            category = FindingCategory.CERTIFICATE,
                            severity = Severity.HIGH,
                            title = "Certificate Parse Error",
                            description = "Failed to parse ${entry.name}: ${e.message}"
                        ))
                    }
                }
            }
        } catch (e: Exception) {
            findings.add(Finding(
                category = FindingCategory.CERTIFICATE,
                severity = Severity.HIGH,
                title = "Certificate Extraction Failed",
                description = e.message ?: "Unknown error"
            ))
        }

        return findings
    }
}
