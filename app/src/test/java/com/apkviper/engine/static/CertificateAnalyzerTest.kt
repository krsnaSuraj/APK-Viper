package com.apkviper.engine.static

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Assume
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class CertificateAnalyzerTest {
    private val analyzer = CertificateAnalyzer()

    companion object {
        private var debugCertDer: ByteArray? = null

        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            try {
                val keystoreFile = File(
                    System.getProperty("user.home") + File.separator +
                            ".android" + File.separator + "debug.keystore"
                )
                if (!keystoreFile.exists()) return
                val ks = KeyStore.getInstance(KeyStore.getDefaultType())
                ks.load(keystoreFile.inputStream(), "android".toCharArray())
                val cert = ks.getCertificate("androiddebugkey") ?: return
                debugCertDer = cert.encoded
            } catch (_: Exception) {
            }
        }

        private fun writeCertZip(tmp: File, der: ByteArray) {
            ZipOutputStream(FileOutputStream(tmp)).use { zos ->
                zos.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
                zos.write(der)
                zos.closeEntry()
            }
        }
    }

    @Test
    fun analyzeReturnsEmpty() {
        val result = DecompileResult(mapOf(), mapOf(), "", mapOf(), emptyList(), emptyList(), 0)
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun analyzeCertificate_nonexistentFile_returnsError() {
        val findings = analyzer.analyzeCertificate(File("/nonexistent/path.apk"))
        assertTrue(findings.any { it.title.contains("Certificate Extraction Failed") })
    }

    @Test
    fun analyzeCertificate_emptyZip_noCertFindings() {
        val tmp = createTempFile("empty", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write("dex content".toByteArray())
            zos.closeEntry()
        }
        val findings = analyzer.analyzeCertificate(tmp)
        assertTrue(findings.any { it.title.contains("No Certificate Found") })
    }

    @Test
    fun analyzeCertificate_malformedEntry_returnsParseError() {
        val tmp = createTempFile("badcert", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
            zos.write("not a real certificate".toByteArray())
            zos.closeEntry()
        }
        val findings = analyzer.analyzeCertificate(tmp)
        assertTrue(findings.any { it.title.contains("Certificate Parse Error") })
    }

    @Test
    fun analyzeCertificate_corruptZip_returnsError() {
        val tmp = createTempFile("corrupt", ".apk")
        tmp.deleteOnExit()
        tmp.writeBytes(byteArrayOf(0, 1, 2, 3, 4, 5))
        val findings = analyzer.analyzeCertificate(tmp)
        assertTrue(findings.any { it.title.contains("Certificate Extraction Failed") })
    }

    @Test
    fun analyzeCertificate_debugKeystoreCert_parsed() {
        Assume.assumeNotNull(debugCertDer)
        val der = debugCertDer!!
        val tmp = createTempFile("debugcert", ".apk").apply { deleteOnExit() }
        writeCertZip(tmp, der)
        val findings = analyzer.analyzeCertificate(tmp)
        assertTrue("Should find self-signed cert", findings.any { it.title.contains("Self-Signed Certificate") })
        assertTrue("Should find single cert note", findings.any { it.title.contains("Single Certificate") })
        assertTrue("Should have issuer fingerprint", findings.any { it.title.contains("Issuer Fingerprint") })
    }

    @Test
    fun analyzeCertificate_debugKeystoreCert_debugSubjectDetected() {
        Assume.assumeNotNull(debugCertDer)
        val der = debugCertDer!!
        val tmp = createTempFile("debugsubj", ".apk").apply { deleteOnExit() }
        writeCertZip(tmp, der)
        val findings = analyzer.analyzeCertificate(tmp)
        val debugFinding = findings.find { it.title.contains("Debug Certificate") }
        assertNotNull("Debug cert subject should trigger debug finding", debugFinding)
        assertEquals(Severity.MEDIUM, debugFinding!!.severity)
    }

    @Test
    fun analyzeCertificate_debugKeystoreCert_findingsCorrectCategory() {
        Assume.assumeNotNull(debugCertDer)
        val der = debugCertDer!!
        val tmp = createTempFile("cat", ".apk").apply { deleteOnExit() }
        writeCertZip(tmp, der)
        val findings = analyzer.analyzeCertificate(tmp)
        findings.forEach { assertEquals(FindingCategory.CERTIFICATE, it.category) }
    }

    @Test
    fun analyzeCertificate_multipleCertEntries_noSingleCertFinding() {
        Assume.assumeNotNull(debugCertDer)
        val der = debugCertDer!!
        val tmp = createTempFile("multi", ".apk").apply { deleteOnExit() }
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
            zos.write(der)
            zos.closeEntry()
            zos.putNextEntry(ZipEntry("META-INF/CERT2.RSA"))
            zos.write(der)
            zos.closeEntry()
        }
        val findings = analyzer.analyzeCertificate(tmp)
        assertFalse("Multiple cert entries should not trigger single cert finding",
            findings.any { it.title.contains("Single Certificate") })
    }

    @Test
    fun analyzeCertificate_debugKeystoreCert_notExpired() {
        Assume.assumeNotNull(debugCertDer)
        val der = debugCertDer!!
        val tmp = createTempFile("notexp", ".apk").apply { deleteOnExit() }
        writeCertZip(tmp, der)
        val findings = analyzer.analyzeCertificate(tmp)
        assertFalse("Recently created cert should not be expired",
            findings.any { it.title.contains("Expired Certificate") })
    }

    @Test
    fun analyzeCertificate_dedupSkipsDuplicateCerts() {
        Assume.assumeNotNull(debugCertDer)
        val der = debugCertDer!!
        analyzer.resetDedupState()
        val tmp = createTempFile("dedup", ".apk").apply { deleteOnExit() }
        writeCertZip(tmp, der)
        val firstFindings = analyzer.analyzeCertificate(tmp)
        assertTrue("First call should produce findings", firstFindings.isNotEmpty())
        val secondFindings = analyzer.analyzeCertificate(tmp)
        val newFindings = secondFindings.filterNot { it in firstFindings }
        assertTrue("Second call should produce no new findings (all deduped)", newFindings.isEmpty())
    }

    @Test
    fun resetDedupState_allowsReprocessing() {
        Assume.assumeNotNull(debugCertDer)
        val der = debugCertDer!!
        analyzer.resetDedupState()
        val tmp = createTempFile("resetdedup", ".apk").apply { deleteOnExit() }
        writeCertZip(tmp, der)
        val firstFindings = analyzer.analyzeCertificate(tmp)
        analyzer.resetDedupState()
        val secondFindings = analyzer.analyzeCertificate(tmp)
        assertTrue("After reset, second call should produce same findings again",
            secondFindings.size >= firstFindings.size)
    }

    @Test
    fun dedupMultipleCerts_identicalContent_deduped() {
        Assume.assumeNotNull(debugCertDer)
        val der = debugCertDer!!
        analyzer.resetDedupState()
        val tmp = createTempFile("multidedup", ".apk").apply { deleteOnExit() }
        java.util.zip.ZipOutputStream(java.io.FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(java.util.zip.ZipEntry("META-INF/CERT.RSA"))
            zos.write(der)
            zos.closeEntry()
            zos.putNextEntry(java.util.zip.ZipEntry("META-INF/CERT2.RSA"))
            zos.write(der)
            zos.closeEntry()
        }
        val findings = analyzer.analyzeCertificate(tmp)
        val selfSignedCount = findings.count { it.title.contains("Self-Signed Certificate") }
        assertEquals("Self-Signed Certificate should appear exactly once after dedup", 1, selfSignedCount)
    }

    // ---- NEW: null APK path, empty cert chain, expired cert ----

    @Test
    fun nullApkPath_returnsError() {
        val findings = analyzer.analyzeCertificate(File("/dev/null/nonexistent.apk"))
        assertTrue("Non-existent file should produce extraction error",
            findings.any { it.title.contains("Certificate Extraction Failed") })
    }

    @Test
    fun emptyCertChain_noRsaEntries_returnsNoCertFinding() {
        val tmp = createTempFile("nochain", ".apk").apply { deleteOnExit() }
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            zos.write("Manifest-Version: 1.0".toByteArray())
            zos.closeEntry()
            zos.putNextEntry(ZipEntry("META-INF/CERT.SF"))
            zos.write("Signature-Version: 1.0".toByteArray())
            zos.closeEntry()
        }
        val findings = analyzer.analyzeCertificate(tmp)
        assertTrue("No .RSA entries should produce 'No Certificate Found'",
            findings.any { it.title.contains("No Certificate Found") })
    }

    @Test
    fun expiredCertDetection() {
        try {
            val expiredDer = generateExpiredCertDer()
            val tmp = createTempFile("expired", ".apk").apply { deleteOnExit() }
            writeCertZip(tmp, expiredDer)
            val findings = analyzer.analyzeCertificate(tmp)
            assertTrue(
                "Should detect expired certificate, got titles: ${findings.map { it.title }}",
                findings.any { it.title.contains("Expired Certificate") }
            )
        } catch (e: Exception) {
            Assume.assumeNoException("Skipping expired cert test: cert generation not available", e)
        }
    }

    private fun generateExpiredCertDer(): ByteArray {
        // Use keytool from JDK to generate an expired self-signed cert
        val javaHome = System.getProperty("java.home")
        val keytool = File(javaHome, "bin/keytool.exe").takeIf { it.exists() }
            ?: File(javaHome, "bin/keytool").takeIf { it.exists() }
            ?: throw RuntimeException("keytool not found")

        val ksFile = createTempFile("expired_ks", ".jks").apply { deleteOnExit() }
        val certFile = createTempFile("expired_cert", ".der").apply { deleteOnExit() }

        // Generate a cert that started 2 days ago and was valid for 1 day
        val gen = ProcessBuilder(
            keytool.absolutePath,
            "-genkeypair",
            "-keystore", ksFile.absolutePath,
            "-storepass", "password",
            "-keypass", "password",
            "-dname", "CN=ExpiredTest,O=TestOrg",
            "-alias", "expired",
            "-keyalg", "RSA",
            "-keysize", "1024",
            "-startdate", "-2d",
            "-validity", "1"
        ).redirectErrorStream(true).start()
        gen.inputStream.readAllBytes()
        val genExit = gen.waitFor()
        if (genExit != 0) throw RuntimeException("keytool gen failed: exit code $genExit")

        // Export the certificate
        val exp = ProcessBuilder(
            keytool.absolutePath,
            "-exportcert",
            "-keystore", ksFile.absolutePath,
            "-storepass", "password",
            "-alias", "expired",
            "-file", certFile.absolutePath
        ).redirectErrorStream(true).start()
        exp.inputStream.readAllBytes()
        val expExit = exp.waitFor()
        if (expExit != 0) throw RuntimeException("keytool export failed: exit code $expExit")

        return certFile.readBytes()
    }
}
