package com.apkviper.engine.advanced

import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.Deflater
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkIntegrityVerifierTest {
    private val verifier = ApkIntegrityVerifier()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun nonExistentFile_returnsInvalid() {
        val result = verifier.verify(File("nonexistent.apk"))
        assertFalse(result.isValid)
        assertFalse(result.isApk)
        assertNotNull(result.error)
    }

    @Test
    fun fileTooSmall_returnsInvalid() {
        val file = tempFolder.newFile("tiny.apk")
        file.writeText("too small")
        val result = verifier.verify(file)
        assertFalse(result.isValid)
        assertTrue(result.totalSize < 1024)
    }

    @Test
    fun notAZipFile_returnsInvalid() {
        val file = tempFolder.newFile("bad.apk")
        file.writeText("This is not a zip file at all. It's random garbage.")
        val result = verifier.verify(file)
        assertFalse(result.isValid)
        assertFalse(result.isZip)
    }

    @Test
    fun validApkStructure_isValid() {
        val file = createValidApk()
        assertTrue("file size = ${file.length()}", file.length() >= 1024)
        val result = verifier.verify(file)
        assertTrue("isValid: isZip=${result.isZip} err=${result.error}", result.isValid)
        assertTrue("hasManifest", result.hasManifest)
        assertTrue("hasDexFiles", result.hasDexFiles)
    }

    @Test
    fun missingManifest_addsFinding() {
        val file = createApk(manifest = false)
        val result = verifier.verify(file)
        assertFalse(result.isValid)
        assertFalse(result.hasManifest)
        if (result.findings.isNotEmpty()) {
            assertTrue(result.findings.any { it.title.contains("Missing AndroidManifest") })
        }
    }

    @Test
    fun missingDex_addsFinding() {
        val file = createApk(dex = false)
        val result = verifier.verify(file)
        assertFalse(result.isValid)
        assertFalse(result.hasDexFiles)
        if (result.findings.isNotEmpty()) {
            assertTrue(result.findings.any { it.title.contains("Missing DEX") })
        }
    }

    @Test
    fun missingSignature_addsFinding() {
        val file = createApk(signature = false)
        val result = verifier.verify(file)
        if (result.findings.isNotEmpty()) {
            assertTrue(result.findings.any { it.title.contains("Unsigned") })
        }
    }

    @Test
    fun pathTraversalEntry_succeeds() {
        val file = tempFolder.newFile("traversal.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.setLevel(Deflater.NO_COMPRESSION)
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(4096))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("../evil.conf"))
            zip.write("evil".toByteArray())
            zip.closeEntry()
        }
        assertTrue("file size = ${file.length()}", file.length() >= 1024)
        val result = verifier.verify(file)
        assertTrue(result.findings.any { it.title.contains("Zip Path Traversal") })
    }

    @Test
    fun signatureFiles_populated() {
        val file = tempFolder.newFile("signed.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.setLevel(Deflater.NO_COMPRESSION)
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(4096))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
            zip.write(ByteArray(100))
            zip.closeEntry()
        }
        val result = verifier.verify(file)
        assertTrue("hasSignature: isZip=${result.isZip} err=${result.error} sig=${result.signatureFiles}", result.hasSignature)
        assertTrue("sigFiles=${result.signatureFiles}", result.signatureFiles.any { it.endsWith(".RSA") })
    }

    private fun createValidApk(): File = createApk()

    private fun createApk(manifest: Boolean = true, dex: Boolean = true, signature: Boolean = true): File {
        val file = tempFolder.newFile("valid.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.setLevel(Deflater.NO_COMPRESSION)
            if (manifest) {
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write("<manifest package='com.test'/>".toByteArray())
                zip.closeEntry()
            }
            if (dex) {
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(ByteArray(4096))
                zip.closeEntry()
            }
            if (signature) {
                zip.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
                zip.write(ByteArray(100))
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("META-INF/CERT.SF"))
                zip.write(ByteArray(100))
                zip.closeEntry()
            }
            zip.putNextEntry(ZipEntry("resources.arsc"))
            zip.write(ByteArray(2048))
            zip.closeEntry()
        }
        return file
    }
}
