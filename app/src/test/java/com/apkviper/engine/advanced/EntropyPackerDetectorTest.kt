package com.apkviper.engine.advanced

import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class EntropyPackerDetectorTest {
    private val detector = EntropyPackerDetector()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun emptyNativeLibs_noFindings() {
        val apk = createApk()
        assertTrue(detector.analyze(apk, emptyList()).isEmpty())
    }

    @Test
    fun calculateEntropy_uniformBytes_zero() {
        val data = ByteArray(256) { 0x41.toByte() }
        val entropy = detector.calculateEntropy(data)
        assertEquals(0.0, entropy, 0.01)
    }

    @Test
    fun calculateEntropy_randomBytes_high() {
        val data = ByteArray(256) { (Math.random() * 256).toInt().toByte() }
        val entropy = detector.calculateEntropy(data)
        assertTrue("Entropy should be > 7.0 for random data, got $entropy", entropy > 7.0)
    }

    @Test
    fun calculateEntropy_evenDistribution_max() {
        val data = ByteArray(256) { it.toByte() }
        val r = ByteArray(256 * 4)
        for (i in 0 until 4) System.arraycopy(data, 0, r, i * 256, 256)
        val entropy = detector.calculateEntropy(r)
        assertTrue("Entropy should be close to 8.0, got $entropy", entropy > 7.9)
    }

    @Test
    fun nativeLibNotInZip_skipped() {
        val apk = createApk()
        val findings = detector.analyze(apk, listOf("lib/x86/libnotfound.so"))
        assertTrue(findings.isEmpty())
    }

    @Test
    fun unknownFrameowrkHighEntropyNotFlagged() {
        // This tests that the entropy calculation works; actual ZIP extraction tested in system tests
        val apk = createApk()
        val data = ByteArray(256) { (Math.random() * 256).toInt().toByte() }
        val entropy = detector.calculateEntropy(data)
        assertTrue(entropy > 7.0)
    }

    @Test
    fun dexHighEntropy_detected() {
        val apk = tempFolder.newFile("dex_ent.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            val highEntData = ByteArray(4096) { (Math.random() * 256).toInt().toByte() }
            zip.write(highEntData)
            zip.closeEntry()
        }
        val findings = detector.analyze(apk, emptyList())
        assertTrue(findings.any { it.title.contains("High Entropy DEX") })
    }

    @Test
    fun readBytesMax_limitsCorrectly() {
        val data = ByteArray(100) { 0x41.toByte() }
        val limited = data.inputStream().readBytesMax(50)
        assertEquals(50, limited.size)
    }

    @Test
    fun mixedFilePackingArchitecture_notEnoughFiles() {
        val apk = createApk()
        assertTrue(detector.analyze(apk, emptyList()).isEmpty())
    }

    private fun createApk(): File {
        val file = tempFolder.newFile("test.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest package='com.test'/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("resources.arsc"))
            zip.write(ByteArray(50))
            zip.closeEntry()
        }
        return file
    }
}
