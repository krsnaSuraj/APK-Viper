package com.apkviper.engine.advanced

import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ModApkDetectorSooTest {
    private val detector = ModApkDetector()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun sooAnomaly_emptyFile_returnsZero() {
        val apk = tempFolder.newFile("empty.apk")
        val result = detector.detectSooAnomaly(apk)
        assertEquals(0f, result, 0.01f)
    }

    @Test
    fun sooAnomaly_noDex_returnsZero() {
        val apk = tempFolder.newFile("noclass.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
        }
        val result = detector.detectSooAnomaly(apk)
        assertEquals(0f, result, 0.01f)
    }

    @Test
    fun sooAnomaly_minimalDex_returnsLow() {
        val apk = createMinimalDexApk()
        val result = detector.detectSooAnomaly(apk)
        assertTrue("SOO should be low for minimal DEX (was $result)", result < 0.25f)
    }

    @Test
    fun assessSooRisk_belowThreshold_noFinding() {
        val finding = detector.assessSooRisk(0.05f)
        assertNull("Low anomaly should not produce finding", finding)
    }

    @Test
    fun assessSooRisk_medium_returnsMedium() {
        val finding = detector.assessSooRisk(0.15f)
        assertNotNull("Medium anomaly should produce finding", finding)
        assertEquals(Severity.MEDIUM, finding!!.severity)
        assertTrue(finding.title.contains("Anomaly"))
    }

    @Test
    fun assessSooRisk_high_returnsHigh() {
        val finding = detector.assessSooRisk(0.30f)
        assertNotNull("High anomaly should produce finding", finding)
        assertEquals(Severity.HIGH, finding!!.severity)
        assertTrue(finding.title.contains("Repackaging"))
    }

    private fun createMinimalDexApk(): File {
        val file = tempFolder.newFile("test_dex.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            val data = ByteArray(512)
            data[0] = 0x64
            data[1] = 0x65
            data[2] = 0x78
            data[3] = 0x0A
            data[4] = 0x30
            data[5] = 0x33
            data[6] = 0x38
            data[7] = 0x00
            data[8] = 0
            data[9] = 0
            data[10] = 0
            data[11] = 0
            data[12] = 0x70
            data[13] = 0
            data[14] = 0
            data[15] = 0
            data[16] = 0
            data[17] = 0x0A
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(data)
            zip.closeEntry()
        }
        return file
    }
}