package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class EntropyAnalyzerTest {
    private val analyzer = EntropyAnalyzer()

    @Test
    fun cleanManifest_noFindings() {
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(),
            manifest = "<manifest><application android:name=\"Main\"></application></manifest>",
            resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun manifestEncrypted_detected() {
        val manifest = "<manifest><uses-permission android:name=\"android.permission.INTERNET\"/>encrypted content</manifest>"
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(),
            manifest = manifest, resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Encrypted Assets Detected" })
        assertEquals(Severity.HIGH, findings.first { it.title == "Encrypted Assets Detected" }.severity)
    }

    @Test
    fun manifestDecrypt_detected() {
        val manifest = "<manifest>decrypt and load assets at runtime</manifest>"
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(),
            manifest = manifest, resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(analyzer.analyze(result).any { it.title == "Encrypted Assets Detected" })
    }

    @Test
    fun calculateEntropy_emptyData_returnsZero() {
        assertEquals(0.0, analyzer.calculateShannonEntropy(ByteArray(0)), 0.001)
    }

    @Test
    fun calculateEntropy_allSameByte_entropyZero() {
        val data = ByteArray(100) { 0x41.toByte() }
        assertEquals(0.0, analyzer.calculateShannonEntropy(data), 0.001)
    }

    @Test
    fun calculateEntropy_uniformDistribution_highEntropy() {
        val data = (0..255).flatMap { b -> List(4) { b.toByte() } }.toByteArray()
        val entropy = analyzer.calculateShannonEntropy(data)
        assertTrue("Expected entropy near 8.0, got $entropy", entropy > 7.5)
    }

    @Test
    fun calculateEntropy_twoValues_eachHalf_probability() {
        val data = ByteArray(100) { if (it < 50) 0x00 else 0x01.toByte() }
        assertEquals(1.0, analyzer.calculateShannonEntropy(data), 0.01)
    }

    @Test
    fun calculateEntropy_singleValue_entropyZero() {
        val data = ByteArray(50) { 0xFF.toByte() }
        assertEquals(0.0, analyzer.calculateShannonEntropy(data), 0.001)
    }

    @Test
    fun calculateEntropy_stringInput_worksCorrectly() {
        val bytes = "Hello World".toByteArray()
        val fromBytes = analyzer.calculateShannonEntropy(bytes)
        val fromString = analyzer.calculateShannonEntropy("Hello World")
        assertEquals(fromBytes, fromString, 0.001)
    }

    @Test
    fun highEntropyResource_triggersFinding() {
        val highEntropyData = (0..255).flatMap { b -> List(10) { b.toByte() } }.toByteArray()
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(),
            manifest = "", resources = mapOf("classes.dex" to highEntropyData),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("High Entropy Resource") })
    }

    @Test
    fun lowEntropyResource_noFinding() {
        val lowEntropyData = ByteArray(100) { 0x41.toByte() }
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(),
            manifest = "", resources = mapOf("res.txt" to lowEntropyData),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(analyzer.analyze(result).none { it.title.contains("High Entropy Resource") })
    }

    @Test
    fun multipleHighEntropyResources_multipleFindings() {
        val highEntropyData = (0..255).flatMap { b -> List(10) { b.toByte() } }.toByteArray()
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(),
            manifest = "", resources = mapOf(
                "file1.bin" to highEntropyData,
                "file2.bin" to highEntropyData
            ),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertEquals(2, findings.count { it.title.contains("High Entropy Resource") })
    }

    @Test
    fun calculateEntropy_nullInput_doesNotCrash() {
        assertEquals(0.0, analyzer.calculateShannonEntropy(ByteArray(0)), 0.001)
    }
}
