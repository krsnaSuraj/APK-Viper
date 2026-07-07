package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class PackerDetectorTest {
    private val detector = PackerDetector()

    @Test
    fun cleanCode_noPackerFindings() {
        val result = DecompileResult(
            javaSource = mapOf("Main.java" to "class Main { void run() { } }"),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.detect(result).isEmpty())
    }

    @Test
    fun bangclePacker_detected() {
        val code = "import com.bangcle.helper;"
        val result = DecompileResult(
            javaSource = mapOf("App.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.detect(result)
        assertTrue(findings.any { it.title.contains("bangcle", ignoreCase = true) })
    }

    @Test
    fun ijiamiPacker_detected() {
        val code = "com.ijiami.protect"
        val result = DecompileResult(
            javaSource = mapOf("App.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.detect(result)
        assertTrue(findings.any { it.title.contains("ijiami", ignoreCase = true) })
    }

    @Test
    fun tencentStubShell_detected() {
        val code = "com.tencent.StubShell"
        val result = DecompileResult(
            javaSource = mapOf("App.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.detect(result)
        assertTrue(findings.any { it.title.contains("StubShell", ignoreCase = true) })
    }

    @Test
    fun dexClassLoader_detected() {
        val code = "DexClassLoader loader = new DexClassLoader();"
        val result = DecompileResult(
            javaSource = mapOf("Loader.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.detect(result)
        assertTrue(findings.any { it.title == "Dynamic DEX Loading" })
        assertEquals(Severity.HIGH, findings.first { it.title == "Dynamic DEX Loading" }.severity)
    }

    @Test
    fun reflectionLoading_detected() {
        val code = "Class.forName(cls); Method.invoke(m, args);"
        val result = DecompileResult(
            javaSource = mapOf("Reflect.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.detect(result)
        assertTrue(findings.any { it.title == "Reflection-based Loading" })
        assertEquals(Severity.MEDIUM, findings.first { it.title == "Reflection-based Loading" }.severity)
    }

    @Test
    fun reflectionOnlyForName_noTrigger() {
        val code = "Class.forName(cls);"
        val result = DecompileResult(
            javaSource = mapOf("Reflect.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.detect(result).none { it.title == "Reflection-based Loading" })
    }

    @Test
    fun elfPackerInNativeLibs_detected() {
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = listOf("libpacker.so has UPX! packed", "shiva detected"),
            decompileTimeMs = 0
        )
        val findings = detector.detect(result)
        assertTrue(findings.any { it.title == "ELF Packing Indicators" })
        assertEquals(Severity.HIGH, findings.first { it.title == "ELF Packing Indicators" }.severity)
    }

    @Test
    fun elfPackerCaseInsensitive() {
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = listOf("LIB IS PACKED WITH UPX!"),
            decompileTimeMs = 0
        )
        val findings = detector.detect(result)
        assertTrue(findings.any { it.title == "ELF Packing Indicators" })
    }

    @Test
    fun stubClasses_detected() {
        val smaliEntries = (1..11).map { "class$it.smali" to """
            .class public Lcom/test/Stub$it;
            .field public x:I
            .field public y:Ljava/lang/String;
        """.trimIndent() }.toMap()
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = smaliEntries,
            manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.detect(result)
        assertTrue(findings.any { it.title.contains("Stub", ignoreCase = true) })
        assertEquals(Severity.HIGH, findings.first { it.title.contains("Stub") }.severity)
    }

    @Test
    fun stubClasses_belowThreshold() {
        val smaliEntries = (1..5).map { "class$it.smali" to """
            .class public Lcom/test/Stub$it;
            .field public x:I
        """.trimIndent() }.toMap()
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = smaliEntries,
            manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.detect(result).none { it.title.contains("Stub") })
    }

    @Test
    fun emptySource_noFindings() {
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.detect(result).isEmpty())
    }

    @Test
    fun nativeLib_withoutPackerStrings_noFinding() {
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = listOf("libnative.so", "libc++_shared.so"),
            decompileTimeMs = 0
        )
        assertTrue(detector.detect(result).none { it.title == "ELF Packing Indicators" })
    }
}
