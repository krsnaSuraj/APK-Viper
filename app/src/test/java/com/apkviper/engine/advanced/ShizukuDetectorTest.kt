package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class ShizukuDetectorTest {
    private val detector = ShizukuDetector()

    private fun decompileResult(javaSource: Map<String, String> = mapOf("A.java" to ""),
                                smaliSource: Map<String, String> = mapOf()): DecompileResult =
        DecompileResult(javaSource, smaliSource, "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun cleanCode_noShizukuDetected() {
        val result = decompileResult(mapOf("A.java" to "package com.example;"))
        assertTrue(detector.analyze(result).isEmpty())
    }

    @Test
    fun singleShizukuReference_mediumSeverity() {
        val result = decompileResult(mapOf("A.java" to "import moe.shizuku.api;"))
        val findings = detector.analyze(result)
        assertEquals(1, findings.size)
        assertEquals(Severity.MEDIUM, findings[0].severity)
        assertEquals("Shizuku API Reference Detected", findings[0].title)
    }

    @Test
    fun twoShizukuReferences_highSeverity() {
        val code = """
            import moe.shizuku.api.Shizuku;
            import moe.shizuku.manager;
            Shizuku.checkSelfPermission();
        """.trimIndent()
        val result = decompileResult(mapOf("A.java" to code))
        val findings = detector.analyze(result)
        assertEquals(1, findings.size)
        assertEquals(Severity.HIGH, findings[0].severity)
    }

    @Test
    fun shizukuWithCriticalShellOps_criticalSeverity() {
        val code = """
            import moe.shizuku.api.Shizuku;
            import moe.shizuku.manager;
            Shizuku.checkSelfPermission();
            Shizuku.bindUserService();
            pm grant
            pm revoke
            settings put
            cmd appops
        """.trimIndent()
        val result = decompileResult(mapOf("A.java" to code))
        val findings = detector.analyze(result)
        assertEquals(Severity.CRITICAL, findings[0].severity)
    }

    @Test
    fun shizukuWithShellOpsBelowThreshold_highSeverity() {
        val code = """
            import moe.shizuku.api.Shizuku;
            import moe.shizuku.manager;
            Shizuku.checkSelfPermission();
            Shizuku.bindUserService();
            pm grant
        """.trimIndent()
        val result = decompileResult(mapOf("A.java" to code))
        val findings = detector.analyze(result)
        assertEquals(Severity.HIGH, findings[0].severity)
    }

    @Test
    fun shizukuPatternCaseInsensitive() {
        val result = decompileResult(mapOf("A.java" to "MOE.SHIZUKU.API.Shizuku"))
        val findings = detector.analyze(result)
        assertEquals("Shizuku API Reference Detected", findings[0].title)
    }

    @Test
    fun shizukuInSmali_detected() {
        val result = decompileResult(
            javaSource = mapOf("A.java" to "package clean;"),
            smaliSource = mapOf("A.smali" to "moe.shizuku.api\nShizukuProvider")
        )
        assertFalse(detector.analyze(result).isEmpty())
    }
}
