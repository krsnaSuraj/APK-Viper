package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class VirtualAppDetectorTest {
    private val detector = VirtualAppDetector()

    private fun decompileResult(javaSource: Map<String, String> = mapOf("A.java" to ""),
                                smaliSource: Map<String, String> = mapOf()): DecompileResult =
        DecompileResult(javaSource, smaliSource, "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun cleanCode_noVirtualAppDetected() {
        val result = decompileResult(mapOf("A.java" to "package com.example; class A {}"))
        assertTrue(detector.analyze(result).isEmpty())
    }

    @Test
    fun parallelSpace_detected() {
        val result = decompileResult(mapOf("A.java" to "com.lbe.parallel.activity"))
        val findings = detector.analyze(result)
        assertEquals(1, findings.size)
        assertEquals("Virtual App Environment Detected", findings[0].title)
    }

    @Test
    fun virtualXposed_detected() {
        val result = decompileResult(mapOf("A.java" to "import io.va.exposed.VirtualXposed;"))
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Virtual App Environment Detected" })
    }

    @Test
    fun virtualAppFramework_detected() {
        val result = decompileResult(mapOf("A.java" to "VirtualCore.getInstance()"))
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Virtual App Environment Detected" })
    }

    @Test
    fun virtualAppWithEscapeAttempt_highSeverity() {
        val code = """
            import com.lbe.parallel.activity;
            import VirtualApp;
            getPackageManager();
            getInstalledPackages();
            Intent.FLAG_ACTIVITY_NEW_TASK;
            startActivity(intent);
        """.trimIndent()
        val result = decompileResult(mapOf("A.java" to code))
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.severity == Severity.HIGH && it.title == "Virtual App Escape Attempt" })
    }

    @Test
    fun virtualAppWithoutEscape_mediumSeverity() {
        val result = decompileResult(mapOf("A.java" to "import com.lbe.parallel; class A {}"))
        val findings = detector.analyze(result)
        assertEquals(Severity.MEDIUM, findings[0].severity)
    }

    @Test
    fun caseInsensitiveMatching() {
        val result = decompileResult(mapOf("A.java" to "COM.LBE.PARALLEL.SOME_CLASS"))
        val findings = detector.analyze(result)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun patternInSmali_detected() {
        val result = decompileResult(
            javaSource = mapOf("A.java" to "package clean;"),
            smaliSource = mapOf("A.smali" to "com.lbe.parallel\ncom.tencent.qqpimsecure")
        )
        assertFalse(detector.analyze(result).isEmpty())
    }
}
