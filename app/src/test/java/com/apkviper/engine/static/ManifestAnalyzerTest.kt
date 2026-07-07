package com.apkviper.engine.static

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class ManifestAnalyzerTest {
    private val analyzer = ManifestAnalyzer()

    private fun decompileResult(manifest: String): DecompileResult =
        DecompileResult(mapOf("A.java" to ""), mapOf(), manifest, mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun cleanManifest_noFindings() {
        val result = decompileResult("""<manifest package="com.example"></manifest>""")
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun exportedComponent_detected() {
        val result = decompileResult("""<activity android:exported="true"></activity>""")
        val findings = analyzer.analyze(result)
        assertEquals(1, findings.size)
        assertEquals(FindingCategory.MANIFEST, findings[0].category)
        assertEquals(Severity.MEDIUM, findings[0].severity)
        assertTrue(findings[0].title.contains("Exported Component"))
    }

    @Test
    fun debuggableFlag_detected() {
        val result = decompileResult("""<application android:debuggable="true">""")
        val findings = analyzer.analyze(result)
        assertEquals(1, findings.size)
        assertEquals(Severity.HIGH, findings[0].severity)
        assertTrue(findings[0].title.contains("Debuggable"))
    }

    @Test
    fun debuggableFlag_false_notDetected() {
        val result = decompileResult("""<application android:debuggable="false">""")
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun allowBackupEnabled_detected() {
        val result = decompileResult("""<application android:allowBackup="true">""")
        val findings = analyzer.analyze(result)
        assertEquals(1, findings.size)
        assertEquals(Severity.MEDIUM, findings[0].severity)
        assertTrue(findings[0].title.contains("Backup Enabled"))
    }

    @Test
    fun cleartextTraffic_detected() {
        val result = decompileResult("""<application android:usesCleartextTraffic="true">""")
        val findings = analyzer.analyze(result)
        assertEquals(1, findings.size)
        assertEquals(Severity.HIGH, findings[0].severity)
        assertTrue(findings[0].title.contains("Cleartext Traffic"))
    }

    @Test
    fun testOnlyFlag_detected() {
        val result = decompileResult("""<application android:testOnly="true">""")
        val findings = analyzer.analyze(result)
        assertEquals(1, findings.size)
        assertEquals(Severity.LOW, findings[0].severity)
        assertTrue(findings[0].title.contains("Test Build"))
    }

    @Test
    fun multipleFlags_allDetected() {
        val manifest = """
            <manifest>
                <activity android:exported="true"/>
                <application android:debuggable="true" android:allowBackup="true" />
            </manifest>
        """.trimIndent()
        val findings = analyzer.analyze(decompileResult(manifest))
        assertEquals(3, findings.size)
        val titles = findings.map { it.title }
        assertTrue(titles.any { it.contains("Exported Component") })
        assertTrue(titles.any { it.contains("Debuggable") })
        assertTrue(titles.any { it.contains("Backup Enabled") })
    }

    @Test
    fun allFlagsSimultaneously_detected() {
        val manifest = """
            <manifest>
                <activity android:exported="true"/>
                <application android:debuggable="true" android:allowBackup="true"
                    android:usesCleartextTraffic="true" android:testOnly="true" />
            </manifest>
        """.trimIndent()
        val findings = analyzer.analyze(decompileResult(manifest))
        assertEquals(5, findings.size)
    }

    @Test
    fun attributeValueAsPartOfLargerString_notDetected() {
        val result = decompileResult("""android:exported="true_disable"""")
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun emptyManifest_noFindings() {
        val result = decompileResult("")
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun caseSensitiveChecking() {
        val result = decompileResult("""<APPLICATION ANDROID:DEBUGGABLE="TRUE">""")
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun findingsHaveCorrectCategory() {
        val result = decompileResult("""<activity android:exported="true"/>""")
        val findings = analyzer.analyze(result)
        findings.forEach { assertEquals(FindingCategory.MANIFEST, it.category) }
    }
}
