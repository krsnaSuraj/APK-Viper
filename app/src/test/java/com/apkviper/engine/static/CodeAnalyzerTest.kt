package com.apkviper.engine.static

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class CodeAnalyzerTest {
    private val analyzer = CodeAnalyzer()

    private fun decompileResult(
        javaSource: Map<String, String> = mapOf("A.java" to ""),
        smaliSource: Map<String, String> = mapOf()
    ): DecompileResult =
        DecompileResult(javaSource, smaliSource, "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun cleanCode_noFindings() {
        val result = decompileResult(mapOf("A.java" to "package com.example; class A { void foo() {} }"))
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun runtimeExec_detected() {
        val result = decompileResult(mapOf("A.java" to "Runtime.getRuntime().exec(\"id\")"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Runtime.exec") })
        assertEquals(Severity.HIGH, findings.find { it.title.contains("Runtime.exec") }!!.severity)
    }

    @Test
    fun processBuilder_detected() {
        val result = decompileResult(mapOf("A.java" to "ProcessBuilder pb = new ProcessBuilder()"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("ProcessBuilder") })
        assertEquals(Severity.HIGH, findings.find { it.title.contains("ProcessBuilder") }!!.severity)
    }

    @Test
    fun dexClassLoader_detected() {
        val result = decompileResult(mapOf("A.java" to "DexClassLoader loader = new DexClassLoader()"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("DEX loading") })
    }

    @Test
    fun addJavascriptInterface_detected() {
        val result = decompileResult(mapOf("A.java" to "webView.addJavascriptInterface(this, \"bridge\")"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("JavaScript interface") })
    }

    @Test
    fun javascriptUrlInjection_detected() {
        val result = decompileResult(mapOf("A.java" to """loadUrl("javascript:alert(1)")"""))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("JavaScript injection") })
    }

    @Test
    fun devicePolicyManager_detected() {
        val result = decompileResult(mapOf("A.java" to "DevicePolicyManager dpm = getSystemService()"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Device admin") })
        assertEquals(Severity.MEDIUM, findings.find { it.title.contains("Device admin") }!!.severity)
    }

    @Test
    fun killBackgroundProcesses_detected() {
        val result = decompileResult(mapOf("A.java" to "killBackgroundProcesses(packageName)"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Background process killing") })
    }

    @Test
    fun getRunningAppProcesses_detected() {
        val result = decompileResult(mapOf("A.java" to "getRunningAppProcesses()"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Process enumeration") })
    }

    @Test
    fun multiplePatternsInSingleFile_allDetected() {
        val code = """
            Runtime.getRuntime().exec("ls")
            ProcessBuilder pb = new ProcessBuilder()
            DexClassLoader loader = new DexClassLoader()
        """.trimIndent()
        val result = decompileResult(mapOf("Main.java" to code))
        val findings = analyzer.analyze(result)
        assertEquals(3, findings.size)
    }

    @Test
    fun patternsInMultipleFiles_allDetected() {
        val javaSource = mapOf(
            "Main.java" to "Runtime.getRuntime().exec(\"ls\")",
            "Helper.java" to "DevicePolicyManager dpm = null"
        )
        val findings = analyzer.analyze(decompileResult(javaSource))
        assertEquals(2, findings.size)
    }

    @Test
    fun smaliSourceScannedToo() {
        val result = decompileResult(
            javaSource = mapOf("A.java" to "clean code"),
            smaliSource = mapOf("A.smali" to "Runtime.getRuntime().exec")
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Runtime.exec") })
    }

    @Test
    fun findingsHaveCorrectCategory() {
        val result = decompileResult(mapOf("A.java" to "Runtime.getRuntime().exec(\"id\")"))
        val findings = analyzer.analyze(result)
        findings.forEach { assertEquals(FindingCategory.CODE, it.category) }
    }

    @Test
    fun filenameInDescription() {
        val result = decompileResult(mapOf("Evil.java" to "Runtime.getRuntime().exec(\"id\")"))
        val findings = analyzer.analyze(result)
        val finding = findings.find { it.title.contains("Runtime.exec") }
        assertNotNull(finding)
        assertTrue(finding!!.description.contains("Evil.java"))
        assertEquals("Evil.java", finding.file)
    }

    @Test
    fun patternInBothJavaAndSmali_dedupNotExpected() {
        val result = decompileResult(
            javaSource = mapOf("A.java" to "Runtime.getRuntime().exec"),
            smaliSource = mapOf("A.smali" to "Runtime.getRuntime().exec")
        )
        val findings = analyzer.analyze(result)
        assertEquals(2, findings.size)
    }

    @Test
    fun emptySource_noFindings() {
        val result = decompileResult(mapOf())
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun sourceWithEmptyString_noFindings() {
        val result = decompileResult(mapOf("A.java" to ""))
        assertTrue(analyzer.analyze(result).isEmpty())
    }
}
