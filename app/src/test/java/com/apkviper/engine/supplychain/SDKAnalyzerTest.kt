package com.apkviper.engine.supplychain

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class SDKAnalyzerTest {
    private val analyzer = SDKAnalyzer()

    private fun decompileResult(code: String): DecompileResult =
        DecompileResult(mapOf("A.java" to code), mapOf(), "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun noSdks_returnsEmpty() {
        val result = decompileResult("package com.example; class A {}")
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun googleFirebase_detected() {
        val result = decompileResult("import com.google.firebase;")
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Firebase") || it.title.contains("SBOM") })
    }

    @Test
    fun facebookSdk_withCve_detected() {
        val result = decompileResult("import com.facebook.FacebookSdk;")
        val findings = analyzer.analyze(result)
        assertTrue("CVE should be in description", findings.any { it.description.contains("CVE-2023-41040") })
    }

    @Test
    fun okhttp_withCve_detected() {
        val result = decompileResult("import okhttp3.OkHttpClient;")
        val findings = analyzer.analyze(result)
        assertTrue("CVE should be in description", findings.any { it.description.contains("CVE-2023-45897") })
    }

    @Test
    fun riskySdk_mediumSeverity() {
        val result = decompileResult("import com.appsflyer.AppsFlyerLib;")
        val findings = analyzer.analyze(result)
        val risky = findings.find { it.title.contains("Risky SDK") }
        assertNotNull(risky)
        assertTrue(risky!!.severity >= Severity.MEDIUM)
    }

    @Test
    fun lowRiskSdk_noRiskyFinding() {
        val result = decompileResult("import androidx.room.Room;")
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title.contains("Risky SDK") })
    }

    @Test
    fun sbomGenerated_whenSdksFound() {
        val result = decompileResult("import com.google.firebase;")
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Software Bill of Materials (SBOM)" })
    }

    @Test
    fun dynamicCodeLoading_detected() {
        val result = decompileResult("DexClassLoader loader = new DexClassLoader();")
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Dynamic Code Loading" })
    }

    @Test
    fun multipleSdksInSameCategory_groupedCorrectly() {
        val result = decompileResult("""
            import com.appsflyer.AppsFlyerLib;
            import com.adjust.Adjust;
            import com.google.firebase;
        """.trimIndent())
        val findings = analyzer.analyze(result)
        val sbom = findings.find { it.title == "Software Bill of Materials (SBOM)" }
        assertNotNull(sbom)
        assertTrue(sbom!!.details!!.contains("Analytics"))
    }
}
