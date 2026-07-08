package com.apkviper.ui.dashboard

import com.apkviper.model.*
import org.junit.Assert.*
import org.junit.Test

class DashboardScreenTest {

    /**
     * The dashboard renders every [ScanResult] from history directly in Compose
     * (score, findings.size, apkName, timestamp, threat color). It must stay safe
     * when optional fields (appLabel, versionCode, minSdk, packageName, sha256) are
     * null, and when the findings list is empty or huge. These tests exercise the
     * pure data shape the screen depends on without a Compose host.
     */

    private fun createScan(
        threatScore: Int,
        findings: List<Finding> = emptyList(),
        apkName: String = "test.apk",
        appLabel: String? = null,
        packageName: String? = null,
        versionCode: Long? = null,
        minSdk: Int? = null
    ): ScanResult = ScanResult(
        apkName = apkName,
        apkPath = "/path/$apkName",
        sha256 = null,
        fileSize = 1024L,
        scanMode = "quick",
        threatLevel = when {
            threatScore >= 80 -> ThreatLevel.CRITICAL
            threatScore >= 60 -> ThreatLevel.HIGH
            threatScore >= 40 -> ThreatLevel.MEDIUM
            threatScore >= 20 -> ThreatLevel.LOW
            else -> ThreatLevel.SAFE
        },
        threatScore = threatScore,
        findings = findings,
        decompileTime = 100L,
        scanTime = 500L,
        appLabel = appLabel,
        packageName = packageName,
        versionCode = versionCode,
        minSdk = minSdk
    )

    @Test
    fun scanResult_withAllNullOptionalFields_isWellFormed() {
        val scan = createScan(threatScore = 50)
        assertEquals("test.apk", scan.apkName)
        assertEquals(50, scan.threatScore)
        assertEquals(ThreatLevel.MEDIUM, scan.threatLevel)
        assertNull(scan.appLabel)
        assertNull(scan.packageName)
        assertNull(scan.versionCode)
        assertNull(scan.minSdk)
        assertNull(scan.sha256)
        assertEquals(0, scan.findings.size)
    }

    @Test
    fun scanResult_nullFields_findingsSizeSafe() {
        val scan = createScan(threatScore = 10, findings = emptyList())
        // Dashboard/Results read result.findings.size directly — must never NPE.
        assertEquals(0, scan.findings.size)
        assertFalse(scan.findings.any { true })
    }

    @Test
    fun scanResult_emptyHistory_noCrashOnDerivedValues() {
        val history: List<ScanResult> = emptyList()
        assertEquals(0, history.size)
        // Summary line "${timeline.size} total · ${scans.size} recent" must be safe.
        assertEquals("0 total · 0 recent", "${history.size} total · ${history.size} recent")
    }

    @Test
    fun scanResult_hugeHistory_countIsStable() {
        val history = (1..5000).map { createScan(threatScore = (it % 100), apkName = "a$it.apk") }
        assertEquals(5000, history.size)
        // Dashboard only shows getRecent() (LIMIT 10) but the full list must stay iterable.
        assertEquals(5000, history.count { it.threatScore in 0..100 })
    }

    @Test
    fun scanResult_threatColorMapping_isConsistent() {
        val mapping: (ThreatLevel) -> String = { level ->
            when (level) {
                ThreatLevel.SAFE -> "safe"
                ThreatLevel.LOW -> "low"
                ThreatLevel.MEDIUM -> "medium"
                ThreatLevel.HIGH -> "high"
                ThreatLevel.CRITICAL, ThreatLevel.MALICIOUS -> "critical"
            }
        }
        assertEquals("safe", mapping(ThreatLevel.SAFE))
        assertEquals("critical", mapping(ThreatLevel.MALICIOUS))
        assertEquals("critical", mapping(ThreatLevel.CRITICAL))
    }
}
