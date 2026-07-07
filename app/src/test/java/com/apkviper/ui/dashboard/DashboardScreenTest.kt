package com.apkviper.ui.dashboard

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.ScanResult
import com.apkviper.model.Severity
import com.apkviper.model.ThreatLevel
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class DashboardScreenTest {

    // Replicates the score delta logic from DashboardScreen.refresh()
    private fun computeScoreDelta(scans: List<ScanResult>, timeline: List<ScanResult>): Int {
        val lastScan = scans.firstOrNull()
        val lastPkg = lastScan?.packageName
        val samePkg = timeline.filter { it.packageName == lastPkg && lastPkg != null }
        return if (samePkg.size >= 2) {
            val sorted = samePkg.sortedBy { it.timestamp }
            sorted.last().threatScore - sorted[sorted.size - 2].threatScore
        } else 0
    }

    private fun createScan(
        packageName: String?,
        threatScore: Int,
        timestamp: Long,
        apkName: String = "${packageName ?: "unknown"}.apk",
        appLabel: String? = packageName?.substringAfterLast('.')
    ): ScanResult = ScanResult(
        apkName = apkName,
        apkPath = "/path/$apkName",
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
        findings = emptyList(),
        decompileTime = 100L,
        scanTime = 500L,
        appLabel = appLabel,
        packageName = packageName,
        timestamp = timestamp
    )

    // ── Edge case: empty data ──────────────────────────────────────

    @Test
    fun scoreDelta_noScans_returnsZero() {
        assertEquals(0, computeScoreDelta(emptyList(), emptyList()))
    }

    @Test
    fun scoreDelta_singleScan_returnsZero() {
        val scan = createScan("com.test", 50, 1000)
        assertEquals(0, computeScoreDelta(listOf(scan), listOf(scan)))
    }

    // ── Happy path: score increase ─────────────────────────────────

    @Test
    fun scoreDelta_samePackageTwoScans_returnsCorrectDelta() {
        val old = createScan("com.test", 30, 1000)
        val latest = createScan("com.test", 70, 2000)
        assertEquals(40, computeScoreDelta(listOf(latest), listOf(old, latest)))
    }

    @Test
    fun scoreDelta_samePackageScoreDecreased_returnsNegative() {
        val old = createScan("com.test", 80, 1000)
        val latest = createScan("com.test", 40, 2000)
        assertEquals(-40, computeScoreDelta(listOf(latest), listOf(old, latest)))
    }

    // ── Edge case: different packages ──────────────────────────────

    @Test
    fun scoreDelta_differentPackages_returnsZero() {
        val scanA = createScan("com.one", 50, 1000)
        val scanB = createScan("com.two", 70, 2000)
        assertEquals(0, computeScoreDelta(listOf(scanB), listOf(scanA, scanB)))
    }

    // ── Edge case: three scans, compares last two ──────────────────

    @Test
    fun scoreDelta_threeScansSamePackage_comparesLastTwo() {
        val early = createScan("com.test", 10, 1000)
        val middle = createScan("com.test", 50, 2000)
        val latest = createScan("com.test", 90, 3000)
        // Should compare scan3 (90) vs scan2 (50) = 40
        assertEquals(40, computeScoreDelta(listOf(latest), listOf(early, middle, latest)))
    }

    // ── Edge case: null package name ───────────────────────────────

    @Test
    fun scoreDelta_lastScanHasNullPackageName_returnsZero() {
        val scan1 = createScan(null, 50, 1000)
        val scan2 = createScan(null, 70, 2000)
        assertEquals(0, computeScoreDelta(listOf(scan2), listOf(scan1, scan2)))
    }

    // ── Happy path: mixed packages, correct filtering ──────────────

    @Test
    fun scoreDelta_mixedPackages_filtersCorrectPackage() {
        val a1 = createScan("com.a", 20, 1000)
        val b1 = createScan("com.b", 60, 1500)
        val a2 = createScan("com.a", 80, 2000)
        // last scan is com.a, should compare com.a scans: 80 - 20 = 60
        assertEquals(60, computeScoreDelta(listOf(a2), listOf(a1, b1, a2)))
    }

    // ── Edge case: zero delta ──────────────────────────────────────

    @Test
    fun scoreDelta_unchangedScore_returnsZero() {
        val old = createScan("com.test", 50, 1000)
        val latest = createScan("com.test", 50, 2000)
        assertEquals(0, computeScoreDelta(listOf(latest), listOf(old, latest)))
    }

    // ── Edge case: max swing ───────────────────────────────────────

    @Test
    fun scoreDelta_scoreSwingFrom0To100_returnsMaxDelta() {
        val old = createScan("com.test", 0, 1000)
        val latest = createScan("com.test", 100, 2000)
        assertEquals(100, computeScoreDelta(listOf(latest), listOf(old, latest)))
    }

    @Test
    fun scoreDelta_negativeSwing_returnsNegativeOneHundred() {
        val old = createScan("com.test", 100, 1000)
        val latest = createScan("com.test", 0, 2000)
        assertEquals(-100, computeScoreDelta(listOf(latest), listOf(old, latest)))
    }

    // ── Edge case: timeline contains irrelevant packages ───────────

    @Test
    fun scoreDelta_onlyOneScanOfPackage_returnsZero() {
        val a = createScan("com.a", 50, 1000)
        val b1 = createScan("com.b", 30, 1500)
        val b2 = createScan("com.b", 70, 2000)
        // last scan is com.a, which has only 1 scan in timeline
        assertEquals(0, computeScoreDelta(listOf(a), listOf(a, b1, b2)))
    }

    // ── Edge case: multiple scans, unsorted input ──────────────────

    @Test
    fun scoreDelta_unsortedTimeline_sortsByTimestamp() {
        val old = createScan("com.test", 10, 3000)
        val latest = createScan("com.test", 90, 1000)
        // sorted: 90 (ts=1000) and 10 (ts=3000) -> latest=10, previous=90 -> 10-90 = -80
        assertEquals(-80, computeScoreDelta(listOf(latest), listOf(old, latest)))
    }
}
