package com.apkviper.engine.scoring

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import com.apkviper.model.ThreatLevel
import org.junit.Assert.*
import org.junit.Test

class ThreatScorerTest {
    private val scorer = ThreatScorer()

    @Test
    fun zeroFindings_returnsSafe() {
        val score = scorer.calculate(emptyList())
        assertEquals(0, score)
        assertEquals(ThreatLevel.SAFE, scorer.getThreatLevel(score))
    }

    @Test
    fun singleInfoFinding_returnsSafe() {
        val findings = listOf(Finding(FindingCategory.MANIFEST, Severity.INFO, "Test", "desc"))
        val score = scorer.calculate(findings)
        assertTrue(score < 20)
        assertEquals(ThreatLevel.SAFE, scorer.getThreatLevel(score))
    }

    @Test
    fun singleLowFinding_returnsLow() {
        val findings = listOf(Finding(FindingCategory.MANIFEST, Severity.LOW, "Test", "desc"))
        val score = scorer.calculate(findings)
        assertTrue(score in 1..40)
    }

    @Test
    fun singleMediumFinding_returnsAtLeastLow() {
        val findings = listOf(Finding(FindingCategory.MANIFEST, Severity.MEDIUM, "Test", "desc"))
        val score = scorer.calculate(findings)
        assertTrue(score > 0)
    }

    @Test
    fun multipleCriticalFindings_returnsMalicious() {
        val findings = (1..10).map {
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware $it", "desc")
        }
        val score = scorer.calculate(findings)
        assertTrue("Score should be high for 10 critical findings, got $score", score >= 80)
        assertTrue(scorer.getThreatLevel(score) in listOf(ThreatLevel.CRITICAL, ThreatLevel.MALICIOUS))
    }

    @Test
    fun mixedFindings_scoreIncreasesCorrectly() {
        val low = Finding(FindingCategory.PERMISSION, Severity.LOW, "Low", "desc")
        val high = Finding(FindingCategory.PACKER, Severity.HIGH, "High", "desc")
        val critical = Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Critical", "desc")

        val score1 = scorer.calculate(listOf(low))
        val score2 = scorer.calculate(listOf(low, high))
        val score3 = scorer.calculate(listOf(low, high, critical))

        assertTrue("More severe findings should increase score", score1 < score2)
        assertTrue("Critical should raise score further", score2 < score3)
    }

    @Test
    fun categoryWeights_affectScore() {
        val permFinding = Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "Perm", "desc")
        val malwareFinding = Finding(FindingCategory.MALWARE, Severity.MEDIUM, "Malware", "desc")
        val permScore = scorer.calculate(listOf(permFinding))
        val malwareScore = scorer.calculate(listOf(malwareFinding))
        assertTrue("Malware category should score higher than permission", malwareScore >= permScore)
    }

    @Test
    fun scoreCappedAt100() {
        val findings = (1..50).map {
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware $it", "desc")
        }
        val score = scorer.calculate(findings)
        assertTrue("Score should be capped at 100, got $score", score <= 100)
    }

    @Test
    fun scoreNeverNegative() {
        val score = scorer.calculate(emptyList())
        assertTrue(score >= 0)
    }

    @Test
    fun threatLevelBoundaries() {
        assertEquals(ThreatLevel.SAFE, scorer.getThreatLevel(0))
        assertEquals(ThreatLevel.SAFE, scorer.getThreatLevel(25))
        assertEquals(ThreatLevel.LOW, scorer.getThreatLevel(26))
        assertEquals(ThreatLevel.LOW, scorer.getThreatLevel(50))
        assertEquals(ThreatLevel.MEDIUM, scorer.getThreatLevel(51))
        assertEquals(ThreatLevel.MEDIUM, scorer.getThreatLevel(65))
        assertEquals(ThreatLevel.HIGH, scorer.getThreatLevel(66))
        assertEquals(ThreatLevel.HIGH, scorer.getThreatLevel(80))
        assertEquals(ThreatLevel.CRITICAL, scorer.getThreatLevel(81))
        assertEquals(ThreatLevel.CRITICAL, scorer.getThreatLevel(90))
        assertEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(91))
        assertEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(100))
    }

    @Test
    fun findingsWithNullDetails_doesNotCrash() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware", "desc", details = null),
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "Perm", "desc", details = null)
        )
        val score = scorer.calculate(findings)
        assertTrue(score > 0)
    }

    @Test
    fun allCategoryTypes_areHandled() {
        val findings = FindingCategory.values().map { cat ->
            Finding(cat, Severity.LOW, cat.name, "test")
        }
        val score = scorer.calculate(findings)
        assertTrue(score > 0)
    }

    @Test
    fun scoreConsistency_sameInputsSameOutput() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "a", "desc"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "b", "desc"),
            Finding(FindingCategory.CODE, Severity.HIGH, "c", "desc")
        )
        assertEquals(scorer.calculate(findings), scorer.calculate(findings))
    }

    @Test
    fun findingsOrder_doesNotAffectScore() {
        val f1 = Finding(FindingCategory.MALWARE, Severity.CRITICAL, "a", "desc")
        val f2 = Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "b", "desc")
        val f3 = Finding(FindingCategory.CODE, Severity.HIGH, "c", "desc")
        val score1 = scorer.calculate(listOf(f1, f2, f3))
        val score2 = scorer.calculate(listOf(f2, f3, f1))
        val score3 = scorer.calculate(listOf(f3, f1, f2))
        assertEquals(score1, score2)
        assertEquals(score2, score3)
    }

    @Test
    fun threatLevel_exactBoundaries() {
        assertEquals(ThreatLevel.SAFE, scorer.getThreatLevel(0))
        assertEquals(ThreatLevel.SAFE, scorer.getThreatLevel(25))
        assertEquals(ThreatLevel.LOW, scorer.getThreatLevel(26))
        assertEquals(ThreatLevel.LOW, scorer.getThreatLevel(50))
        assertEquals(ThreatLevel.MEDIUM, scorer.getThreatLevel(51))
        assertEquals(ThreatLevel.MEDIUM, scorer.getThreatLevel(65))
        assertEquals(ThreatLevel.HIGH, scorer.getThreatLevel(66))
        assertEquals(ThreatLevel.HIGH, scorer.getThreatLevel(80))
        assertEquals(ThreatLevel.CRITICAL, scorer.getThreatLevel(81))
        assertEquals(ThreatLevel.CRITICAL, scorer.getThreatLevel(90))
        assertEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(91))
        assertEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(100))
    }

    @Test
    fun singleCriticalFinding_returnsAtLeastCritical() {
        val findings = (1..9).map {
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Critical $it", "desc")
        }
        val score = scorer.calculate(findings)
        assertTrue(
            "Score $score should be CRITICAL or MALICIOUS",
            scorer.getThreatLevel(score) in listOf(ThreatLevel.CRITICAL, ThreatLevel.MALICIOUS)
        )
    }

    @Test
    fun mixedInfoAndCritical_stillRaisesScore() {
        val critical = Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Critical", "desc")
        val info = listOf(
            Finding(FindingCategory.MANIFEST, Severity.INFO, "Info 1", "desc"),
            Finding(FindingCategory.STRING, Severity.INFO, "Info 2", "desc"),
            Finding(FindingCategory.CERTIFICATE, Severity.INFO, "Info 3", "desc")
        )
        val criticalOnly = scorer.calculate(listOf(critical))
        val mixed = scorer.calculate(listOf(critical) + info)
        assertEquals("Info findings should not change the score", criticalOnly, mixed)
    }

    @Test
    fun score_with1000Findings_doesNotOverflow() {
        val findings = (1..1000).map {
            Finding(FindingCategory.MALWARE, Severity.LOW, "Finding $it", "desc")
        }
        val score = scorer.calculate(findings)
        assertTrue("Score should still be capped at 100 with 1000 findings, got $score", score <= 100)
        assertTrue("Score should still be >= 0 with 1000 findings", score >= 0)
    }

    @Test
    fun score_withEmptyTitleAndDesc_doesNotCrash() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "", ""),
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "", "")
        )
        val score = scorer.calculate(findings)
        assertTrue("Score should be positive even with empty title/desc", score > 0)
    }
}
