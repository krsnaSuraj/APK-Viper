package com.apkviper.engine.scoring

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import com.apkviper.model.ThreatLevel
import org.junit.Assert.*
import org.junit.Test

class ThreatScorerGateTest {

    private fun mal(severity: Severity, confidence: FindingConfidence = FindingConfidence.HIGH, source: String? = "curated") =
        Finding(FindingCategory.MALWARE, severity, "t", "d", confidence = confidence, ruleSource = source)

    private fun knownHash() =
        Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Known Malware: x", "d", confidence = FindingConfidence.HIGH, ruleSource = "known_hash")

    @Test
    fun singleCuratedYara_cappedAtHigh_notMalicious() {
        val scorer = ThreatScorer()
        val findings = listOf(mal(Severity.CRITICAL))
        val raw = scorer.calculate(findings)
        assertTrue("raw should be high", raw >= 80)
        val gated = scorer.gateVerdict(raw, findings)
        assertTrue("single YARA must be capped <= 80 (got $gated)", gated <= 80)
        assertEquals(ThreatLevel.HIGH, scorer.getThreatLevel(gated))
        assertNotEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(gated))
    }

    @Test
    fun twoIndependentStrongSources_allowsMalicious() {
        val scorer = ThreatScorer()
        // Two distinct curated MALWARE CRITICAL findings => 2 strong sources.
        val findings = listOf(mal(Severity.CRITICAL), mal(Severity.CRITICAL))
        val raw = scorer.calculate(findings)
        assertTrue("raw should reach >=91 (got $raw)", raw >= 91)
        val gated = scorer.gateVerdict(raw, findings)
        assertEquals(raw, gated)
        assertEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(gated))
    }

    @Test
    fun twoMediumHighFidelityMalware_isMalicious() {
        // High-fidelity MEDIUM MALWARE patterns (e.g. MalwarePatternDetector's Keylogger +
        // Accessibility Abuse combos) are the realistic "2+ strong findings" case. On their own
        // the raw score is only ~HIGH, but the gate must still force a MALICIOUS verdict.
        val scorer = ThreatScorer()
        val findings = listOf(mal(Severity.MEDIUM), mal(Severity.MEDIUM))
        val raw = scorer.calculate(findings)
        assertTrue("raw alone is below 91 (got $raw)", raw < 91)
        val gated = scorer.gateVerdict(raw, findings)
        assertEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(gated))
    }

    @Test
    fun knownHash_isDefinitiveMalicious() {
        val scorer = ThreatScorer()
        val findings = listOf(knownHash())
        val raw = scorer.calculate(findings)
        val gated = scorer.gateVerdict(raw, findings)
        assertTrue("known hash must force >=91 (got $gated)", gated >= 91)
        assertEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(gated))
    }

    @Test
    fun communityLowConfidence_notStrongEvidence() {
        val scorer = ThreatScorer()
        val findings = listOf(mal(Severity.CRITICAL, FindingConfidence.LOW, "community"))
        val raw = scorer.calculate(findings)
        val gated = scorer.gateVerdict(raw, findings)
        assertTrue("community low-confidence must be capped <=80 (got $gated)", gated <= 80)
        assertFalse("community rule must NOT be strong evidence", scorer.hasStrongEvidence(findings))
    }

    @Test
    fun packedHighSeverity_notStrongEvidence() {
        val scorer = ThreatScorer()
        val findings = listOf(Finding(FindingCategory.PACKER, Severity.CRITICAL, "p", "d"))
        assertFalse("PACKER must not be strong evidence", scorer.hasStrongEvidence(findings))
    }

    @Test
    fun knownGood_withoutStrongEvidence_cappedLow() {
        val scorer = ThreatScorer()
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "p", "d"),
            Finding(FindingCategory.CERTIFICATE, Severity.INFO, "c", "d"),
            Finding(FindingCategory.NATIVE, Severity.LOW, "n", "d")
        )
        val raw = scorer.calculate(findings, knownGood = true)
        val gated = scorer.gateVerdict(raw, findings, knownGood = true)
        assertTrue("known-good without strong evidence capped <=12 (got $gated)", gated <= 12)
    }

    @Test
    fun heuristicLowConfidenceMalware_moddedApp_notMalicious() {
        // Regression: a modded game with ad SDKs trips several heuristic MALWARE rules. With
        // LOW confidence those are surface-only and must never drive a MALICIOUS verdict.
        val scorer = ThreatScorer()
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Overlay Phishing", "ad SDK API chain",
                confidence = FindingConfidence.LOW, ruleSource = "heuristic"),
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Confirmed Data Exfiltration Chain", "ad SDK signals",
                confidence = FindingConfidence.LOW, ruleSource = "heuristic"),
            Finding(FindingCategory.NATIVE, Severity.CRITICAL, "Reverse Shell Capability", "system() in lib"),
            Finding(FindingCategory.NETWORK, Severity.HIGH, "Suspicious Socket", "outbound socket")
        )
        val raw = scorer.calculate(findings)
        val gated = scorer.gateVerdict(raw, findings)
        assertFalse("heuristic LOW MALWARE must NOT be strong evidence", scorer.hasStrongEvidence(findings))
        assertTrue("gated score must be <=80 (got $gated)", gated <= 80)
        assertNotEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(gated))
    }

    @Test
    fun singleMediumHighFidelity_isStrongButCappedBelowMalicious() {
        // A single high-fidelity MEDIUM MALWARE finding (e.g. lone Keylogger) IS strong evidence
        // (so the classifier may label it) but, with no second corroborating finding, the scorer
        // gate must NOT promote it to MALICIOUS — it stays capped at <=80 (HIGH).
        val scorer = ThreatScorer()
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.MEDIUM, "Keylogger", "KeyEvent + InputMethodService",
                confidence = FindingConfidence.MEDIUM, ruleSource = "heuristic")
        )
        assertTrue("single high-fidelity MEDIUM is strong evidence", scorer.hasStrongEvidence(findings))
        val raw = scorer.calculate(findings)
        val gated = scorer.gateVerdict(raw, findings)
        assertTrue("single strong finding must be capped <=80 (got $gated)", gated <= 80)
        assertNotEquals(ThreatLevel.MALICIOUS, scorer.getThreatLevel(gated))
    }

    @Test
    fun emptyFindings_knownGood_returnsSafe() {
        val scorer = ThreatScorer()
        assertEquals(0, scorer.calculate(emptyList(), knownGood = true))
        assertEquals(ThreatLevel.SAFE, scorer.getThreatLevel(scorer.gateVerdict(0, emptyList(), knownGood = true)))
    }
}
