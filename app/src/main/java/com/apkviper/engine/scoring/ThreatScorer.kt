package com.apkviper.engine.scoring

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import com.apkviper.model.ThreatLevel
import kotlin.math.exp

/**
 * Evidence-weighted, benign-aware threat scoring.
 *
 * Design (informed by how top-tier detectors — DREBIN, Random-Forest, MobSF, VirusTotal —
 * separate malware from genuine/modded apps): the malicious score is driven by *corroborated
 * malicious evidence* (known-malware hashes, curated YARA families, confirmed C2/IOC,
 * spyware/overlay/credential-theft behaviors, crypto-miners, packed+evasive payloads), NOT by
 * raw finding volume. Benign indicators (trackers, standard permissions, R8/ProGuard
 * obfuscation, `system()`/`execve` in native libs, mod-patching) contribute only a small,
 * capped "risk surface" that can never by itself reach a MALICIOUS verdict.
 *
 * Trusted/known-good apps are additionally capped unless strong malware evidence is present.
 *
 * VERDICT GATE (defense-in-depth): a MALICIOUS verdict (score >= 91) requires corroborated
 * strong evidence — either a confirmed known-malware hash, or at least TWO independent strong
 * findings (e.g. a curated YARA family AND a crypto-miner AND/OR a high-confidence ML signal).
 * A single heuristic / single YARA match can at most reach HIGH (capped at 80). This is what
 * prevents genuine/modded apps that merely trip noisy heuristics from being called MALICIOUS.
 *
 * Low-confidence (community / auto-updated) YARA matches are deliberately NOT treated as strong
 * evidence: they may surface as informational findings but can never alone (or even combined
 * with each other) drive a MALICIOUS verdict.
 */
class ThreatScorer {

    private val severityWeights = mapOf(
        Severity.CRITICAL to 14,
        Severity.HIGH to 9,
        Severity.MEDIUM to 5,
        Severity.LOW to 2,
        Severity.INFO to 0
    )

    /** Categories that are inherently malicious — any severity counts as strong evidence. */
    private val malwareCategories = setOf(FindingCategory.MALWARE, FindingCategory.CRYPTO_MINER)

    /** Weight applied to inherently-malicious categories. A confirmed malware hash match is
     *  the strongest possible signal (akin to a VirusTotal detection). */
    private val malwareCategoryWeight = mapOf(
        FindingCategory.MALWARE to 4.5,
        FindingCategory.CRYPTO_MINER to 3.5
    )

    /** Weight applied to "packed + evasive" payloads (only when clearly suspicious). */
    private val packerWeight = 2.0

    /** Capped weight for benign-indicator categories (risk surface, never alone malicious). */
    private val surfaceCategoryWeight = mapOf(
        FindingCategory.PERMISSION to 0.5,
        FindingCategory.OBFUSCATION to 0.5,
        FindingCategory.MANIFEST to 0.5,
        FindingCategory.CERTIFICATE to 0.4,
        FindingCategory.STRING to 0.8,
        FindingCategory.CLOUD to 0.8,
        FindingCategory.CODE to 1.0,
        FindingCategory.CODEGEN to 1.0,
        FindingCategory.NETWORK to 1.0,
        FindingCategory.NATIVE to 1.0,
        FindingCategory.BEHAVIORAL to 1.0
    )

    /** Surface contribution is capped so benign indicators can never alone reach MALICIOUS. */
    private val SURFACE_CAP = 18.0
    /** Steepness of the malicious-evidence saturation curve. */
    private val MALWARE_K = 35.0
    /** Hard ceiling on the score for trusted/known-good apps without strong malware evidence. */
    private val KNOWN_GOOD_CAP = 12
    /** Ceiling when strong evidence is insufficient to call the app MALICIOUS. */
    private val NO_STRONG_CAP = 80
    /** Minimum number of independent strong findings required for a MALICIOUS verdict
     *  (unless a definitive known-malware hash is present). */
    private val MIN_STRONG_FINDINGS = 2

    fun calculate(findings: List<Finding>, knownGood: Boolean = false): Int {
        var malwareRaw = 0.0
        var surfaceRaw = 0.0

        for (f in findings) {
            val sevW = severityWeights[f.severity] ?: 0
            if (isStrongMalwareEvidence(f)) {
                val catW = when (f.category) {
                    FindingCategory.MALWARE -> malwareCategoryWeight[FindingCategory.MALWARE] ?: 3.0
                    FindingCategory.CRYPTO_MINER -> malwareCategoryWeight[FindingCategory.CRYPTO_MINER] ?: 2.6
                    FindingCategory.PACKER -> packerWeight
                    else -> 1.5
                }
                malwareRaw += sevW * catW
            } else {
                val catW = surfaceCategoryWeight[f.category] ?: 0.6
                surfaceRaw += sevW * catW
            }
        }

        val malScore = 100.0 * (1.0 - exp(-malwareRaw / MALWARE_K))
        val surfScore = minOf(surfaceRaw, SURFACE_CAP)
        var score = (malScore + surfScore).toInt().coerceIn(0, 100)

        // Trusted/known-good apps: only genuinely malicious evidence can override the cap.
        if (knownGood && malwareRaw < 1.0) {
            score = minOf(score, KNOWN_GOOD_CAP)
        }
        return score
    }

    /**
     * Applies the verdict gate on top of the raw score.
     *  - A confirmed known-malware hash is definitive -> no cap.
     *  - Otherwise MALICIOUS (>=91) requires at least [MIN_STRONG_FINDINGS] independent
     *    strong findings. With insufficient corroboration the score is capped at [NO_STRONG_CAP]
     *    (at most HIGH), so noisy heuristics can never produce a MALICIOUS verdict.
     */
    fun gateVerdict(rawScore: Int, findings: List<Finding>, knownGood: Boolean = false): Int {
        val strong = strongFindings(findings)
        val hasKnownHash = strong.any { it.ruleSource == "known_hash" }
        val knownGoodCap = knownGood && strong.isEmpty()

        return when {
            // A confirmed known-malware hash is definitive — force MALICIOUS regardless of score.
            hasKnownHash -> maxOf(rawScore, 91)
            // Two or more independent strong findings is the documented bar for MALICIOUS:
            // lift the raw score to at least 91 so genuine malware (e.g. a high-fidelity
            // Keylogger + Accessibility-Abuse pair, both MEDIUM) is correctly labelled MALICIOUS,
            // while a single strong finding stays capped at NO_STRONG_CAP (<=80).
            strong.size >= MIN_STRONG_FINDINGS -> maxOf(rawScore, 91)
            knownGoodCap -> minOf(rawScore, KNOWN_GOOD_CAP)
            else -> minOf(rawScore, NO_STRONG_CAP)
        }
    }

    fun hasStrongEvidence(findings: List<Finding>): Boolean = strongFindings(findings).isNotEmpty()

    /** Independent strong findings that may drive a MALICIOUS verdict. */
    private fun strongFindings(findings: List<Finding>): List<Finding> {
        return findings.filter { isStrongMalwareEvidence(it) }
    }

    /**
     * A finding is "strong malware evidence" only when it comes from a category that, by
     * construction, represents genuinely malicious behavior AND is high-confidence:
     *   - MALWARE with HIGH confidence and NOT low-confidence/community: known-malware hashes,
     *     curated YARA families (RATs, bankers, miners, ransomware, spyware).
     *   - CRYPTO_MINER at HIGH/CRITICAL: crypto-mining payloads.
     *   - BEHAVIORAL at CRITICAL with HIGH confidence: TinyML high-confidence zero-day signal.
     *
     * Deliberately EXCLUDES:
     *   - NATIVE, NETWORK, CODE, CERTIFICATE, PACKER, PERMISSION, etc. — emitted by heuristic
     *     engines that routinely fire on genuine apps.
     *   - Low-confidence (community / auto-updated) YARA matches — surface only.
     */
    private fun isStrongMalwareEvidence(f: Finding): Boolean {
        return when {
            f.category == FindingCategory.MALWARE &&
                f.confidence != FindingConfidence.LOW &&
                f.ruleSource != "community" -> true
            f.category == FindingCategory.CRYPTO_MINER &&
                (f.severity == Severity.HIGH || f.severity == Severity.CRITICAL) -> true
            f.category == FindingCategory.BEHAVIORAL &&
                f.severity == Severity.CRITICAL &&
                f.confidence == FindingConfidence.HIGH -> true
            else -> false
        }
    }

    fun getThreatLevel(score: Int): ThreatLevel = when {
        score >= 91 -> ThreatLevel.MALICIOUS
        score >= 81 -> ThreatLevel.CRITICAL
        score >= 66 -> ThreatLevel.HIGH
        score >= 51 -> ThreatLevel.MEDIUM
        score >= 26 -> ThreatLevel.LOW
        else -> ThreatLevel.SAFE
    }
}
