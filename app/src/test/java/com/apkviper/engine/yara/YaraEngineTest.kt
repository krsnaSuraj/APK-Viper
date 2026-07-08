package com.apkviper.engine.yara

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class YaraEngineTest {
    private val engine = YaraEngine()

    companion object {
        private const val D = "DOLLAR"
    }

    private fun yara(src: String): String = src.replace(D, "$")

    private val testRules = yara("""
        rule Test_RAT_Detector {
            meta:
                description = "Detects RAT indicators"
                family = "RAT"
                severity = "critical"
            strings:
                ${D}s1 = "RemoteInput"
                ${D}s2 = "sendTextMessage"
            condition:
                ${D}s1 or ${D}s2
        }

        rule Test_Packer_Detector {
            meta:
                description = "Detects known packer"
                family = "Packer"
                severity = "high"
            strings:
                ${D}s1 = "UPX!"
                ${D}s2 = "protect.dll"
            condition:
                ${D}s1 or ${D}s2
        }
    """.trimIndent())

    private fun makeResult(
        javaSrc: Map<String, String> = emptyMap(),
        smaliSrc: Map<String, String> = emptyMap(),
        manifest: String = ""
    ): DecompileResult {
        return DecompileResult(
            javaSource = javaSrc, smaliSource = smaliSrc,
            manifest = manifest, resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
    }

    @Test
    fun scanBeforeLoad_returnsEmpty() {
        engine.loadRules("")
        val result = makeResult(javaSrc = mapOf("Test.java" to "RemoteInput"))
        val findings = engine.scan(result)
        assertTrue(findings.isEmpty())
    }

    @Test
    fun loadRules_thenScan_matchesPattern() {
        engine.loadRules(testRules)
        val result = makeResult(
            javaSrc = mapOf("Main.java" to "class Main { void test() { sendTextMessage(); } }"),
            manifest = "<manifest/>"
        )
        val findings = engine.scan(result)
        assertTrue("Should match RAT rule", findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("RAT", ignoreCase = true) })
    }

    @Test
    fun noMatch_returnsEmpty() {
        engine.loadRules(testRules)
        val result = makeResult(javaSrc = mapOf("Clean.java" to """System.out.println("hello")"""))
        val findings = engine.scan(result)
        assertTrue(findings.isEmpty())
    }

    @Test
    fun matchInSmali_isDetected() {
        engine.loadRules(testRules)
        val result = makeResult(smaliSrc = mapOf("classes.smali" to "UPX!"))
        val findings = engine.scan(result)
        assertTrue("Should match UPX in smali", findings.any { it.title.contains("Packer") })
    }

    @Test
    fun matchInManifest_isDetected() {
        engine.loadRules(testRules)
        val result = makeResult(manifest = "protect.dll")
        val findings = engine.scan(result)
        assertTrue("Should match protect.dll in manifest", findings.isNotEmpty())
    }

    @Test
    fun multipleRules_allChecked() {
        engine.loadRules(testRules)
        val result = makeResult(
            javaSrc = mapOf("Hack.java" to "sendTextMessage"),
            smaliSrc = mapOf("a.smali" to "UPX!"),
            manifest = "<manifest/>"
        )
        val findings = engine.scan(result)
        assertTrue("Should match both rules", findings.size >= 2)
    }

    @Test
    fun reloadRules_clearsPrevious() {
        engine.loadRules(testRules)
        engine.loadRules(yara("""rule Dummy { strings: ${D}a = "nothing" condition: false }"""))
        val result = makeResult(javaSrc = mapOf("M.java" to "sendTextMessage"))
        val findings = engine.scan(result)
        assertTrue("Old rules should be cleared", findings.isEmpty())
    }

    @Test
    fun largeContent_noCrash() {
        engine.loadRules(testRules)
        val largeSrc = mapOf("Large.java" to "a".repeat(100_000))
        val findings = engine.scan(makeResult(javaSrc = largeSrc))
        assertNotNull(findings)
    }

    @Test
    fun regexPattern_detectsCorrectly() {
        val regexRules = yara("""
            rule Regex_Test {
                strings:
                    ${D}r1 = /[Hh]ello/
                condition:
                    ${D}r1
            }
        """.trimIndent())
        engine.loadRules(regexRules)
        val result = makeResult(javaSrc = mapOf("A.java" to "hello world"))
        val findings = engine.scan(result)
        assertTrue("Regex pattern should match hello", findings.isNotEmpty())
    }

    @Test
    fun textPattern_caseInsensitive() {
        val caseRule = yara("""
            rule Case_Test {
                strings:
                    ${D}s1 = "sendTextMessage"
                condition:
                    ${D}s1
            }
        """.trimIndent())
        engine.loadRules(caseRule)
        val result = makeResult(javaSrc = mapOf("A.java" to "SENDTEXTMESSAGE"))
        val findings = engine.scan(result)
        assertTrue("Text matching should be case-insensitive", findings.isNotEmpty())
    }

    @Test
    fun emptyRules_scanReturnsEmpty() {
        engine.loadRules("")
        val result = makeResult(javaSrc = mapOf("A.java" to "test"))
        val findings = engine.scan(result)
        assertTrue(findings.isEmpty())
    }

    @Test
    fun invalidRule_noCrash() {
        engine.loadRules("this is not a valid yara rule at all $$$$")
        val result = makeResult(javaSrc = mapOf("A.java" to "test"))
        val findings = engine.scan(result)
        assertNotNull(findings)
    }

    @Test
    fun malformedHexPattern_noCrash() {
        val badHexRules = yara("""
            rule Bad_Hex {
                strings:
                    ${D}h1 = { NOTHEX }
                condition:
                    ${D}h1
            }
        """.trimIndent())
        engine.loadRules(badHexRules)
        val result = makeResult(javaSrc = mapOf("A.java" to "test"))
        val findings = engine.scan(result)
        assertNotNull(findings)
    }

    @Test
    fun malformedMeta_survives() {
        val badMeta = yara("""
            rule Meta_Test {
                meta:
                    = "bad_meta
                strings:
                    ${D}a = "test"
                condition:
                    ${D}a
            }
        """.trimIndent())
        engine.loadRules(badMeta)
        val result = makeResult(javaSrc = mapOf("A.java" to "test"))
        val findings = engine.scan(result)
        assertFalse("Should still find pattern even with bad meta", findings.isEmpty())
    }

    @Test
    fun ruleWithoutName_doesNotBreak() {
        val noName = yara("""
            rule {
                strings:
                    ${D}a = "x"
                condition:
                    ${D}a
            }
        """.trimIndent())
        engine.loadRules(noName)
        val result = makeResult(javaSrc = mapOf("A.java" to "x"))
        val findings = engine.scan(result)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun ahoCorasick_rejectsEmptyPatterns() {
        val ac = YaraEngine.AhoCorasick(emptyList())
        val result = ac.search("test")
        assertTrue(result.isEmpty())
    }

    @Test
    fun ahoCorasick_findsAllMatches() {
        val ac = YaraEngine.AhoCorasick(listOf("test", "pattern", "hello"))
        val result = ac.search("this is a test pattern, hello!")
        assertEquals(3, result.size)
    }

    @Test
    fun ahoCorasick_noMatch_returnsEmpty() {
        val ac = YaraEngine.AhoCorasick(listOf("xyz", "abc"))
        val result = ac.search("nothing matches here")
        assertTrue(result.isEmpty())
    }

    @Test
    fun ahoCorasick_overlappingPatterns() {
        val ac = YaraEngine.AhoCorasick(listOf("aa", "aaa", "aaaa"))
        val result = ac.search("aaaa")
        assertEquals(3, result.size)
        val positions = result.values.flatten().sorted()
        assertTrue(positions.isNotEmpty())
    }

    @Test
    fun ahoCorasick_singleCharPattern() {
        val ac = YaraEngine.AhoCorasick(listOf("a", "b", "c"))
        val result = ac.search("abc")
        assertEquals(3, result.size)
    }

    @Test
    fun ahoCorasick_emptyText() {
        val ac = YaraEngine.AhoCorasick(listOf("test"))
        val result = ac.search("")
        assertTrue(result.isEmpty())
    }

    @Test
    fun severity_byRuleName_rat() {
        assertSeverity("RAT_Detector", Severity.CRITICAL)
    }

    @Test
    fun severity_byRuleName_banker() {
        assertSeverity("Banker_Stealer", Severity.CRITICAL)
    }

    @Test
    fun severity_byRuleName_trojan() {
        assertSeverity("Trojan_Generic", Severity.CRITICAL)
    }

    @Test
    fun severity_byRuleName_spyware() {
        assertSeverity("Spyware_Agent", Severity.HIGH)
    }

    @Test
    fun severity_byRuleName_miner() {
        assertSeverity("CryptoMiner_Detect", Severity.CRITICAL)
    }

    @Test
    fun severity_byRuleName_ransomware() {
        assertSeverity("Ransomware_Locky", Severity.CRITICAL)
    }

    @Test
    fun severity_byRuleName_packer() {
        assertSeverity("Packer_UPX", Severity.HIGH)
    }

    @Test
    fun severity_byRuleName_stealer() {
        assertSeverity("InfoStealer", Severity.HIGH)
    }

    @Test
    fun severity_byRuleName_adware() {
        assertSeverity("Adware_Generic", Severity.MEDIUM)
    }

    @Test
    fun severity_byRuleName_antiAnalysis() {
        assertSeverity("Anti_Analysis_Detect", Severity.HIGH)
    }

    @Test
    fun severity_byRuleName_unknown_fallsToMedium() {
        assertSeverity("Unknown_Malware", Severity.MEDIUM)
    }

    private fun assertSeverity(ruleName: String, expectedSeverity: Severity) {
        val singleRule = yara("""
            rule $ruleName {
                meta:
                    description = "test"
                strings:
                    ${D}a = "trigger"
                condition:
                    ${D}a
            }
        """.trimIndent())
        engine.loadRules(singleRule)
        val result = engine.scan(makeResult(javaSrc = mapOf("A.java" to "trigger")))
        assertTrue("Should find match for $ruleName", result.isNotEmpty())
        assertEquals("Severity mismatch for $ruleName", expectedSeverity, result[0].severity)
    }

    @Test
    fun findingHasCorrectCategory() {
        engine.loadRules(testRules)
        val result = engine.scan(makeResult(javaSrc = mapOf("A.java" to "sendTextMessage")))
        assertTrue(result.isNotEmpty())
        assertEquals(FindingCategory.MALWARE, result[0].category)
    }

    @Test
    fun findingIncludesMatchedStrings() {
        engine.loadRules(testRules)
        val result = engine.scan(makeResult(javaSrc = mapOf("A.java" to "RemoteInput")))
        assertTrue(result.isNotEmpty())
        assertTrue("Details should mention matched string identifier", result[0].details?.contains("\$s1") == true)
    }

    @Test
    fun findingIncludesDefaultDescription_whenMetaMissing() {
        val ruleNoMeta = yara("""
            rule No_Meta {
                strings:
                    ${D}a = "ping"
                condition:
                    ${D}a
            }
        """.trimIndent())
        engine.loadRules(ruleNoMeta)
        val result = engine.scan(makeResult(javaSrc = mapOf("A.java" to "ping")))
        assertTrue(result.isNotEmpty())
        assertEquals("Matched known malware signature", result[0].description)
    }

    // ── Verdict-gate: confidence / ruleSource mapping ──────────────
    // Community rules (confidence = "low") must be tagged so they can NEVER alone
    // (or even together) drive a MALICIOUS verdict. Curated rules stay HIGH.

    @Test
    fun communityRule_mapsToLowConfidenceAndCommunitySource() {
        val communityRule = yara("""
            rule Community_Android {
                meta:
                    description = "community detection"
                    confidence = "low"
                strings:
                    ${D}a = "encrypt"
                condition:
                    ${D}a
            }
        """.trimIndent())
        engine.loadRules(communityRule)
        val result = engine.scan(makeResult(javaSrc = mapOf("A.java" to "encrypt")))
        assertTrue("Community rule should still match", result.isNotEmpty())
        val f = result.first()
        assertEquals("community", f.ruleSource)
        assertEquals(FindingConfidence.LOW, f.confidence)
        assertEquals(FindingCategory.MALWARE, f.category)
    }

    @Test
    fun curatedRule_mapsToHighConfidenceAndCuratedSource() {
        val curatedRule = yara("""
            rule Curated_RAT {
                meta:
                    description = "curated detection"
                    family = "RAT"
                strings:
                    ${D}a = "RemoteInput"
                condition:
                    ${D}a
            }
        """.trimIndent())
        engine.loadRules(curatedRule)
        val result = engine.scan(makeResult(javaSrc = mapOf("A.java" to "RemoteInput")))
        assertTrue("Curated rule should match", result.isNotEmpty())
        val f = result.first()
        assertEquals("curated", f.ruleSource)
        assertEquals(FindingConfidence.HIGH, f.confidence)
    }

    @Test
    fun conditionNotMet_doesNotFire() {
        // Both strings present in rule, but condition requires BOTH — only one matches.
        val rule = yara("""
            rule Both_Required {
                meta:
                    description = "needs both"
                strings:
                    ${D}s1 = "alpha"
                    ${D}s2 = "beta"
                condition:
                    ${D}s1 and ${D}s2
            }
        """.trimIndent())
        engine.loadRules(rule)
        val result = engine.scan(makeResult(javaSrc = mapOf("A.java" to "alpha but not the other token")))
        assertTrue("Rule whose condition is unsatisfied must not fire", result.isEmpty())
    }

    @Test
    fun conditionWithNOf_satisfied_fires() {
        val rule = yara("""
            rule Two_Of_Three {
                meta:
                    description = "2 of 3"
                strings:
                    ${D}a = "x1"
                    ${D}b = "x2"
                    ${D}c = "x3"
                condition:
                    2 of (${D}a, ${D}b, ${D}c)
            }
        """.trimIndent())
        engine.loadRules(rule)
        val result = engine.scan(makeResult(javaSrc = mapOf("A.java" to "x1 x2")))
        assertTrue("2 of 3 should satisfy the condition", result.isNotEmpty())
    }
}
