package com.apkviper.engine.yara

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class YaraEngineConditionTest {

    private fun resultWithSource(text: String): DecompileResult =
        DecompileResult(
            javaSource = emptyMap(),
            smaliSource = emptyMap(),
            manifest = "<manifest/>",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0,
            allSourceText = text,
            permissions = emptyList(),
            exportedServiceCount = 0,
            nativeLibBytes = emptyMap()
        )

    @Test
    fun singleStringMatch_doesNotFire_withoutCondition() {
        // Rule requires BOTH "encrypt" AND ".locked"; presence of "encrypt" alone must NOT fire.
        val rules = """
            rule Test_Ransom {
                meta: description="ransom", family="x", severity="critical"
                strings:
                    ${"$"}a = "encrypt"
                    ${"$"}b = ".locked"
                condition:
                    ${"$"}a and ${"$"}b
            }
        """.trimIndent()
        val engine = YaraEngine()
        engine.loadRules(rules)

        assertEquals(0, engine.scan(resultWithSource("this app can encrypt data safely")).size)
        assertEquals(1, engine.scan(resultWithSource("encrypt then rename to file.locked")).size)
    }

    @Test
    fun anyOf_wildcard_andQuantifier() {
        val rules = """
            rule Test_Combo {
                meta: description="combo", family="x", severity="critical"
                strings:
                    ${"$"}sdk1 = "net.droidjack.server"
                    ${"$"}sdk2 = "droidjack"
                    ${"$"}func1 = "getInstalledPackages"
                    ${"$"}func2 = "getRunningTasks"
                condition:
                    any of (${"$"}sdk*, ${"$"}func1, ${"$"}func2)
            }
        """.trimIndent()
        val engine = YaraEngine()
        engine.loadRules(rules)

        // Only a wildcard match ($sdk*) should satisfy "any of ($sdk*, $func1, $func2)".
        assertEquals(1, engine.scan(resultWithSource("net.droidjack.server found")).size)
        // No match at all -> no fire.
        assertEquals(0, engine.scan(resultWithSource("nothing relevant here")).size)
    }

    @Test
    fun allOf_requiresEveryString() {
        val rules = """
            rule Test_All {
                meta: description="all", family="x", severity="high"
                strings:
                    ${"$"}x = "alpha"
                    ${"$"}y = "beta"
                    ${"$"}z = "gamma"
                condition:
                    all of (${"$"}x, ${"$"}y, ${"$"}z)
            }
        """.trimIndent()
        val engine = YaraEngine()
        engine.loadRules(rules)
        assertEquals(0, engine.scan(resultWithSource("alpha beta only")).size)
        assertEquals(1, engine.scan(resultWithSource("alpha beta gamma present")).size)
    }

    @Test
    fun communityLowConfidence_taggedAndNotStrong() {
        val rules = """
            rule Test_Community {
                meta:
                    description="community rule"
                    family="x"
                    severity="critical"
                    confidence = "low"
                strings:
                    ${"$"}a = "suspiciousstring"
                condition:
                    ${"$"}a
            }
        """.trimIndent()
        val engine = YaraEngine()
        engine.loadRules(rules)
        val findings = engine.scan(resultWithSource("here is a suspiciousstring match"))
        assertEquals(1, findings.size)
        assertEquals(FindingConfidence.LOW, findings.first().confidence)
        assertEquals("community", findings.first().ruleSource)
        assertEquals(FindingCategory.MALWARE, findings.first().category)
    }

    @Test
    fun malformedCondition_doesNotCrash_andDoesNotFire() {
        val rules = """
            rule Test_Bad {
                meta: description="bad", family="x"
                strings:
                    ${"$"}a = "trigger"
                condition:
                    them in (${"$"}a)  // unsupported syntax
            }
        """.trimIndent()
        val engine = YaraEngine()
        engine.loadRules(rules)
        assertEquals(0, engine.scan(resultWithSource("trigger word here")).size)
    }
}
