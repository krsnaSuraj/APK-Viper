package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class ObfuscationDetectorTest {
    private val detector = ObfuscationDetector()

    @Test
    fun cleanJava_noObfuscationFindings() {
        val code = """
            public class Main {
                private String userName;
                private int userAge;
                public void processData() {
                    String displayName = "hello";
                    int totalCount = 0;
                }
            }
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Main.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).isEmpty())
    }

    @Test
    fun singleLetterVars_exactly500_noFinding() {
        val vars = (1..500).joinToString("\n") { "a = $it;" }
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to vars),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title == "Heavy Obfuscation" })
    }

    @Test
    fun singleLetterVars_501_triggersFinding() {
        val vars = (1..501).joinToString("\n") { "a = $it;" }
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to vars),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Heavy Obfuscation" })
        assertEquals(Severity.INFO, findings.first { it.title == "Heavy Obfuscation" }.severity)
    }

    @Test
    fun stringBuilderWithoutCharAt_noFinding() {
        val code = """
            StringBuilder sb = new StringBuilder();
            sb.append("hello");
            sb.append("world");
            String result = sb.toString();
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title == "String Construction Pattern" })
    }

    @Test
    fun stringBuilderWithCharAt_triggersStringFinding() {
        val code = """
            StringBuilder sb = new StringBuilder();
            char c = sb.charAt(0);
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "String Construction Pattern" })
        assertEquals(Severity.MEDIUM, findings.first { it.title == "String Construction Pattern" }.severity)
    }

    @Test
    fun controlFlow_switchCount20_noFinding() {
        val switches = (1..20).joinToString("\n") { "switch(i) { case $it: break; }" }
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to switches),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title == "Control Flow Obfuscation" })
    }

    @Test
    fun controlFlow_switchCount21_triggersFinding() {
        val switches = (1..21).joinToString("\n") { "switch(i) { case $it: break; }" }
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to switches),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Control Flow Obfuscation" })
        assertEquals(Severity.LOW, findings.first { it.title == "Control Flow Obfuscation" }.severity)
    }

    @Test
    fun base64_longStrings_notEncoded_noFinding() {
        val strings = (1..15).joinToString("\n") { "String s$it = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\";" }
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to strings),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.none { it.title == "Base64 Encoded Strings" })
    }

    @Test
    fun base64Count_11_triggersFinding() {
        val strings = (1..11).joinToString("\n") { "String b64$it = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";" }
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to strings),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Base64 Encoded Strings" })
        assertEquals(Severity.MEDIUM, findings.first { it.title == "Base64 Encoded Strings" }.severity)
    }

    @Test
    fun unicodeEscapedStrings_triggersFinding() {
        val code = """
            ${(1..21).joinToString("\n") { "String s$it = \"\\u00${it.toString().padStart(2, '0')}A\";" }}
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Obfuscated Strings" })
    }

    @Test
    fun smaliHexStrings_combinedWithUnicode_triggers() {
        val java = (1..10).joinToString("\n") { "String s$it = \"\\u00${it.toString().padStart(2, '0')}A\";" }
        val smali = (1..11).joinToString("\n") { "const-string v0, \"0x0$it\"" }
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to java),
            smaliSource = mapOf("Test.smali" to smali),
            manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Obfuscated Strings" })
    }

    @Test
    fun mixedObfuscationTechniques_multipleFindings() {
        val vars = (1..501).joinToString("\n") { "a = $it;" }
        val obfuscatedCode = "$vars\nStringBuilder sb; char c = sb.charAt(0);"
        val switches = (1..21).joinToString("\n") { "switch(i) { case $it: break; }" }
        val code = "$obfuscatedCode\n$switches"
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Heavy Obfuscation" })
        assertTrue(findings.any { it.title == "String Construction Pattern" })
        assertTrue(findings.any { it.title == "Control Flow Obfuscation" })
    }

    @Test
    fun emptyJavaSource_noFindings() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).isEmpty())
    }

    @Test
    fun largeCode_noFalsePositives() {
        val lines = (1..1000).joinToString("\n") { "int variable$it = $it;" }
        val code = """
            public class Large {
                $lines
                public void run() {
                    int result = 0;
                    String name = "test";
                }
            }
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Large.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).isEmpty())
    }
}
