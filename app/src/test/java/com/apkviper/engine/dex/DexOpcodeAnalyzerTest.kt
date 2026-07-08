package com.apkviper.engine.dex

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class DexOpcodeAnalyzerTest {
    private val analyzer = DexOpcodeAnalyzer()

    @Test
    fun emptySmaliSource_returnsEmptyFindings() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = emptyMap(),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun nullApkFile_stillWorks() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Test.smali" to "return-void"),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result, apkFile = null)
        assertNotNull(findings)
    }

    @Test
    fun nonEmptySmali_noPatternMatch_noFindings() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Clean.smali" to """
                .class public Lcom/test/Clean;
                .super Ljava/lang/Object;
                .method public foo()V
                    .registers 2
                    return-void
                .end method
            """.trimIndent()),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.isEmpty())
    }

    @Test
    fun facebookRedexgenObfuscation_isSkipped_notFlaggedAsSuspicious() {
        // Facebook Audience Network's "redex" tool emits classes named
        // Lcom_facebook_ads_redexgen_X_* whose new-array/fill-array-data and dead-code patterns
        // are benign SDK artifacts. They must NOT be scored as suspicious (prevents false
        // RAT/MALICIOUS verdicts on any app bundling the Facebook ads SDK).
        val smali = """
            .method public foo()V
                .registers 3
                new-array v0, v1, [B
                fill-array-data v0, :payload
                const-string v2, "x"
                invoke-static {v2}, Lcom/test/Decrypt;->decrypt(Ljava/lang/String;)Ljava/lang/String;
                throw v0
            .end method
        """.trimIndent()
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Lcom_facebook_ads_redexgen_X_0E_.smali" to smali),
            manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(
            "Facebook redex obfuscation must be skipped, got: ${findings.map { it.title }}",
            findings.none { it.title == "Suspicious Opcode Sequence" }
        )
    }

    @Test
    fun constStringThenInvokeStatic_triggersSuspiciousSequence() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Bad.smali" to """
                const-string v0, "encrypted"
                invoke-static {v0}, Lcom/test/Decrypt;->decrypt(Ljava/lang/String;)Ljava/lang/String;
            """.trimIndent()),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Suspicious Opcode Sequence" })
        assertEquals(FindingCategory.CODE, findings.first { it.title == "Suspicious Opcode Sequence" }.category)
        assertEquals(Severity.HIGH, findings.first { it.title == "Suspicious Opcode Sequence" }.severity)
    }

    @Test
    fun gotoThenReturnVoid_triggersSuspiciousSequence() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Dead.smali" to """
                goto/16 :label
                return-void
            """.trimIndent()),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Suspicious Opcode Sequence" })
    }

    @Test
    fun monitorEnterThenMonitorExit_triggersSuspiciousSequence() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("AntiDebug.smali" to """
                monitor-enter v0
                monitor-exit v0
            """.trimIndent()),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Suspicious Opcode Sequence" })
    }

    @Test
    fun throwOpcode_triggersSuspiciousSequence() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Throw.smali" to "throw v0"),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Suspicious Opcode Sequence" })
    }

    @Test
    fun newArrayThenFillArrayData_triggersSuspiciousSequence() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Payload.smali" to """
                new-array v0, v1, [B
                fill-array-data v0, :array_data
            """.trimIndent()),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Suspicious Opcode Sequence" })
    }

    @Test
    fun constStringInvokeDirectNewInstanceInvokeDirect_triggersSuspiciousSequence() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Reflect.smali" to """
                const-string v0, "dex"
                invoke-direct {v0}, Lcom/test/Loader;->load(Ljava/lang/String;)V
                new-instance v1, Lcom/test/Payload
                invoke-direct {v1}, Lcom/test/Payload;-><init>()V
            """.trimIndent()),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Suspicious Opcode Sequence" })
    }

    @Test
    fun heavyReflection_overTwenty_triggersFinding() {
        val reflectionLines = (1..25).joinToString("\n") { "    invoke-static {}, Ldalvik/system/DexClassLoader;->Class.forName()V" }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Reflect.smali" to reflectionLines),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Heavy Reflection Usage" })
        assertEquals(FindingCategory.OBFUSCATION, findings.first { it.title == "Heavy Reflection Usage" }.category)
        assertEquals(Severity.HIGH, findings.first { it.title == "Heavy Reflection Usage" }.severity)
    }

    @Test
    fun heavyReflection_underTwenty_noFinding() {
        val reflectionLines = (1..19).joinToString("\n") { "    invoke-static {}, L/test;->Class.forName()V" }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Reflect.smali" to reflectionLines),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title == "Heavy Reflection Usage" })
    }

    @Test
    fun dynamicDexLoading_detected() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Loader.smali" to """
                const-string v0, "test.dex"
                invoke-static {v0}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;)V
            """.trimIndent()),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Dynamic DEX Loading" })
        assertEquals(FindingCategory.PACKER, findings.first { it.title == "Dynamic DEX Loading" }.category)
        assertEquals(Severity.HIGH, findings.first { it.title == "Dynamic DEX Loading" }.severity)
    }

    @Test
    fun pathClassLoader_detected() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Loader.smali" to "PathClassLoader"),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Dynamic DEX Loading" })
    }

    @Test
    fun inMemoryDexClassLoader_detected() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Loader.smali" to "InMemoryDexClassLoader"),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Dynamic DEX Loading" })
    }

    @Test
    fun antiAnalysis_overThree_triggersFinding() {
        val antiLines = (1..5).joinToString("\n") { "    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z" }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Anti.smali" to antiLines),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Anti-Analysis Detection" })
        assertEquals(FindingCategory.MALWARE, findings.first { it.title == "Anti-Analysis Detection" }.category)
        assertEquals(Severity.HIGH, findings.first { it.title == "Anti-Analysis Detection" }.severity)
        // Verdict-gate: noisy anti-analysis heuristic must NOT be strong evidence,
        // otherwise a single modded-game match could be flipped to MALICIOUS.
        assertEquals(FindingConfidence.LOW, findings.first { it.title == "Anti-Analysis Detection" }.confidence)
    }

    @Test
    fun antiAnalysis_underFour_noFinding() {
        val antiLines = (1..3).joinToString("\n") { "android/os/Debug" }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Anti.smali" to antiLines),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title == "Anti-Analysis Detection" })
    }

    @Test
    fun buildFingerprint_antiAnalysis_detected() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Anti.smali" to (1..5).joinToString("\n") { "Build/FINGERPRINT" }),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Anti-Analysis Detection" })
    }

    @Test
    fun superuser_antiAnalysis_detected() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Anti.smali" to (1..5).joinToString("\n") { "which su" }),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Anti-Analysis Detection" })
    }

    @Test
    fun highGotoDensity_triggersControlFlowFinding() {
        val gotoLines = mutableListOf<String>()
        repeat(55) { gotoLines.add("    goto/16 :label_$it") }
        repeat(45) { gotoLines.add("    nop") } // filler to keep ratio high
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Obfuscated.smali" to gotoLines.joinToString("\n")),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Control Flow Obfuscation" })
        assertEquals(FindingCategory.OBFUSCATION, findings.first { it.title == "Control Flow Obfuscation" }.category)
        assertEquals(Severity.MEDIUM, findings.first { it.title == "Control Flow Obfuscation" }.severity)
    }

    @Test
    fun lowGotoDensity_noFinding() {
        val lines = mutableListOf<String>()
        repeat(10) { lines.add("    goto/16 :label_$it") }
        repeat(90) { lines.add("    nop") }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Normal.smali" to lines.joinToString("\n")),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title == "Control Flow Obfuscation" })
    }

    @Test
    fun highThrowDensity_triggersDeadCodeFinding() {
        val throwLines = mutableListOf<String>()
        repeat(12) { throwLines.add("    throw v$it") }
        repeat(80) { throwLines.add("    nop") }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("DeadCode.smali" to throwLines.joinToString("\n")),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Dead Code Injection" })
        assertEquals(FindingCategory.OBFUSCATION, findings.first { it.title == "Dead Code Injection" }.category)
        assertEquals(Severity.MEDIUM, findings.first { it.title == "Dead Code Injection" }.severity)
    }

    @Test
    fun lowThrowCount_noFinding() {
        val throwLines = mutableListOf<String>()
        repeat(5) { throwLines.add("    throw v$it") }
        repeat(95) { throwLines.add("    nop") }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Normal.smali" to throwLines.joinToString("\n")),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title == "Dead Code Injection" })
    }

    @Test
    fun fillArrayDataOverFive_triggersPayloadFinding() {
        val fillLines = (1..8).joinToString("\n") { "    fill-array-data v$it, :payload_$it" }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Payload.smali" to fillLines),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Encrypted Array Payloads" })
        assertEquals(FindingCategory.PACKER, findings.first { it.title == "Encrypted Array Payloads" }.category)
        assertEquals(Severity.HIGH, findings.first { it.title == "Encrypted Array Payloads" }.severity)
    }

    @Test
    fun fillArrayDataUnderSix_noFinding() {
        val fillLines = (1..5).joinToString("\n") { "    fill-array-data v$it, :arr_$it" }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Normal.smali" to fillLines),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title == "Encrypted Array Payloads" })
    }

    @Test
    fun multipleFiles_aggregationWorks() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf(
                "File1.smali" to (1..15).joinToString("\n") { "Class.forName" },
                "File2.smali" to (1..15).joinToString("\n") { "Class.forName" }
            ),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Heavy Reflection Usage" })
    }

    @Test
    fun multipleFindings_allPresent() {
        val smali = buildString {
            appendLine("const-string v0, \"flag\"")
            appendLine("invoke-static {v0}, Lutil;->check()V")
            appendLine("throw v0")
            appendLine("goto/16 :end")
            appendLine("return-void")
            repeat(10) { appendLine("Class.forName") }
            appendLine("DexClassLoader")
        }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Multi.smali" to smali),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Suspicious Opcode Sequence" })
        assertTrue(findings.any { it.title == "Dynamic DEX Loading" })
    }

    @Test
    fun opcodeSequence_noMatch_whenOrderWrong() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Safe.smali" to """
                invoke-static {v0}, Lutil;->check()V
                const-string v0, "flag"
            """.trimIndent()),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        // const-string then invoke-static is suspicious, but reversed order is not
        assertFalse(findings.any { it.title == "Suspicious Opcode Sequence" })
    }

    @Test
    fun opcodeSequence_partialMatchNotEnough() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Partial.smali" to """
                const-string v0, "x"
                return-void
                invoke-static {v0}, Lutil;->check()V
            """.trimIndent()),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        // const-string and invoke-static are separated by return-void (which IS tracked)
        // so the sequence is [0x1a, 0x0e, 0x71] which doesn't match any suspicious pattern
        assertTrue(findings.isEmpty())
    }

    @Test
    fun veryLargeOpcodeList_doesNotOom() {
        val hugeSequence = (1..5000).joinToString("\n") { "    nop ; # some comment" }
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Huge.smali" to hugeSequence),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertNotNull(findings)
    }

    @Test
    fun methodInvoke_reflection_detected() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Reflect.smali" to (1..25).joinToString("\n") { "Method.invoke" }),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Heavy Reflection Usage" })
    }

    @Test
    fun fieldGet_reflection_detected() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Reflect.smali" to (1..25).joinToString("\n") { "Field.get" }),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Heavy Reflection Usage" })
    }

    @Test
    fun constructorNewInstance_reflection_detected() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Reflect.smali" to (1..25).joinToString("\n") { "Constructor.newInstance" }),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title == "Heavy Reflection Usage" })
    }
}
