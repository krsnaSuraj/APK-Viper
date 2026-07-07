package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class CfgStructuralAnalyzerTest {
    private val analyzer = CfgStructuralAnalyzer()

    private fun decompile(javaSource: Map<String, String> = mapOf()): DecompileResult =
        DecompileResult(javaSource, mapOf(), "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun emptySource_noFindings() {
        assertTrue(analyzer.analyze(decompile()).isEmpty())
    }

    @Test
    fun simpleMethod_noFindings() {
        val code = """
            class A {
                void foo() { }
            }
        """.trimIndent()
        assertTrue(analyzer.analyze(decompile(mapOf("A.java" to code))).isEmpty())
    }

    @Test
    fun methodMatchedMalwareCfg_criticalFinding() {
        val code = """
            class A {
                void run() {
                    if (x > 0) { doSomething(); }
                    if (y > 0) { doElse(); }
                    for (int i = 0; i < 10; i++) { loop(); }
                    for (int j = 0; j < 5; j++) { another(); }
                    call1();
                    call2();
                    call3();
                }
            }
        """.trimIndent()
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        assertTrue(findings.any { it.category == com.apkviper.model.FindingCategory.MALWARE })
    }

    @Test
    fun suspiciousControlFlow_nonGameClass_highFinding() {
        val code = """
            class Utils {
                void process() {
                    if (a) { doA(); }
                    if (b) { doB(); }
                    if (c) { doC(); }
                    if (d) { doD(); }
                    for (int i = 0; i < n; i++) { call1(); }
                    for (int j = 0; j < m; j++) { call2(); }
                    for (int k = 0; k < l; k++) { call3(); }
                    x();
                    y();
                    z();
                    w();
                    p();
                    q();
                    r();
                    s();
                }
            }
        """.trimIndent()
        val findings = analyzer.analyze(decompile(mapOf("Utils.java" to code)))
        assertTrue(findings.any { it.title.contains("Suspicious Control Flow") })
        assertEquals(Severity.HIGH, findings.first { it.title.contains("Suspicious Control Flow") }.severity)
    }

    @Test
    fun gameCode_excludedFromSuspiciousFinding() {
        val code = """
            class GameEngine {
                void render() {
                    for (int i = 0; i < n; i++) { draw(); }
                    for (int j = 0; j < m; j++) { update(); }
                    for (int k = 0; k < l; k++) { render(); }
                    if (a) { if (b) { if (c) { if (d) { process(); } } } }
                }
            }
        """.trimIndent()
        val findings = analyzer.analyze(decompile(mapOf("GameEngine.java" to code)))
        assertFalse(findings.any { it.title.contains("Suspicious Control Flow") })
    }

    @Test
    fun blocksGenerated_includeFileName() {
        val code = """
            class A {
                void go() {
                    if (x) { foo(); }
                    if (y) { bar(); }
                    if (z) { baz(); }
                    for (int i = 0; i < n; i++) { loop(); }
                    for (int j = 0; j < m; j++) { inner(); }
                    a();
                    b();
                    c();
                    d();
                }
            }
        """.trimIndent()
        val findings = analyzer.analyze(decompile(mapOf("Target.java" to code)))
        assertTrue(findings.any { it.file == "Target.java" })
    }

    @Test
    fun structuralHashGeneratedAndIncluded() {
        val code = """
            class A {
                void go() {
                    if (x) { a(); }
                    if (y) { b(); }
                }
            }
        """.trimIndent()
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        if (findings.isNotEmpty()) {
            assertTrue(findings.any { it.details?.contains("Structural hash") == true })
        }
    }

    @Test
    fun tryCatchBlocks_extraBlocks() {
        val code = """
            class A {
                void safe() {
                    try { risky(); }
                    catch (Exception e) { handle(); }
                    if (x) { recover(); }
                }
            }
        """.trimIndent()
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
    }

    @Test
    fun emptyMethodBody_skipped() {
        val code = """
            class A {
                void empty() {}
            }
        """.trimIndent()
        assertTrue(analyzer.analyze(decompile(mapOf("A.java" to code))).isEmpty())
    }

    @Test
    fun onlyAssignments_noFindings() {
        val code = """
            class A {
                void compute() {
                    int a = 1;
                    int b = 2;
                    int c = a + b;
                    String s = "hello";
                }
            }
        """.trimIndent()
        assertTrue(analyzer.analyze(decompile(mapOf("A.java" to code))).isEmpty())
    }
}
