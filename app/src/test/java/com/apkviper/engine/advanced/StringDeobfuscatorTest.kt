package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class StringDeobfuscatorTest {
    private val deobfuscator = StringDeobfuscator()

    private fun decompile(javaSource: Map<String, String> = mapOf(), allSource: String = ""): DecompileResult =
        DecompileResult(javaSource, mapOf(), "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun emptyJavaSource_noFindings() {
        assertTrue(deobfuscator.analyze(decompile(), "").isEmpty())
    }

    @Test
    fun cleanCode_noFindings() {
        val code = "class A { void foo() { int x = 1; } }"
        val source = "class A { void foo() { int x = 1; } }"
        assertTrue(deobfuscator.analyze(decompile(mapOf("A.java" to code)), source).isEmpty())
    }

    @Test
    fun reflectionClassForName_detected() {
        val code = """
            Class.forName("hidden.Class");
            method.invoke(obj, args);
        """.trimIndent()
        val source = code
        val findings = deobfuscator.analyze(decompile(mapOf("A.java" to code)), source)
        assertTrue(findings.any { it.title.contains("Reflection API Abuse") })
    }

    @Test
    fun reflectionDexLoader_detected() {
        val code = """
            DexClassLoader loader = new DexClassLoader(path, ...);
            method.invoke(loadedClass, args);
        """.trimIndent()
        val source = code
        val findings = deobfuscator.analyze(decompile(mapOf("A.java" to code)), source)
        assertTrue(findings.any { it.title.contains("Reflection API Abuse") })
    }

    @Test
    fun reflectionLoadClass_detected() {
        val code = """
            ClassLoader cl = ...;
            cl.loadClass("evil.Payload");
            setAccessible(true);
        """.trimIndent()
        val source = code
        val findings = deobfuscator.analyze(decompile(mapOf("A.java" to code)), source)
        assertTrue(findings.any { it.title.contains("Reflection API Abuse") })
    }

    @Test
    fun singleReflectionFlag_notEnough() {
        val code = "Class.forName(\"test.Class\");"
        val source = code
        assertTrue(deobfuscator.analyze(decompile(mapOf("A.java" to code)), source).isEmpty())
    }

    @Test
    fun rot13Strings_detected() {
        val source = """
            new String(new byte[]{\x61, \x62, \x63});
            new String(new byte[]{\x64, \x65, \x66});
            new String(new byte[]{\x67, \x68, \x69});
            new String(new byte[]{\x6a, \x6b, \x6c});
            new String(new byte[]{\x6d, \x6e, \x6f});
        """.trimIndent()
        val findings = deobfuscator.analyze(decompile(mapOf("A.java" to "")), source)
        assertTrue(findings.any { it.title.contains("ROT13") })
    }

    @Test
    fun base64Strings_detected() {
        val b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk="
        val source = (1..10).joinToString("\n") { "\"$b64\"" }
        val findings = deobfuscator.analyze(decompile(mapOf("A.java" to "")), source)
        assertTrue(findings.any { it.title.contains("Base64") })
    }

    @Test
    fun fewBase64Strings_notEnough() {
        val source = """
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk="
        """.trimIndent()
        assertTrue(deobfuscator.analyze(decompile(mapOf("A.java" to "")), source).isEmpty())
    }

    @Test
    fun fiveOrMoreReflections_highSeverity() {
        val code = """
            Class.forName("A"); method.invoke(a);
            Class.forName("B"); method.invoke(b);
            Class.forName("C"); method.invoke(c);
            Class.forName("D"); method.invoke(d);
            Class.forName("E"); method.invoke(e);
        """.trimIndent()
        val source = code
        val javaSource = mapOf(
            "A.java" to "Class.forName(\"A\"); method.invoke(a);",
            "B.java" to "Class.forName(\"B\"); method.invoke(b);",
            "C.java" to "Class.forName(\"C\"); method.invoke(c);",
            "D.java" to "Class.forName(\"D\"); method.invoke(d);",
            "E.java" to "Class.forName(\"E\"); method.invoke(e);"
        )
        val findings = deobfuscator.analyze(decompile(javaSource = javaSource), source)
        val refFinding = findings.find { it.title.contains("Reflection API Abuse") }
        assertNotNull(refFinding)
        assertEquals(Severity.HIGH, refFinding!!.severity)
    }

    @Test
    fun twoToFourReflections_mediumSeverity() {
        val code = """
            Class.forName("A"); method.invoke(a);
            Class.forName("B"); method.invoke(b);
        """.trimIndent()
        val javaSource = mapOf(
            "A.java" to "Class.forName(\"A\"); method.invoke(a);",
            "B.java" to "Class.forName(\"B\"); method.invoke(b);"
        )
        val findings = deobfuscator.analyze(decompile(javaSource = javaSource), code)
        val refFinding = findings.find { it.title.contains("Reflection API Abuse") }
        assertNotNull(refFinding)
        assertEquals(Severity.MEDIUM, refFinding!!.severity)
    }

    @Test
    fun allThreeDetectionsTogether() {
        val code = "Class.forName(\"X\"); method.invoke(obj);"
        val source = """
            ${code}
            new String(new byte[]{\x41, \x42, \x43});
            new String(new byte[]{\x44, \x45, \x46});
            new String(new byte[]{\x47, \x48, \x49});
            new String(new byte[]{\x4A, \x4B, \x4C});
            new String(new byte[]{\x4D, \x4E, \x4F});
        """.trimIndent()
        val findings = deobfuscator.analyze(decompile(javaSource = mapOf("A.java" to code)), source)
        val rot13 = findings.find { it.title.contains("ROT13") }
        assertNotNull(rot13)
        assertEquals(Severity.MEDIUM, rot13!!.severity)
    }
}
