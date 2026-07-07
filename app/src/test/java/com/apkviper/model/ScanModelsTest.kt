package com.apkviper.model

import org.junit.Assert.*
import org.junit.Test

class ScanModelsTest {

    // --- ScanResult tests ---

    @Test
    fun scanResult_defaultTimestamp_isSet() {
        val before = System.currentTimeMillis()
        val result = ScanResult(
            apkName = "test.apk",
            apkPath = "/path/test.apk",
            fileSize = 1024L,
            scanMode = "quick",
            threatLevel = ThreatLevel.SAFE,
            threatScore = 0,
            findings = emptyList(),
            decompileTime = 100L,
            scanTime = 200L
        )
        val after = System.currentTimeMillis()
        assertTrue("Timestamp should be >= before creation", result.timestamp >= before)
        assertTrue("Timestamp should be <= after creation", result.timestamp <= after)
    }

    @Test
    fun scanResult_allFieldsExplicitlySet_storedCorrectly() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware", "desc")
        )
        val result = ScanResult(
            id = 42L,
            apkName = "evil.apk",
            apkPath = "/data/evil.apk",
            sha256 = "abc123def456",
            fileSize = 2048L,
            scanMode = "deep",
            threatLevel = ThreatLevel.MALICIOUS,
            threatScore = 95,
            findings = findings,
            decompileTime = 500L,
            scanTime = 1000L,
            timestamp = 123456789L,
            classification = "Trojan",
            remediations = listOf("Uninstall immediately"),
            appLabel = "Evil App",
            packageName = "com.evil.app",
            versionName = "1.0",
            versionCode = 1L,
            minSdk = 21,
            targetSdk = 34
        )
        assertEquals(42L, result.id)
        assertEquals("evil.apk", result.apkName)
        assertEquals("/data/evil.apk", result.apkPath)
        assertEquals("abc123def456", result.sha256)
        assertEquals(2048L, result.fileSize)
        assertEquals("deep", result.scanMode)
        assertEquals(ThreatLevel.MALICIOUS, result.threatLevel)
        assertEquals(95, result.threatScore)
        assertSame(findings, result.findings)
        assertEquals(500L, result.decompileTime)
        assertEquals(1000L, result.scanTime)
        assertEquals(123456789L, result.timestamp)
        assertEquals("Trojan", result.classification)
        assertEquals(listOf("Uninstall immediately"), result.remediations)
        assertEquals("Evil App", result.appLabel)
        assertEquals("com.evil.app", result.packageName)
        assertEquals("1.0", result.versionName)
        assertEquals(1L, result.versionCode)
        assertEquals(21, result.minSdk)
        assertEquals(34, result.targetSdk)
    }

    @Test
    fun scanResult_defaultValues_areCorrect() {
        val result = ScanResult(
            apkName = "a.apk",
            apkPath = "/a.apk",
            fileSize = 0L,
            scanMode = "quick",
            threatLevel = ThreatLevel.SAFE,
            threatScore = 0,
            findings = emptyList(),
            decompileTime = 0L,
            scanTime = 0L
        )
        assertEquals(0L, result.id)
        assertNull(result.sha256)
        assertNull(result.classification)
        assertTrue(result.remediations.isEmpty())
        assertNull(result.appLabel)
        assertNull(result.packageName)
        assertNull(result.versionName)
        assertNull(result.versionCode)
        assertNull(result.minSdk)
        assertNull(result.targetSdk)
    }

    @Test
    fun scanResult_emptyFindings_doesNotCrash() {
        val result = ScanResult(
            apkName = "a.apk",
            apkPath = "/a.apk",
            fileSize = 0L,
            scanMode = "quick",
            threatLevel = ThreatLevel.SAFE,
            threatScore = 0,
            findings = emptyList(),
            decompileTime = 0L,
            scanTime = 0L
        )
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun scanResult_withAllOptionalNulls_doesNotCrash() {
        val result = ScanResult(
            apkName = "n.apk",
            apkPath = "/n.apk",
            fileSize = 1L,
            scanMode = "brutal",
            threatLevel = ThreatLevel.LOW,
            threatScore = 10,
            findings = emptyList(),
            decompileTime = 0L,
            scanTime = 0L,
            sha256 = null,
            classification = null,
            remediations = emptyList(),
            appLabel = null,
            packageName = null,
            versionName = null,
            versionCode = null,
            minSdk = null,
            targetSdk = null
        )
        assertNull(result.sha256)
        assertNull(result.classification)
        assertNull(result.appLabel)
        assertNull(result.packageName)
        assertNull(result.versionName)
        assertNull(result.versionCode)
        assertNull(result.minSdk)
        assertNull(result.targetSdk)
    }

    @Test
    fun scanResult_negativeValues_areAllowed() {
        val result = ScanResult(
            apkName = "n.apk",
            apkPath = "/n.apk",
            fileSize = -1L,
            scanMode = "quick",
            threatLevel = ThreatLevel.SAFE,
            threatScore = -5,
            findings = emptyList(),
            decompileTime = -100L,
            scanTime = -200L
        )
        assertEquals(-1L, result.fileSize)
        assertEquals(-5, result.threatScore)
        assertEquals(-100L, result.decompileTime)
        assertEquals(-200L, result.scanTime)
    }

    // --- Finding tests ---

    @Test
    fun finding_allFieldsSet_areStoredCorrectly() {
        val finding = Finding(
            category = FindingCategory.PACKER,
            severity = Severity.HIGH,
            title = "UPX Packer Detected",
            description = "APK is packed with UPX",
            details = "UPX 3.96 detected in classes.dex",
            file = "classes.dex",
            line = 0
        )
        assertEquals(FindingCategory.PACKER, finding.category)
        assertEquals(Severity.HIGH, finding.severity)
        assertEquals("UPX Packer Detected", finding.title)
        assertEquals("APK is packed with UPX", finding.description)
        assertEquals("UPX 3.96 detected in classes.dex", finding.details)
        assertEquals("classes.dex", finding.file)
        assertEquals(0, finding.line)
    }

    @Test
    fun finding_minimalFields_areStoredCorrectly() {
        val finding = Finding(
            category = FindingCategory.MANIFEST,
            severity = Severity.INFO,
            title = "Debuggable flag set",
            description = "App is debuggable"
        )
        assertEquals(FindingCategory.MANIFEST, finding.category)
        assertEquals(Severity.INFO, finding.severity)
        assertEquals("Debuggable flag set", finding.title)
        assertEquals("App is debuggable", finding.description)
        assertNull(finding.details)
        assertNull(finding.file)
        assertNull(finding.line)
    }

    @Test
    fun finding_nullDetails_doesNotCrash() {
        val finding = Finding(
            category = FindingCategory.CERTIFICATE,
            severity = Severity.LOW,
            title = "Self-signed cert",
            description = "Certificate is self-signed",
            details = null,
            file = null,
            line = null
        )
        assertNull(finding.details)
        assertNull(finding.file)
        assertNull(finding.line)
    }

    @Test
    fun finding_veryLongStrings_areStored() {
        val title = "T".repeat(5000)
        val desc = "D".repeat(50000)
        val details = "X".repeat(100000)
        val finding = Finding(
            category = FindingCategory.CLOUD,
            severity = Severity.CRITICAL,
            title = title,
            description = desc,
            details = details,
            file = "/long/path/" + "f".repeat(1000),
            line = Int.MAX_VALUE
        )
        assertEquals(title, finding.title)
        assertEquals(desc, finding.description)
        assertEquals(details, finding.details)
        assertEquals(Int.MAX_VALUE, finding.line)
    }

    @Test
    fun finding_negativeLineNumber_isAllowed() {
        val finding = Finding(
            category = FindingCategory.CODE,
            severity = Severity.MEDIUM,
            title = "Negative line",
            description = "Line number is -1",
            line = -1
        )
        assertEquals(-1, finding.line)
    }

    @Test
    fun finding_emptyStrings_areAllowed() {
        val finding = Finding(
            category = FindingCategory.STRING,
            severity = Severity.INFO,
            title = "",
            description = "",
            details = "",
            file = ""
        )
        assertEquals("", finding.title)
        assertEquals("", finding.description)
        assertEquals("", finding.details)
        assertEquals("", finding.file)
    }

    @Test
    fun finding_unusualCharacters_areStored() {
        val finding = Finding(
            category = FindingCategory.BEHAVIORAL,
            severity = Severity.HIGH,
            title = "Special: \u0000\u0001\u0002 escape chars",
            description = "Line breaks\n\r\t and unicode \u4e2d\u6587\u65e5\u672c\u8a9e",
            details = "Emoji: \ud83d\ude00\ud83d\udd25\ud83d\udca9"
        )
        assertEquals("Special: \u0000\u0001\u0002 escape chars", finding.title)
        assertEquals("Line breaks\n\r\t and unicode \u4e2d\u6587\u65e5\u672c\u8a9e", finding.description)
        assertEquals("Emoji: \ud83d\ude00\ud83d\udd25\ud83d\udca9", finding.details)
    }

    // --- ThreatLevel ordering tests ---

    @Test
    fun threatLevel_safeIsLowest() {
        val ordered = listOf(ThreatLevel.SAFE, ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.MALICIOUS)
        for (i in 0 until ordered.size - 1) {
            assertTrue("${ordered[i]} should be < ${ordered[i + 1]}", ordered[i].ordinal < ordered[i + 1].ordinal)
        }
    }

    @Test
    fun threatLevel_ordinalValues_areInExpectedOrder() {
        assertEquals(0, ThreatLevel.SAFE.ordinal)
        assertEquals(1, ThreatLevel.LOW.ordinal)
        assertEquals(2, ThreatLevel.MEDIUM.ordinal)
        assertEquals(3, ThreatLevel.HIGH.ordinal)
        assertEquals(4, ThreatLevel.CRITICAL.ordinal)
        assertEquals(5, ThreatLevel.MALICIOUS.ordinal)
    }

    @Test
    fun threatLevel_name_matchesEnumName() {
        assertEquals("SAFE", ThreatLevel.SAFE.name)
        assertEquals("LOW", ThreatLevel.LOW.name)
        assertEquals("MEDIUM", ThreatLevel.MEDIUM.name)
        assertEquals("HIGH", ThreatLevel.HIGH.name)
        assertEquals("CRITICAL", ThreatLevel.CRITICAL.name)
        assertEquals("MALICIOUS", ThreatLevel.MALICIOUS.name)
    }

    @Test
    fun threatLevel_valueOf_allValues() {
        assertEquals(ThreatLevel.SAFE, ThreatLevel.valueOf("SAFE"))
        assertEquals(ThreatLevel.LOW, ThreatLevel.valueOf("LOW"))
        assertEquals(ThreatLevel.MEDIUM, ThreatLevel.valueOf("MEDIUM"))
        assertEquals(ThreatLevel.HIGH, ThreatLevel.valueOf("HIGH"))
        assertEquals(ThreatLevel.CRITICAL, ThreatLevel.valueOf("CRITICAL"))
        assertEquals(ThreatLevel.MALICIOUS, ThreatLevel.valueOf("MALICIOUS"))
    }

    @Test
    fun threatLevel_values_containsAll() {
        val values = ThreatLevel.values()
        assertEquals(6, values.size)
        assertTrue(values.contains(ThreatLevel.SAFE))
        assertTrue(values.contains(ThreatLevel.MALICIOUS))
    }

    // --- Severity enum tests ---

    @Test
    fun severity_ordinalValues_areInExpectedOrder() {
        assertEquals(0, Severity.INFO.ordinal)
        assertEquals(1, Severity.LOW.ordinal)
        assertEquals(2, Severity.MEDIUM.ordinal)
        assertEquals(3, Severity.HIGH.ordinal)
        assertEquals(4, Severity.CRITICAL.ordinal)
    }

    @Test
    fun severity_valueOf_allValues() {
        assertEquals(Severity.INFO, Severity.valueOf("INFO"))
        assertEquals(Severity.LOW, Severity.valueOf("LOW"))
        assertEquals(Severity.MEDIUM, Severity.valueOf("MEDIUM"))
        assertEquals(Severity.HIGH, Severity.valueOf("HIGH"))
        assertEquals(Severity.CRITICAL, Severity.valueOf("CRITICAL"))
    }

    @Test
    fun severity_values_containsAll() {
        val values = Severity.values()
        assertEquals(5, values.size)
    }

    @Test
    fun severity_name_matchesEnumName() {
        assertEquals("INFO", Severity.INFO.name)
        assertEquals("CRITICAL", Severity.CRITICAL.name)
    }

    // --- FindingCategory enum tests ---

    @Test
    fun findingCategory_values_containsAllExpected() {
        val values = FindingCategory.values().toSet()
        assertTrue(values.contains(FindingCategory.MANIFEST))
        assertTrue(values.contains(FindingCategory.PERMISSION))
        assertTrue(values.contains(FindingCategory.CODE))
        assertTrue(values.contains(FindingCategory.STRING))
        assertTrue(values.contains(FindingCategory.CERTIFICATE))
        assertTrue(values.contains(FindingCategory.PACKER))
        assertTrue(values.contains(FindingCategory.OBFUSCATION))
        assertTrue(values.contains(FindingCategory.NATIVE))
        assertTrue(values.contains(FindingCategory.NETWORK))
        assertTrue(values.contains(FindingCategory.CLOUD))
        assertTrue(values.contains(FindingCategory.MALWARE))
        assertTrue(values.contains(FindingCategory.CRYPTO_MINER))
        assertTrue(values.contains(FindingCategory.CODEGEN))
        assertTrue(values.contains(FindingCategory.BEHAVIORAL))
        assertEquals(14, values.size)
    }

    @Test
    fun findingCategory_valueOf_allValues() {
        assertEquals(FindingCategory.MANIFEST, FindingCategory.valueOf("MANIFEST"))
        assertEquals(FindingCategory.PERMISSION, FindingCategory.valueOf("PERMISSION"))
        assertEquals(FindingCategory.CODE, FindingCategory.valueOf("CODE"))
        assertEquals(FindingCategory.STRING, FindingCategory.valueOf("STRING"))
        assertEquals(FindingCategory.CERTIFICATE, FindingCategory.valueOf("CERTIFICATE"))
        assertEquals(FindingCategory.PACKER, FindingCategory.valueOf("PACKER"))
        assertEquals(FindingCategory.OBFUSCATION, FindingCategory.valueOf("OBFUSCATION"))
        assertEquals(FindingCategory.NATIVE, FindingCategory.valueOf("NATIVE"))
        assertEquals(FindingCategory.NETWORK, FindingCategory.valueOf("NETWORK"))
        assertEquals(FindingCategory.CLOUD, FindingCategory.valueOf("CLOUD"))
        assertEquals(FindingCategory.MALWARE, FindingCategory.valueOf("MALWARE"))
        assertEquals(FindingCategory.CRYPTO_MINER, FindingCategory.valueOf("CRYPTO_MINER"))
        assertEquals(FindingCategory.CODEGEN, FindingCategory.valueOf("CODEGEN"))
        assertEquals(FindingCategory.BEHAVIORAL, FindingCategory.valueOf("BEHAVIORAL"))
    }

    @Test
    fun findingCategory_ordinal_areUnique() {
        val ordinals = FindingCategory.values().map { it.ordinal }.toSet()
        assertEquals(FindingCategory.values().size, ordinals.size)
    }

    // --- DecompileResult tests ---

    @Test
    fun decompileResult_allFields_storedCorrectly() {
        val javaSource = mapOf("MainActivity.java" to "class MainActivity {}")
        val smaliSource = mapOf("classes.smali" to ".class public Main")
        val resources = mapOf("res/layout/main.xml" to byteArrayOf(0x01, 0x02, 0x03))
        val dexFiles = listOf("classes.dex", "classes2.dex")
        val nativeLibs = listOf("lib/armeabi-v7a/libnative.so")

        val result = DecompileResult(
            javaSource = javaSource,
            smaliSource = smaliSource,
            manifest = "AndroidManifest.xml content",
            resources = resources,
            dexFiles = dexFiles,
            nativeLibs = nativeLibs,
            decompileTimeMs = 1500L
        )

        assertEquals(javaSource, result.javaSource)
        assertEquals(smaliSource, result.smaliSource)
        assertEquals("AndroidManifest.xml content", result.manifest)
        assertEquals(resources, result.resources)
        assertEquals(dexFiles, result.dexFiles)
        assertEquals(nativeLibs, result.nativeLibs)
        assertEquals(1500L, result.decompileTimeMs)
    }

    @Test
    fun decompileResult_emptyMaps_doesNotCrash() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = emptyMap(),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0L
        )
        assertTrue(result.javaSource.isEmpty())
        assertTrue(result.smaliSource.isEmpty())
        assertTrue(result.resources.isEmpty())
        assertTrue(result.dexFiles.isEmpty())
        assertTrue(result.nativeLibs.isEmpty())
        assertEquals("", result.manifest)
        assertEquals(0L, result.decompileTimeMs)
    }

    @Test
    fun decompileResult_negativeTime_isAllowed() {
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = emptyMap(),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = -1L
        )
        assertEquals(-1L, result.decompileTimeMs)
    }

    @Test
    fun decompileResult_largeByteArrayInResources_isStored() {
        val largeBytes = ByteArray(65536) { it.toByte() }
        val resources = mapOf("large.bin" to largeBytes)
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = emptyMap(),
            manifest = "",
            resources = resources,
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0L
        )
        assertArrayEquals(largeBytes, result.resources["large.bin"])
    }

    @Test
    fun decompileResult_multipleJavaFiles_stored() {
        val javaSource = mapOf(
            "A.java" to "class A {}",
            "B.java" to "class B {}",
            "C.java" to "class C {}"
        )
        val result = DecompileResult(
            javaSource = javaSource,
            smaliSource = emptyMap(),
            manifest = "",
            resources = emptyMap(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0L
        )
        assertEquals(3, result.javaSource.size)
        assertEquals("class A {}", result.javaSource["A.java"])
        assertEquals("class B {}", result.javaSource["B.java"])
        assertEquals("class C {}", result.javaSource["C.java"])
    }

    // --- Data class equality tests ---

    @Test
    fun scanResult_equalObjects_areEqual() {
        val r1 = ScanResult(
            apkName = "a.apk",
            apkPath = "/a.apk",
            fileSize = 100L,
            scanMode = "quick",
            threatLevel = ThreatLevel.LOW,
            threatScore = 10,
            findings = emptyList(),
            decompileTime = 50L,
            scanTime = 100L
        )
        val r2 = r1.copy()
        assertEquals(r1, r2)
        assertEquals(r1.hashCode(), r2.hashCode())
    }

    @Test
    fun finding_equalObjects_areEqual() {
        val f1 = Finding(FindingCategory.CODE, Severity.HIGH, "Title", "Desc", "Det", "f", 1)
        val f2 = Finding(FindingCategory.CODE, Severity.HIGH, "Title", "Desc", "Det", "f", 1)
        assertEquals(f1, f2)
        assertEquals(f1.hashCode(), f2.hashCode())
    }

    @Test
    fun finding_differentFields_areNotEqual() {
        val f1 = Finding(FindingCategory.CODE, Severity.HIGH, "Title", "Desc")
        val f2 = Finding(FindingCategory.CODE, Severity.CRITICAL, "Title", "Desc")
        assertNotEquals(f1, f2)
    }

    @Test
    fun decompileResult_equalObjects_areEqual() {
        val d1 = DecompileResult(
            javaSource = mapOf("A.java" to "a"),
            smaliSource = mapOf("B.smali" to "b"),
            manifest = "m",
            resources = mapOf("r" to byteArrayOf(1)),
            dexFiles = listOf("d"),
            nativeLibs = listOf("n"),
            decompileTimeMs = 100L
        )
        val d2 = d1.copy()
        assertEquals(d1, d2)
        assertEquals(d1.hashCode(), d2.hashCode())
    }

    @Test
    fun finding_toString_containsFields() {
        val f = Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Trojan", "Desc")
        val str = f.toString()
        assertTrue(str.contains("MALWARE"))
        assertTrue(str.contains("CRITICAL"))
        assertTrue(str.contains("Trojan"))
    }

    @Test
    fun scanResult_toString_containsFields() {
        val r = ScanResult(
            apkName = "test.apk",
            apkPath = "/test.apk",
            fileSize = 1L,
            scanMode = "quick",
            threatLevel = ThreatLevel.SAFE,
            threatScore = 0,
            findings = emptyList(),
            decompileTime = 0L,
            scanTime = 0L
        )
        val str = r.toString()
        assertTrue(str.contains("test.apk"))
        assertTrue(str.contains("SAFE"))
    }
}
