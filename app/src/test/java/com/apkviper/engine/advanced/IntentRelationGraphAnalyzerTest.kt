package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class IntentRelationGraphAnalyzerTest {
    private val analyzer = IntentRelationGraphAnalyzer()

    private fun decompile(javaSource: Map<String, String> = mapOf(),
                          manifest: String = ""): DecompileResult =
        DecompileResult(javaSource, mapOf(), manifest, mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun emptyManifest_noFindings() {
        assertTrue(analyzer.analyze(decompile(manifest = "")).isEmpty())
    }

    @Test
    fun noComponents_noFindings() {
        val manifest = """<manifest package="com.test" />"""
        assertTrue(analyzer.analyze(decompile(manifest = manifest)).isEmpty())
    }

    @Test
    fun crossComponentIntentChain_detected() {
        val manifest = """
            <manifest package="com.test">
                <activity android:name=".MainActivity"/>
                <service android:name=".DataService"/>
            </manifest>
        """.trimIndent()
        val code = """
            Intent intent = new Intent(this, DataService.class);
            getDeviceId();
        """.trimIndent()
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("MainActivity.java" to code),
            manifest = manifest
        ))
        assertTrue(findings.any { it.title.contains("Cross-Component Intent Chain") })
    }

    @Test
    fun smsComponentWithCrossComponentChain_detected() {
        val manifest = """
            <manifest package="com.test">
                <activity android:name=".Collector"/>
                <service android:name=".Sender"/>
            </manifest>
        """.trimIndent()
        val code = """
            Intent i = new Intent(this, Sender.class);
            getDeviceId();
            HttpURLConnection conn;
            i.putExtra("data", "sensitive");
        """.trimIndent()
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("Collector.java" to code),
            manifest = manifest
        ))
        assertTrue(findings.any { it.title.contains("Cross-Component Intent Chain") })
    }

    @Test
    fun manyComponents_heavyFragmentation() {
        val comps = (1..6).map { """<activity android:name=".Act$it"/>""" }
        val services = (1..3).map { """<service android:name=".Svc$it"/>""" }
        val manifest = """
            <manifest package="com.test">
                ${comps.joinToString("\n")}
                ${services.joinToString("\n")}
            </manifest>
        """.trimIndent()
        val findings = analyzer.analyze(decompile(manifest = manifest))
        assertTrue(findings.any { it.title.contains("Heavy Component Fragmentation") })
        assertEquals(Severity.MEDIUM, findings.first { it.title.contains("Heavy Component Fragmentation") }.severity)
    }

    @Test
    fun componentWithIntentAndTrackedApis_detected() {
        val manifest = """
            <manifest package="com.test">
                <activity android:name=".CollectorActivity"/>
                <service android:name=".UploadService"/>
            </manifest>
        """.trimIndent()
        val code = """
            Intent i = new Intent(this, UploadService.class);
            String deviceId = getDeviceId();
            String location = getLastKnownLocation();
        """.trimIndent()
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("CollectorActivity.java" to code),
            manifest = manifest
        ))
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun noIntentTargets_noFinding() {
        val manifest = """
            <manifest package="com.test">
                <activity android:name=".MainActivity"/>
            </manifest>
        """.trimIndent()
        val code = "getDeviceId();"
        assertTrue(analyzer.analyze(decompile(
            javaSource = mapOf("MainActivity.java" to code),
            manifest = manifest
        )).isEmpty())
    }

    @Test
    fun intentTargetNotInComponents_ignored() {
        val manifest = """
            <manifest package="com.test">
                <activity android:name=".MainActivity"/>
            </manifest>
        """.trimIndent()
        val code = """
            Intent i = new Intent(this, SomeExternalClass.class);
        """.trimIndent()
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("MainActivity.java" to code),
            manifest = manifest
        ))
        assertFalse(findings.any { it.title.contains("Cross-Component Intent Chain") })
    }

    @Test
    fun intentRegex_matchesNewIntentPattern() {
        val manifest = """
            <manifest package="com.test">
                <activity android:name=".Launcher"/>
                <service android:name=".TargetService"/>
            </manifest>
        """.trimIndent()
        val code = """
            new Intent(this, TargetService.class);
            getDeviceId();
        """.trimIndent()
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("Launcher.java" to code),
            manifest = manifest
        ))
        assertTrue(
            "Regex should match 'new Intent(this, TargetService.class)' pattern",
            findings.any { it.title.contains("Cross-Component Intent Chain") }
        )
    }

    @Test
    fun smsSpyDetected_whenPermissionsPresent() {
        val base = decompile(manifest = """<manifest package="com.test"/>""")
        val result = base.copy(
            permissions = listOf(
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.READ_SMS"
            )
        )
        val findings = analyzer.analyze(result)
        val smsSpy = findings.find { it.title.contains("Auto-start SMS Spy") }
        assertNotNull(
            "SMS spy finding not found. findings=${findings.map { it.title }}, perms=${result.permissions}",
            smsSpy
        )
    }

    @Test
    fun fewComponents_noHeavyFragmentation() {
        val manifest = """
            <manifest package="com.test">
                <activity android:name=".MainActivity"/>
                <activity android:name=".SettingsActivity"/>
                <service android:name=".SimpleService"/>
            </manifest>
        """.trimIndent()
        val findings = analyzer.analyze(decompile(manifest = manifest))
        assertFalse(
            "Legitimate apps with <5 components should NOT trigger Heavy Fragmentation",
            findings.any { it.title.contains("Heavy Component Fragmentation") }
        )
    }

    @Test
    fun smsSpy_withSmsPermOnly_noBoot_doesNotTrigger() {
        val result = DecompileResult(
            javaSource = mapOf(),
            smaliSource = mapOf(),
            manifest = """<manifest package="com.test"/>""",
            resources = mapOf(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0,
            permissions = listOf("android.permission.READ_SMS")
        )
        val findings = analyzer.analyze(result)
        assertFalse(
            "SMS spy should require BOTH SMS and boot permissions",
            findings.any { it.title.contains("Auto-start SMS Spy") }
        )
    }

    @Test
    fun smsSpy_withBootPermOnly_noSms_doesNotTrigger() {
        val result = DecompileResult(
            javaSource = mapOf(),
            smaliSource = mapOf(),
            manifest = """<manifest package="com.test"/>""",
            resources = mapOf(),
            dexFiles = emptyList(),
            nativeLibs = emptyList(),
            decompileTimeMs = 0,
            permissions = listOf("android.permission.RECEIVE_BOOT_COMPLETED")
        )
        val findings = analyzer.analyze(result)
        assertFalse(
            "SMS spy should require BOTH SMS and boot permissions",
            findings.any { it.title.contains("Auto-start SMS Spy") }
        )
    }
}
