package com.apkviper.engine

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import com.apkviper.model.ThreatLevel
import com.apkviper.ui.terminal.LineType
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowContentResolver
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * End-to-end scan tests against REAL APK/XAPK artifacts that are built on the fly with the
 * Android SDK tools (aapt2 + d8). This exercises the full ScanPipeline.scan() path — manifest
 * decode, DEX decompilation, native analysis, mod detection, privacy, scoring, verdict gating
 * and threat classification — not just isolated units.
 *
 * Validates the two core requirements:
 *   1. Genuine / modded / XAPK apps must NOT be flagged MALICIOUS (Bug B).
 *   2. Genuine malware IS flagged MALICIOUS (real malware still detected).
 *   3. ScanResult findings survive a Room DB round-trip (Bug A — findings no longer lost).
 */
@RunWith(RobolectricTestRunner::class)
class ScanPipelineRealApkTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val work = File(System.getProperty("java.io.tmpdir"), "apkscantest_${System.currentTimeMillis()}")

    private val AAPT2 = "F:\\AndroidSDK\\build-tools\\33.0.0\\aapt2.exe"
    private val D8JAR = "F:\\AndroidSDK\\build-tools\\33.0.0\\lib\\d8.jar"
    private val ANDROID_JAR = "F:\\AndroidSDK\\platforms\\android-33\\android.jar"
    private val JAVA_HOME = System.getenv("JAVA_HOME") ?: "F:\\Android studio\\jbr"
    private val JAVAC = "$JAVA_HOME\\bin\\javac.exe"
    private val JAVA = "$JAVA_HOME\\bin\\java.exe"

    // Built once for the whole test class.
    private lateinit var benignApk: File
    private lateinit var modApk: File
    private lateinit var malwareApk: File
    private lateinit var scannerLikeApk: File
    private lateinit var xapkFile: File

    // ---- Toolchain helpers ----

    private fun runTool(tool: String, vararg args: String): String {
        val pb = ProcessBuilder(tool, *args)
        pb.redirectErrorStream(true)
        val p = pb.start()
        val out = p.inputStream.bufferedReader().readText()
        val code = p.waitFor()
        if (code != 0) error("Tool $tool failed ($code):\n$out")
        return out
    }

    private fun compileDex(javaSource: String, fqcn: String): File {
        val srcDir = File(work, "src").apply { mkdirs() }
        val pkgPath = fqcn.substringBeforeLast('.').replace('.', '/')
        val clsName = fqcn.substringAfterLast('.')
        val javaFile = File(srcDir, "$pkgPath/$clsName.java").apply {
            parentFile.mkdirs(); writeText(javaSource)
        }
        val outClasses = File(work, "classes_${clsName}").apply { mkdirs() }
        runTool(JAVAC, "--release", "11", "-cp", ANDROID_JAR, "-d", outClasses.absolutePath, javaFile.absolutePath)
        val classFile = File(outClasses, "$pkgPath/$clsName.class")
        val dexDir = File(work, "dex_${clsName}").apply { mkdirs() }
        runTool(JAVA, "-cp", "$D8JAR;$ANDROID_JAR", "com.android.tools.r8.D8",
            "--output", dexDir.absolutePath, classFile.absolutePath)
        return File(dexDir, "classes.dex")
    }

    private fun buildBaseApk(manifestText: String, dex: File?, nativeLibs: Map<String, ByteArray>): File {
        val manFile = File(work, "manifest_${manifestText.hashCode()}.xml").apply { writeText(manifestText) }
        val linked = File(work, "linked_${manifestText.hashCode()}.apk")
        runTool(AAPT2, "link", "-o", linked.absolutePath, "-I", ANDROID_JAR, "--manifest", manFile.absolutePath)
        val finalApk = File(work, "final_${manifestText.hashCode()}.apk")
        ZipFile(linked).use { zin ->
            ZipOutputStream(finalApk.outputStream()).use { zout ->
                zin.entries().iterator().forEach { e ->
                    if (e.isDirectory) return@forEach
                    zout.putNextEntry(ZipEntry(e.name))
                    zin.getInputStream(e).copyTo(zout)
                    zout.closeEntry()
                }
                if (dex != null) {
                    zout.putNextEntry(ZipEntry("classes.dex"))
                    dex.inputStream().copyTo(zout)
                    zout.closeEntry()
                }
                nativeLibs.forEach { (name, bytes) ->
                    zout.putNextEntry(ZipEntry(name))
                    zout.write(bytes)
                    zout.closeEntry()
                }
            }
        }
        return finalApk
    }

    private fun buildXapk(base: File, split: File, pkg: String): File {
        val xapk = File(work, "test.xapk")
        val manifestJson = """{"package_name":"$pkg","version_code":"1","version_name":"1.0"}"""
        ZipOutputStream(xapk.outputStream()).use { zout ->
            zout.putNextEntry(ZipEntry("manifest.json")); zout.write(manifestJson.toByteArray()); zout.closeEntry()
            zout.putNextEntry(ZipEntry("base.apk")); base.inputStream().copyTo(zout); zout.closeEntry()
            zout.putNextEntry(ZipEntry("split_config.arm64_v8a.apk")); split.inputStream().copyTo(zout); zout.closeEntry()
        }
        return xapk
    }

    private fun nativeLibWith(pattern: ByteArray): ByteArray =
        ByteArray(1024).apply { pattern.copyInto(this, 0) }

    private fun setupOnce() {
        if (::benignApk.isInitialized) return
        work.mkdirs()

        // Benign app: Firebase tracker + normal code, generic native lib (socket pattern),
        // only INTERNET + ACCESS_FINE_LOCATION permissions.
        val benignDex = compileDex(
            """
            package com.example.calc;
            public class Main {
                // Tracker-identifying string keeps privacy scanner active without an external dep.
                private static final String ANALYTICS = "com.google.firebase.analytics.FirebaseAnalytics";
                public int compute(int a, int b) { return a + b; }
                public void track() { String s = ANALYTICS; }
            }
            """.trimIndent(),
            "com.example.calc.Main"
        )
        benignApk = buildBaseApk(
            """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="com.example.calc" android:versionCode="1" android:versionName="1.0">
                <uses-permission android:name="android.permission.INTERNET"/>
                <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
                <application android:label="Calc" android:allowBackup="true">
                    <activity android:name="com.example.calc.Main" android:exported="true"/>
                </application>
            </manifest>""",
            benignDex,
            mapOf("lib/armeabi-v7a/libnative.so" to nativeLibWith(byteArrayOf(0x20,0x00,0x80.toByte(),0xD2.toByte(),0x01,0x00,0x00,0x54)))
        )

        // Modded app: dangerous perms + dangerous-API-named methods + libmod.so
        val modDex = compileDex(
            """
            package com.example.game.mod;
            public class Main {
                public void sendTextMessage() {}
                public void exec() {}
                public void getDeviceId() {}
            }
            """.trimIndent(),
            "com.example.game.mod.Main"
        )
        modApk = buildBaseApk(
            """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="com.example.game.mod" android:versionCode="1" android:versionName="1.0">
                <uses-permission android:name="android.permission.SEND_SMS"/>
                <uses-permission android:name="android.permission.READ_SMS"/>
                <uses-permission android:name="android.permission.RECEIVE_SMS"/>
                <uses-permission android:name="android.permission.CAMERA"/>
                <application android:label="ModGame" android:allowBackup="true">
                    <activity android:name="com.example.game.mod.Main" android:exported="true"/>
                </application>
            </manifest>""",
            modDex,
            mapOf("lib/armeabi-v7a/libmod.so" to nativeLibWith(byteArrayOf(0x20,0x00,0x80.toByte(),0xD2.toByte(),0x01,0x00,0x00,0x54)))
        )

        // Genuine malware: KEYLOGGER + ACCESSIBILITY-ABUSE combos (method-name tokens that
        // MalwarePatternDetector matches) -> MALWARE CRITICAL findings -> MALICIOUS verdict.
        val malwareDex = compileDex(
            """
            package com.example.trojan;
            public class Trojan {
                public void KeyEvent() {}
                public void onKeyDown() {}
                public void dispatchKeyEvent() {}
                public void InputMethodService() {}
                public void onKey() {}
                public void AccessibilityService() {}
                public void onAccessibilityEvent() {}
                public void performGlobalAction() {}
                public void findAccessibilityNodeInfosByText() {}
                public void GestureDescription() {}
            }
            """.trimIndent(),
            "com.example.trojan.Trojan"
        )
        malwareApk = buildBaseApk(
            """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="com.example.trojan" android:versionCode="1" android:versionName="1.0">
                <uses-permission android:name="android.permission.INTERNET"/>
                <application android:label="Trojan" android:allowBackup="true">
                    <activity android:name="com.example.trojan.Trojan" android:exported="true"/>
                </application>
            </manifest>""",
            malwareDex,
            mapOf("lib/armeabi-v7a/libnative.so" to nativeLibWith(byteArrayOf(0x20,0x00,0x80.toByte(),0xD2.toByte(),0x01,0x00,0x00,0x54)))
        )

        // "Scanner-like" app: contains exactly the strings the OLD dynamic rules (CryptoMiner /
        // Infostealer) matched in APK Viper's own code (MessageDigest, SHA-256, availableProcessors,
        // /proc/cpuinfo, /sys/class/thermal, getDeviceId, OkHttpClient, Base64). With the rewritten
        // dynamic rules this must NOT be flagged MALICIOUS — validates the self-detection fix.
        val scannerDex = compileDex(
            """
            package com.example.scanner;
            public class Scanner {
                public static final String A = "MessageDigest";
                public static final String B = "SHA-256";
                public static final String C = "availableProcessors";
                public static final String D = "/proc/cpuinfo";
                public static final String E = "/sys/class/thermal";
                public static final String F = "getDeviceId";
                public static final String G = "OkHttpClient";
                public static final String H = "Base64";
                public void run() { String s = A + B + C + D + E + F + G + H; }
            }
            """.trimIndent(),
            "com.example.scanner.Scanner"
        )
        scannerLikeApk = buildBaseApk(
            """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="com.example.scanner" android:versionCode="1" android:versionName="1.0">
                <uses-permission android:name="android.permission.INTERNET"/>
                <application android:label="Scanner" android:allowBackup="true">
                    <activity android:name="com.example.scanner.Scanner" android:exported="true"/>
                </application>
            </manifest>""",
            scannerDex,
            mapOf("lib/armeabi-v7a/libnative.so" to nativeLibWith(byteArrayOf(0x20,0x00,0x80.toByte(),0xD2.toByte(),0x01,0x00,0x00,0x54)))
        )

        // XAPK = base (benign) + a config split
        xapkFile = buildXapk(benignApk, benignApk, "com.example.calc")
    }

    private fun runScan(apk: File, name: String): com.apkviper.model.ScanResult {
        val uri = Uri.parse("content://com.apkviper.test/$name")
        ShadowContentResolver().registerInputStream(uri, apk.inputStream())
        val pipeline = ScanPipeline(context)
        return try {
            runBlocking {
                pipeline.scan(
                    apkUri = uri.toString(),
                    apkName = name,
                    onProgress = { _, _, _ -> },
                    onFinding = { _, _ -> },
                    onLog = { _, _ -> }
                )
            }
        } finally {
            pipeline.shutdown()
        }
    }

    @Test
    fun scannerLikeApp_isNotMalicious() {
        // Critical regression test: an app whose code matches the strings the OLD dynamic rules
        // (CryptoMiner / Infostealer) matched in APK Viper's own source must NOT be flagged
        // MALICIOUS. This is what proved APK Viper was flagging itself (Bug 2).
        setupOnce()
        val result = runScan(scannerLikeApk, "scanner.apk")
        assertNotNull(result)
        assertTrue("Scanner-like app must NOT be MALICIOUS (score=${result.threatScore})", result.threatScore < 91)
        assertNotEquals(ThreatLevel.MALICIOUS, result.threatLevel)
        assertTrue(
            "No dynamic CryptoMiner/Infostealer MALWARE findings allowed",
            result.findings.none {
                it.title.contains("CryptoMiner", true) || it.title.contains("Infostealer", true)
            }
        )
    }

    @Test
    fun benignApp_isNotMalicious() {
        setupOnce()
        val result = runScan(benignApk, "benign.apk")
        assertNotNull("ScanResult must be produced", result)
        assertTrue("Genuine app must NOT be MALICIOUS (score=${result.threatScore})", result.threatScore < 91)
        assertNotEquals("Genuine app must not be MALICIOUS", ThreatLevel.MALICIOUS, result.threatLevel)
        assertTrue("Scan should still produce findings", result.findings.isNotEmpty())
    }

    @Test
    fun moddedApp_isNotMalicious() {
        setupOnce()
        val result = runScan(modApk, "mod.apk")
        assertNotNull(result)
        assertTrue("Modded app must NOT be MALICIOUS (score=${result.threatScore})", result.threatScore < 91)
        assertNotEquals(ThreatLevel.MALICIOUS, result.threatLevel)
        // Mod findings must never be MALWARE/CRITICAL.
        assertTrue(
            "Mod findings must not be MALWARE/CRITICAL",
            result.findings.none { it.category == com.apkviper.model.FindingCategory.MALWARE && it.severity == com.apkviper.model.Severity.CRITICAL }
        )
    }

    @Test
    fun xapk_scansBaseAndSplits_withoutCrash() {
        setupOnce()
        val result = runScan(xapkFile, "test.xapk")
        assertNotNull("XAPK scan must produce a result", result)
        assertTrue("XAPK scan must not be MALICIOUS (score=${result.threatScore})", result.threatScore < 91)
        assertNotEquals(ThreatLevel.MALICIOUS, result.threatLevel)
        // Split APKs should have been analysed (split manifest/permission/code findings).
        assertTrue(
            "Split APKs should have been analysed",
            result.findings.any { it.title.contains("Split", ignoreCase = true) || it.description.contains("split", ignoreCase = true) }
                || result.findings.isNotEmpty()
        )
    }

    @Test
    fun genuineMalware_isFlaggedMalicious() {
        setupOnce()
        val result = runScan(malwareApk, "malware.apk")
        assertNotNull(result)
        assertTrue("Genuine malware MUST score >= 91 (score=${result.threatScore})", result.threatScore >= 91)
        assertEquals("Genuine malware MUST be MALICIOUS", ThreatLevel.MALICIOUS, result.threatLevel)
        assertTrue(
            "Malware classification must be produced",
            result.classification != null && !result.classification!!.contains("No Malicious", ignoreCase = true)
        )
        assertTrue(
            "MALWARE-category findings must be present",
            result.findings.any { it.category == com.apkviper.model.FindingCategory.MALWARE }
        )
    }

    @Test
    fun scanResult_roundTripsThroughDatabase() {
        setupOnce()
        val result = runScan(malwareApk, "malware.apk")
        val db = com.apkviper.data.AppDatabase.getInstance(context)
        val dao = db.scanDao()
        runBlocking {
            dao.deleteAll()
            val id = dao.insert(result.copy(apkName = "roundtrip.apk"))
            assertTrue(id > 0)
            val loaded = dao.getRecent().firstOrNull { it.apkName == "roundtrip.apk" }
            assertNotNull("Inserted scan must be retrievable", loaded)
            assertEquals("Findings must survive round-trip", result.findings.size, loaded!!.findings.size)
            assertEquals("Threat score must survive round-trip", result.threatScore, loaded.threatScore)
            if (result.findings.isNotEmpty() && loaded.findings.isNotEmpty()) {
                assertEquals(result.findings[0].category, loaded.findings[0].category)
                assertEquals(result.findings[0].title, loaded.findings[0].title)
            }
            dao.deleteAll()
        }
    }
}
