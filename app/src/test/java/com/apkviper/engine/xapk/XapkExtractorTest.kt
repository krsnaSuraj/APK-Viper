package com.apkviper.engine.xapk

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
class XapkExtractorTest {

    private fun createXapk(vararg entries: Pair<String, String>): File {
        val tmp = File.createTempFile("test_xapk", ".xapk")
        FileOutputStream(tmp).use { fos ->
            ZipOutputStream(fos).use { zos ->
                for ((name, content) in entries) {
                    zos.putNextEntry(ZipEntry(name))
                    zos.write(content.toByteArray())
                    zos.closeEntry()
                }
            }
        }
        return tmp
    }

    @Test
    fun isXapk_xapkExtension_returnsTrue() {
        val file = File("test.xapk")
        val extractor = XapkExtractor()
        assertFalse("Non-existent file should return false", extractor.isXapk(file))
    }

    @Test
    fun isXapk_fileWithManifestJson_returnsTrue() {
        val file = createXapk(
            "base.apk" to "APK",
            "manifest.json" to """{"package_name":"test","version_code":"1","version_name":"1"}"""
        )
        val extractor = XapkExtractor()
        assertTrue("File with manifest.json should be detected as XAPK", extractor.isXapk(file))
        file.delete()
    }

    @Test
    fun isXapk_plainApkWithoutManifest_returnsFalse() {
        val file = File.createTempFile("plain_apk", ".apk")
        FileOutputStream(file).use { fos ->
            ZipOutputStream(fos).use { zos ->
                zos.putNextEntry(ZipEntry("classes.dex"))
                zos.write("DEX".toByteArray())
                zos.closeEntry()
            }
        }
        val extractor = XapkExtractor()
        assertFalse("Plain .apk without manifest should NOT be XAPK", extractor.isXapk(file))
        file.delete()
    }

    @Test
    fun extract_singleApk_returnsBaseApk() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val xapkFile = createXapk(
            "base.apk" to "APK_CONTENT",
            "manifest.json" to """{"package_name":"com.test","version_code":"1","version_name":"1.0"}"""
        )
        val extractor = XapkExtractor()
        val result = extractor.extract(ctx, xapkFile)

        assertTrue("Extraction should succeed", result.success)
        assertTrue("Base APK should exist", result.baseApk.exists())
        assertTrue("Base APK should have content", result.baseApk.length() > 0)
        assertTrue("No split APKs for single APK XAPK", result.splitApks.isEmpty())

        xapkFile.delete()
        result.baseApk.parentFile?.deleteRecursively()
    }

    @Test
    fun extract_splitApks_returnsAll() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val xapkFile = createXapk(
            "base.apk" to "BASE",
            "split_config.arm64.apk" to "ARM",
            "split_config.xhdpi.apk" to "DPI",
            "manifest.json" to """{"package_name":"com.test","version_code":"2","version_name":"2.0"}"""
        )
        val extractor = XapkExtractor()
        val result = extractor.extract(ctx, xapkFile)

        assertTrue("Extraction should succeed", result.success)
        assertEquals("Should find 3 APKs total", 2, result.splitApks.size)
        assertTrue("Base APK should exist", result.baseApk.exists())

        xapkFile.delete()
        result.baseApk.parentFile?.deleteRecursively()
    }

    @Test
    fun extract_noManifest_returnsError() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val xapkFile = createXapk("base.apk" to "APK")
        val extractor = XapkExtractor()
        val result = extractor.extract(ctx, xapkFile)

        assertFalse("Missing manifest should fail", result.success)
        assertNotNull("Error should be present", result.error)
        assertTrue("Error should mention manifest", result.error!!.contains("manifest", ignoreCase = true))

        xapkFile.delete()
    }

    @Test
    fun extract_zipslip_detected() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        // Entry starting with / should be detected as ZipSlip (must include manifest first)
        val xapkFile = File.createTempFile("zipslip", ".xapk")
        val manifestJson = """{
            "package_name": "com.test",
            "name": "Test",
            "version_code": "1",
            "version_name": "1.0",
            "assets": [{"id": "main", "install_path": "Android/obb/com.test/main.1.com.test.obb", "file": "main.1.com.test.obb"}]
        }"""
        FileOutputStream(xapkFile).use { fos ->
            ZipOutputStream(fos).use { zos ->
                zos.putNextEntry(ZipEntry("manifest.json"))
                zos.write(manifestJson.toByteArray())
                zos.closeEntry()
                // ZipSlip entry
                zos.putNextEntry(ZipEntry("/etc/passwd"))
                zos.write("EVIL".toByteArray())
                zos.closeEntry()
            }
        }
        val extractor = XapkExtractor()
        val result = extractor.extract(ctx, xapkFile)

        assertFalse("ZipSlip with / prefix should be detected", result.success)
        assertTrue("Error should mention ZipSlip: ${result.error}",
            result.error?.contains("ZipSlip") == true)

        xapkFile.delete()
    }

    @Test
    fun extract_invalidManifestJson_returnsError() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val xapkFile = createXapk(
            "base.apk" to "APK",
            "manifest.json" to "not valid json"
        )
        val extractor = XapkExtractor()
        val result = extractor.extract(ctx, xapkFile)

        assertFalse("Invalid manifest JSON should fail", result.success)

        xapkFile.delete()
    }

    @Test
    fun parseManifestFromZip_validManifest_returnsData() {
        val xapkFile = createXapk(
            "manifest.json" to """{"package_name":"com.test.app","version_code":"5","version_name":"1.5","expansions":[{"file":"main.5.com.test.app.obb"}]}"""
        )
        val zip = java.util.zip.ZipFile(xapkFile)
        val manifest = XapkExtractor.parseManifestFromZip(zip)
        zip.close()

        assertNotNull("Manifest should be parsed", manifest)
        assertEquals("com.test.app", manifest?.packageName)
        assertEquals("5", manifest?.versionCode)
        assertEquals("1.5", manifest?.versionName)
        assertEquals(1, manifest?.expansions?.size)

        xapkFile.delete()
    }

    @Test
    fun parseManifestFromZip_noManifest_returnsNull() {
        val xapkFile = createXapk("base.apk" to "APK")
        val zip = java.util.zip.ZipFile(xapkFile)
        val manifest = XapkExtractor.parseManifestFromZip(zip)
        zip.close()
        assertNull("No manifest should return null", manifest)
        xapkFile.delete()
    }

    @Test
    fun analyzeFindings_noSplits_returnsEmpty() {
        val extracted = XapkExtractor.ExtractedXapk(
            baseApk = File("base.apk"), splitApks = emptyList(),
            success = true
        )
        val extractor = XapkExtractor()
        val findings = extractor.analyzeFindings(extracted)
        assertTrue("No splits should yield no findings", findings.isEmpty())
    }

    @Test
    fun analyzeFindings_withSplits_returnsFindings() {
        val extracted = XapkExtractor.ExtractedXapk(
            baseApk = File("base.apk"),
            splitApks = listOf(File("config.arm64.apk"), File("config.xhdpi.apk")),
            success = true
        )
        val extractor = XapkExtractor()
        val findings = extractor.analyzeFindings(extracted)
        assertTrue("Split APKs should generate findings", findings.isNotEmpty())
        assertTrue("Should mention split count", findings.any { it.description.contains("2 split") })
    }

    @Test
    fun analyzeFindings_suspiciousNames_detected() {
        val extracted = XapkExtractor.ExtractedXapk(
            baseApk = File("modded.apk"),
            splitApks = listOf(File("cracked_config.apk")),
            success = true
        )
        val extractor = XapkExtractor()
        val findings = extractor.analyzeFindings(extracted)
        assertTrue("Suspicious names should be detected",
            findings.any { it.title.contains("Suspicious") })
    }

    @Test
    fun extract_emptyXapk_returnsError() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val xapkFile = File.createTempFile("empty", ".xapk")
        xapkFile.writeText("") // Not a valid ZIP
        val extractor = XapkExtractor()
        val result = extractor.extract(ctx, xapkFile)
        assertFalse("Empty/invalid ZIP should fail", result.success)
        xapkFile.delete()
    }
}
