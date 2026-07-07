package com.apkviper.engine.advanced

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkIntegritySplitApkTest {
    private val verifier = ApkIntegrityVerifier()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun splitApk_withoutDex_isValid() {
        val file = createSplitApk(includeDex = false)
        val result = verifier.verify(file, isSplitApk = true)
        assertTrue("Split APK without DEX should be valid: ${result.error}", result.isValid)
        assertTrue(result.hasManifest)
        assertFalse(result.hasDexFiles)
    }

    @Test
    fun splitApk_withoutSignature_isValid() {
        val file = createSplitApk(includeDex = true, includeSignature = false)
        val result = verifier.verify(file, isSplitApk = true)
        assertTrue("Split APK without signature should be valid: ${result.error}", result.isValid)
        assertFalse(result.hasSignature)
    }

    @Test
    fun splitApk_corrupt_returnsFallback() {
        val file = tempFolder.newFile("corrupt.apk")
        file.writeText("not a zip at all")
        val result = verifier.verify(file, isSplitApk = true)
        assertTrue("Corrupt split APK should return pseudo-valid: ${result.error}", result.isValid)
        assertFalse(result.isZip)
    }

    @Test
    fun normalApk_withoutDex_isInvalid() {
        val file = createSplitApk(includeDex = false)
        val result = verifier.verify(file, isSplitApk = false)
        assertFalse("Normal APK without DEX should be invalid", result.isValid)
    }

    @Test
    fun splitApk_validWithDexAndSig_isValid() {
        val file = createSplitApk(includeDex = true)
        val result = verifier.verify(file, isSplitApk = true)
        assertTrue("Full split APK should be valid: ${result.error}", result.isValid)
        assertTrue(result.hasDexFiles)
    }

    private fun createSplitApk(includeDex: Boolean, includeSignature: Boolean = true): File {
        val file = tempFolder.newFile("split_config_arm.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            val manifest = if (includeDex)
                """<manifest package="com.test" split="config_arm"/>"""
            else
                """<manifest package="com.test" split="config_arm" hasCode="false"/>"""
            zip.write(manifest.toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("res/drawable/icon.png"))
            zip.write(ByteArray(512))
            zip.closeEntry()
            if (includeDex) {
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(ByteArray(4096))
                zip.closeEntry()
            }
            if (includeSignature) {
                zip.putNextEntry(ZipEntry("META-INF/BNDLTOOL.RSA"))
                zip.write(ByteArray(100))
                zip.closeEntry()
            }
        }
        return file
    }
}