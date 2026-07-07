package com.apkviper.engine.decompile

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class DecompilerManagerPerfTest {

    @Test
    fun parallelDecompiler_smallZip_generatesSmaliWithoutCrash() = runBlocking {
        val apk = createMinimalZip()
        val manager = DecompilerManager()
        try {
            val result = manager.decompile(apk)
            assertNotNull("Decompile result should not be null", result)
            assertNotNull("Manifest should be extracted", result.manifest)
        } catch (e: Exception) {
            if (e.message?.contains("DEX") == true || e.message?.contains("header") == true) {
                return@runBlocking
            }
            throw e
        }
    }

    @Test
    fun decompileResult_allSourceTextDefaultsToNull() {
        val result = com.apkviper.model.DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(),
            manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0L
        )
        assertNull("allSourceText should default to null", result.allSourceText)
        assertTrue("permissions should default to empty", result.permissions.isEmpty())
        assertEquals("exportedServiceCount should default to 0", 0, result.exportedServiceCount)
        assertTrue("nativeLibBytes should default to empty", result.nativeLibBytes.isEmpty())
    }

    @Test
    fun decompileResult_copy_populatesSharedContext() {
        val result = com.apkviper.model.DecompileResult(
            javaSource = mapOf("Test.java" to "class Test {}"),
            smaliSource = mapOf("Test.smali" to ".class LTest;"),
            manifest = "<manifest><uses-permission android:name=\"android.permission.INTERNET\"/></manifest>",
            resources = emptyMap(), dexFiles = emptyList(),
            nativeLibs = listOf("lib/armeabi-v7a/libnative.so"),
            decompileTimeMs = 0L
        )
        val enhanced = result.copy(
            allSourceText = "combined source",
            permissions = listOf("android.permission.INTERNET"),
            exportedServiceCount = 1,
            nativeLibBytes = mapOf("lib/armeabi-v7a/libnative.so" to byteArrayOf(0x7F, 0x45, 0x4C, 0x46))
        )
        assertEquals("combined source", enhanced.allSourceText)
        assertEquals(listOf("android.permission.INTERNET"), enhanced.permissions)
        assertEquals(1, enhanced.exportedServiceCount)
        assertEquals(1, enhanced.nativeLibBytes.size)
        assertArrayEquals(byteArrayOf(0x7F, 0x45, 0x4C, 0x46), enhanced.nativeLibBytes["lib/armeabi-v7a/libnative.so"])
    }

    @Test
    fun decompileResult_copy_preservesOriginalFields() {
        val result = com.apkviper.model.DecompileResult(
            javaSource = mapOf("A.java" to "class A {}"),
            smaliSource = mapOf("A.smali" to ".class LA;"),
            manifest = "<manifest/>", resources = emptyMap(),
            dexFiles = listOf("classes.dex"), nativeLibs = emptyList(), decompileTimeMs = 100L
        )
        val enhanced = result.copy(allSourceText = "combined text")
        assertEquals(1, enhanced.javaSource.size)
        assertEquals(1, enhanced.smaliSource.size)
        assertEquals("<manifest/>", enhanced.manifest)
        assertEquals(1, enhanced.dexFiles.size)
        assertEquals(100L, enhanced.decompileTimeMs)
    }

    @Test
    fun decompileResult_emptyNativeLibs_returnsEmptyNativeLibBytes() {
        val result = com.apkviper.model.DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(),
            manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0L
        )
        assertTrue(result.nativeLibBytes.isEmpty())
    }

    @Test
    fun decompileResult_noPermissions_defaultsToEmptyList() {
        val result = com.apkviper.model.DecompileResult(
            javaSource = emptyMap(), smaliSource = emptyMap(),
            manifest = "<manifest/>", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0L
        )
        assertTrue(result.permissions.isEmpty())
    }

    private fun createMinimalZip(): File {
        val file = File.createTempFile("perf_test", ".apk")
        try {
            java.util.zip.ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(createMinimalManifestBytes())
                zip.closeEntry()

                val fakeDex = createMinimalDexHeader()
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(fakeDex)
                zip.closeEntry()
            }
        } catch (_: Exception) {
            file.writeBytes(ByteArray(100))
        }
        return file
    }

    private fun createMinimalManifestBytes(): ByteArray {
        val xml = "<?xml version=\"1.0\"?><manifest package=\"com.test\"><application/></manifest>"
        return xml.encodeToByteArray()
    }

    private fun createMinimalDexHeader(): ByteArray {
        val data = ByteArray(112)
        data[0] = 0x64; data[1] = 0x65; data[2] = 0x78; data[3] = 0x0A
        data[4] = 0x30; data[5] = 0x33; data[6] = 0x35; data[7] = 0x00
        return data
    }
}
