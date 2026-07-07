package com.apkviper.engine.advanced

import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class NativeCallGraphCorrelatorTest {
    private val correlator = NativeCallGraphCorrelator()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun emptyLibs_noFindings() {
        val apk = createApk()
        assertTrue(correlator.analyze(apk, emptyList()).isEmpty())
    }

    @Test
    fun libNotInZip_skipped() {
        val apk = createApk()
        assertTrue(correlator.analyze(apk, listOf("lib/x86/libnonexistent.so")).isEmpty())
    }

    @Test
    fun reverseShellChain_detected() {
        val libContent = "socket\nconnect\ndup2\nexecve"
        val apk = createApkWithLib("libnative.so", libContent)
        val findings = correlator.analyze(apk, listOf("lib/armeabi-v7a/libnative.so"))
        assertTrue(findings.any { it.title.contains("Reverse Shell") })
        assertEquals(Severity.CRITICAL, findings.first { it.title.contains("Reverse Shell") }.severity)
    }

    @Test
    fun bindShellChain_detected() {
        val libContent = "socket\nbind\nlisten\naccept\nexecve"
        val apk = createApkWithLib("libbind.so", libContent)
        val findings = correlator.analyze(apk, listOf("lib/armeabi-v7a/libbind.so"))
        assertTrue(findings.any { it.title.contains("Bind Shell") })
    }

    @Test
    fun ptraceInjectionChain_detected() {
        val libContent = "ptrace\nPTRACE_ATTACH\nPTRACE_GETREGS\nPTRACE_SETREGS\nPTRACE_POKEDATA"
        val apk = createApkWithLib("libptrace.so", libContent)
        val findings = correlator.analyze(apk, listOf("lib/armeabi-v7a/libptrace.so"))
        assertTrue(findings.any { it.title.contains("Ptrace-based") })
    }

    @Test
    fun filelessDropperChain_detected() {
        val libContent = "fork\npipe\nexecve\nconnect"
        val apk = createApkWithLib("libdrop.so", libContent)
        val findings = correlator.analyze(apk, listOf("lib/armeabi-v7a/libdrop.so"))
        assertTrue(findings.any { it.title.contains("Fileless Dropper") })
    }

    @Test
    fun dnsTunnelingChain_detected() {
        val libContent = "gethostbyname\nsocket\nconnect\nsend"
        val apk = createApkWithLib("libdns.so", libContent)
        val findings = correlator.analyze(apk, listOf("lib/armeabi-v7a/libdns.so"))
        assertTrue(findings.any { it.title.contains("DNS Tunneling") })
    }

    @Test
    fun partialChain_noFindings() {
        val libContent = "socket\nconnect\ndup2"
        val apk = createApkWithLib("libpartial.so", libContent)
        val findings = correlator.analyze(apk, listOf("lib/armeabi-v7a/libpartial.so"))
        assertFalse(findings.any { it.title.contains("Reverse Shell") })
    }

    @Test
    fun frameworkLib_skipped() {
        val libContent = "socket\nconnect\ndup2\nexecve"
        val apk = createApkWithLib("libflutter.so", libContent)
        val findings = correlator.analyze(apk, listOf("lib/armeabi-v7a/libflutter.so"))
        assertFalse(findings.any { it.title.contains("Reverse Shell") })
    }

    @Test
    fun crossLibraryCorrelation_detected() {
        val apk = tempFolder.newFile("cross.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/armeabi-v7a/libnet.so"))
            zip.write("socket\nconnect\nsend".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/armeabi-v7a/libexec.so"))
            zip.write("execve\nfork\nsystem".toByteArray())
            zip.closeEntry()
        }
        val findings = correlator.analyze(apk, listOf(
            "lib/armeabi-v7a/libnet.so", "lib/armeabi-v7a/libexec.so"
        ))
        assertTrue(findings.any { it.title.contains("Cross-Library") })
    }

    @Test
    fun emptyLib_noFindings() {
        val apk = createApkWithLib("libempty.so", "")
        val findings = correlator.analyze(apk, listOf("lib/armeabi-v7a/libempty.so"))
        assertTrue(findings.isEmpty())
    }

    private fun createApk(): File {
        val file = tempFolder.newFile("test.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
        }
        return file
    }

    private fun createApkWithLib(name: String, content: String): File {
        val file = tempFolder.newFile("chain_$name.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/armeabi-v7a/$name"))
            zip.write(content.toByteArray())
            zip.closeEntry()
        }
        return file
    }
}
