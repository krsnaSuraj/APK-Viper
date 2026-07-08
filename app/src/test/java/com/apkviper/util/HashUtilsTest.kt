package com.apkviper.util

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class HashUtilsTest {

    @Test
    fun sha256_knownInput_expectedOutput() {
        val input = "Hello, World!".toByteArray(Charsets.UTF_8)
        val hash = HashUtils.sha256(input)
        assertEquals("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", hash)
    }

    @Test
    fun sha256_emptyString_knownHash() {
        val hash = HashUtils.sha256(byteArrayOf())
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
    }

    @Test
    fun sha256_fileExists_returnsHash() {
        val file = File.createTempFile("hash_test", ".tmp")
        file.writeText("test content")
        val hash = HashUtils.sha256(file)
        assertNotNull(hash)
        assertEquals(64, hash.length)
        file.delete()
    }

    @Test
    fun sha256_sameContent_sameHash() {
        val f1 = File.createTempFile("hash_a", ".tmp").apply { writeText("same data") }
        val f2 = File.createTempFile("hash_b", ".tmp").apply { writeText("same data") }
        assertEquals(HashUtils.sha256(f1), HashUtils.sha256(f2))
        f1.delete(); f2.delete()
    }

    @Test
    fun sha256_differentContent_differentHash() {
        val f1 = File.createTempFile("hash_c", ".tmp").apply { writeText("data one") }
        val f2 = File.createTempFile("hash_d", ".tmp").apply { writeText("data two") }
        assertNotEquals(HashUtils.sha256(f1), HashUtils.sha256(f2))
        f1.delete(); f2.delete()
    }

    @Test
    fun sha256_byteArray_empty_returnsHash() {
        val hash = HashUtils.sha256(ByteArray(0))
        assertEquals(64, hash.length)
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
    }

    @Test
    fun sha256_byteArray_small_returnsHash() {
        val hash = HashUtils.sha256(byteArrayOf(0x41))
        assertEquals(64, hash.length)
        assertTrue(hash.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun md5_knownInput_expectedOutput() {
        val file = File.createTempFile("md5_known", ".tmp")
        file.writeText("Hello, World!")
        val hash = HashUtils.md5(file)
        assertEquals("65a8e27d8879283831b664bd8b7f0ad4", hash)
        file.delete()
    }

    @Test
    fun md5_emptyString_knownHash() {
        val file = File.createTempFile("md5_empty", ".tmp")
        file.writeText("")
        val hash = HashUtils.md5(file)
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", hash)
        file.delete()
    }

    @Test
    fun md5_fileExists_returnsHash() {
        val file = File.createTempFile("md5_test", ".tmp")
        file.writeText("test content")
        val hash = HashUtils.md5(file)
        assertNotNull(hash)
        assertEquals(32, hash.length)
        file.delete()
    }

    @Test
    fun md5_sameContent_sameHash() {
        val f1 = File.createTempFile("md5_a", ".tmp").apply { writeText("same data") }
        val f2 = File.createTempFile("md5_b", ".tmp").apply { writeText("same data") }
        assertEquals(HashUtils.md5(f1), HashUtils.md5(f2))
        f1.delete(); f2.delete()
    }

    @Test
    fun md5_differentContent_differentHash() {
        val f1 = File.createTempFile("md5_c", ".tmp").apply { writeText("data one") }
        val f2 = File.createTempFile("md5_d", ".tmp").apply { writeText("data two") }
        assertNotEquals(HashUtils.md5(f1), HashUtils.md5(f2))
        f1.delete(); f2.delete()
    }

    @Test
    fun sha256_fileNotFound_throws() {
        try {
            HashUtils.sha256(File("nonexistent_file_xyz.tmp"))
            fail("Expected exception for non-existent file")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("Cannot read file"))
        }
    }

    @Test
    fun sha256_largeFile_streamingConsistent() {
        // Exercises the chunked (BUFFER_SIZE) read path with content spanning many buffers
        // and a size that is NOT a multiple of the buffer size.
        val data = ByteArray(1_234_567) { (it * 31).toByte() }
        val f1 = File.createTempFile("hash_large_a", ".tmp").apply { writeBytes(data) }
        val f2 = File.createTempFile("hash_large_b", ".tmp").apply { writeBytes(data) }
        assertEquals("Large-file hashing must be stable across runs/buffers", HashUtils.sha256(f1), HashUtils.sha256(f2))
        assertEquals(64, HashUtils.sha256(f1).length)
        f1.delete(); f2.delete()
    }

    @Test
    fun sha256_directory_throws() {
        val dir = File.createTempFile("hash_dir", ".tmp").apply { delete(); mkdirs() }
        try {
            HashUtils.sha256(dir)
            fail("Expected exception for a directory")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("Cannot read file"))
        } finally {
            dir.delete()
        }
    }
}
