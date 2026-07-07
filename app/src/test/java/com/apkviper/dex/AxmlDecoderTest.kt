package com.apkviper.dex

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AxmlDecoderTest {
    private val decoder = AxmlDecoder()

    @Test
    fun emptyByteArray_returnsEmptyString() {
        val result = decoder.decode(ByteArray(0))
        assertEquals("", result)
    }

    @Test
    fun minimalValidHeader_noCrash() {
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0003) // RES_XML_TYPE
        buf.putShort(8)      // header size
        buf.putInt(8)        // chunk size
        val result = decoder.decode(buf.array())
        assertEquals("", result)
    }

    @Test
    fun stringPoolOnly_doesNotCrash() {
        val buf = ByteBuffer.allocate(8 + 28).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0003)  // RES_XML_TYPE
        buf.putShort(8)
        buf.putInt(36)        // total chunk: 8 + 28

        buf.putShort(0x0001)  // RES_STRING_POOL_TYPE
        buf.putShort(28)      // header size
        buf.putInt(28)        // chunk size
        buf.putInt(0)         // stringCount = 0
        buf.putInt(0)         // styleCount
        buf.putInt(0)         // flags
        buf.putInt(0)         // stringStartOffset
        buf.putInt(0)         // styleStartOffset

        val result = decoder.decode(buf.array())
        assertEquals("", result)
    }

    @Test
    fun startNamespaceWithoutStringPool_doesNotCrash() {
        val buf = ByteBuffer.allocate(8 + 16).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0003)
        buf.putShort(8)
        buf.putInt(24)

        buf.putShort(0x0100)  // RES_XML_START_NAMESPACE_TYPE
        buf.putShort(16)      // header size
        buf.putInt(16)        // chunk size
        buf.putInt(0)         // prefixIdx
        buf.putInt(0)         // uriIdx

        val result = decoder.decode(buf.array())
        assertEquals("", result)
    }

    @Test
    fun randomGarbageData_doesNotThrow() {
        val garbage = ByteArray(256) { it.toByte() }
        val result = decoder.decode(garbage)
        assertNotNull(result)
    }

    @Test
    fun allChunkTypesEncountered_doesNotThrow() {
        val buf = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0003)
        buf.putShort(8)
        buf.putInt(1024)

        buf.putShort(0x0100.toShort()) // start namespace
        buf.putShort(16)
        buf.putInt(16)
        buf.putInt(0); buf.putInt(0)

        buf.putShort(0x0101.toShort()) // end namespace
        buf.putShort(8)
        buf.putInt(8)

        buf.putShort(0x0180.toShort()) // resource map
        buf.putShort(8)
        buf.putInt(8)

        buf.putShort(0x0102.toShort()) // start element
        buf.putShort(24)
        buf.putInt(24)
        buf.putInt(0); buf.putInt(0); buf.putInt(0); buf.putInt(0)
        buf.putShort(0); buf.putShort(0); buf.putShort(0); buf.putShort(0)

        buf.putShort(0x0103.toShort()) // end element
        buf.putShort(8); buf.putInt(8)
        buf.putInt(0); buf.putInt(0)

        // Fill rest with zeros
        while (buf.hasRemaining()) buf.put(0)

        buf.flip()
        val result = decoder.decode(buf.array())
        assertNotNull(result)
    }

    @Test
    fun cdataWithoutStringPool_doesNotThrow() {
        val buf = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0003)
        buf.putShort(8)
        buf.putInt(32)

        buf.putShort(0x0104.toShort()) // RES_XML_CDATA_TYPE
        buf.putShort(8)
        buf.putInt(20) // chunkSize: 8 header + 12 of body
        buf.putInt(99)  // line number
        buf.putInt(0)   // comment
        buf.putInt(0)   // dataIdx
        // remaining = 20 - 8 - 12 = 0, so loop doesn't run

        val result = decoder.decode(buf.array())
        assertEquals("", result)
    }

    @Test
    fun unknownChunkType_skippedGracefully() {
        val buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0003)
        buf.putShort(8)
        buf.putInt(16)

        buf.putShort(0xFFFF.toShort()) // unknown chunk type
        buf.putShort(8)
        buf.putInt(8) // chunk size = 8, loop skips 0 bytes

        val result = decoder.decode(buf.array())
        assertEquals("", result)
    }

    @Test
    fun veryLargeInput_doesNotOom() {
        val size = 1024 * 1024 // 1 MB
        val data = ByteArray(size)
        // First 8 bytes are a valid RES_XML_TYPE header
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0003)
        buf.putShort(8)
        buf.putInt(size)
        // The rest will be treated as unknown chunks, skipped via guard loops
        val result = decoder.decode(data)
        assertNotNull(result)
    }

    @Test
    fun truncatedChunkData_doesNotThrow() {
        val data = byteArrayOf(
            0x03, 0x00, 0x08, 0x00, 0x20, 0x00, 0x00, 0x00, // RES_XML_TYPE header (chunkSize=32)
            0x02.toByte(), 0x01.toByte(), 0x08, 0x00, 0x20, 0x00, 0x00, 0x00, // START_ELEMENT
            0x00, 0x00, 0x00, 0x00  // only 4 more bytes, but chunk claims 32
        )
        try {
            decoder.decode(data)
        } catch (_: IllegalArgumentException) {
            // Expected for truncated data
        }
    }
}
