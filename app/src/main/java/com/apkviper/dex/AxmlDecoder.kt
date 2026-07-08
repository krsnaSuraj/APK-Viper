package com.apkviper.dex

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure Kotlin decoder for Android Binary XML (AXML) format.
 * Decodes binary AndroidManifest.xml and resource files into human-readable XML.
 *
 * AXML format is documented in Android's ResourceTypes.h and aapt source.
 */
class AxmlDecoder {

    fun decode(axmlData: ByteArray): String {
        val stringPool = mutableListOf<String>()
        val nsPrefixByUri = mutableMapOf<String, String>()

        val buf = ByteBuffer.wrap(axmlData).order(ByteOrder.LITTLE_ENDIAN)
        val sb = StringBuilder(axmlData.size * 2)
        var indent = 0
        var lineStart = true
        val selfCloseStack = ArrayDeque<Pair<String, Int>>() // (name, position before '>')

        try {
            while (buf.hasRemaining()) {
            val chunkType = buf.short.toInt() and 0xFFFF
            buf.short // chunk header size (skip)
            val chunkSize = buf.int

            when (chunkType) {
                RES_XML_TYPE -> {
                    // XML resource header - skip it
                    buf.position(buf.position() + chunkSize - 8)
                }
                RES_STRING_POOL_TYPE -> {
                    readStringPool(buf, chunkSize, stringPool)
                }
                RES_XML_RESOURCE_MAP_TYPE -> {
                    buf.position(buf.position() + chunkSize - 8)
                }
                RES_XML_START_NAMESPACE_TYPE -> {
                    val prefixIdx = buf.int
                    val uriIdx = buf.int
                    val prefix = stringPool.getOrElse(prefixIdx) { "" }
                    val uri = stringPool.getOrElse(uriIdx) { "" }
                    if (prefix.isNotEmpty() && uri.isNotEmpty()) {
                        nsPrefixByUri[uri] = prefix
                    }
                }
                RES_XML_END_NAMESPACE_TYPE -> {
                    // Skip namespace end
                }
                RES_XML_START_ELEMENT_TYPE -> {
                    @Suppress("UNUSED_VARIABLE") val lineNumber = buf.int
                    buf.int // comment
                    @Suppress("UNUSED_VARIABLE") val nsIdx = buf.int
                    val nameIdx = buf.int

                    val name = stringPool.getOrElse(nameIdx) { "unknown" }
                    val attCount = buf.short.toInt() and 0xFFFF
                    @Suppress("UNUSED_VARIABLE") val idAttr = buf.short.toInt() and 0xFFFF
                    @Suppress("UNUSED_VARIABLE") val classAttr = buf.short.toInt() and 0xFFFF
                    @Suppress("UNUSED_VARIABLE") val styleAttr = buf.short.toInt() and 0xFFFF

                    if (lineStart) {
                        sb.append("\n")
                        lineStart = false
                    }
                    sb.append(" ".repeat(indent))
                    sb.append("<$name")

                    for (i in 0 until attCount) {
                        val attrNs = buf.int
                        val attrNameIdx = buf.int
                        val attrRawValue = buf.int

                        buf.short  // size (2 bytes)
                        buf.get()  // reserved (1 byte)
                        val dataType = buf.get().toInt()  // dataType (1 byte)
                        val data = buf.int  // data (4 bytes) = 8 bytes total

                        val attrName = stringPool.getOrElse(attrNameIdx) { "" }
                        val nsPrefix = if (attrNs >= 0 && attrNs < stringPool.size) {
                            val uri = stringPool[attrNs]
                            nsPrefixByUri[uri]
                        } else null
                        val qualifiedName = if (nsPrefix != null) "$nsPrefix:$attrName" else attrName

                        if (qualifiedName.isNotEmpty()) {
                            val value = when (dataType) {
                                3 -> stringPool.getOrElse(data) { data.toString() }
                                4 -> data.toFloat().toString()
                                0x10 -> "$data"
                                0x11 -> if (data != 0) "true" else "false"
                                else -> stringPool.getOrElse(attrRawValue) { attrRawValue.toString() }
                            }
                            sb.append("\n")
                            sb.append(" ".repeat(indent + 4))
                            sb.append("$qualifiedName=\"$value\"")
                        }
                    }

                    // Push onto stack so END_ELEMENT can decide self-closing
                    sb.append(">")
                    selfCloseStack.addLast(name to (sb.length - 1))
                    indent += 2
                }
                RES_XML_END_ELEMENT_TYPE -> {
                    indent -= 2
                    @Suppress("UNUSED_VARIABLE") val nsIdx = buf.int
                    val nameIdx = buf.int
                    val name = stringPool.getOrElse(nameIdx) { "unknown" }

                    // Check if element was empty (no content between > and </name>)
                    val startInfo = selfCloseStack.removeLastOrNull()
                    if (startInfo != null && startInfo.first == name) {
                        val startGtIdx = startInfo.second
                        val contentAfter = sb.substring(startGtIdx + 1)
                        val endTagPattern = "\\s*</$name>\\s*$".toRegex()
                        if (contentAfter.matches(endTagPattern)) {
                            sb.replace(startGtIdx, startGtIdx + 1, "/>")
                            sb.setLength(sb.length - ("</$name>\n".length))
                            if (sb.isNotEmpty() && sb.last() == '\n') sb.setLength(sb.length - 1)
                            lineStart = true
                            continue
                        }
                    }

                    sb.append(" ".repeat(indent.coerceAtLeast(0)))
                    sb.append("</$name>\n")
                    lineStart = true
                }
                RES_XML_CDATA_TYPE -> {
                    buf.int // line number
                    buf.int // comment (string pool ref)
                    val dataIdx = buf.int
                    // Skip remaining CDATA data (typedData or padding)
                    val remaining = chunkSize - 8 - 12
                    for (i in 0 until remaining) {
                        if (buf.hasRemaining()) buf.get()
                    }
                    sb.append(stringPool.getOrElse(dataIdx) { "" })
                }
                else -> {
                    for (i in 8 until chunkSize) {
                        if (buf.hasRemaining()) buf.get()
                    }
                }
            }
            }
        } catch (_: Exception) {
            // Malformed/truncated AXML — stop parsing and return partial output
        }

        return sb.toString()
    }

    private fun readStringPool(buf: ByteBuffer, chunkSize: Int, stringPool: MutableList<String>) {
        val startPos = buf.position() - 8

        val stringCount = buf.int
        @Suppress("UNUSED_VARIABLE") val styleCount = buf.int
        val flags = buf.int
        val stringStartOffset = buf.int
        @Suppress("UNUSED_VARIABLE") val styleStartOffset = buf.int

        val isUtf8 = flags and (1 shl 8) != 0

        val offsets = IntArray(stringCount)
        for (i in 0 until stringCount) {
            offsets[i] = buf.int
        }

        for (i in 0 until stringCount) {
            val offset = startPos + stringStartOffset + offsets[i]
            val savedPos = buf.position()
            buf.position(offset)

            val str = if (isUtf8) {
                readUtf8String(buf, offset)
            } else {
                readUtf16String(buf, offset)
            }

            stringPool.add(str)
            buf.position(savedPos)
        }

        buf.position(startPos + chunkSize - 8)
    }

    private fun readUtf8String(buf: ByteBuffer, @Suppress("UNUSED_PARAMETER") offset: Int): String {
        val len = readUtf8Length(buf)
        val sb = StringBuilder(len)
        var i = 0
        while (i < len) {
            val b = buf.get().toInt() and 0xFF
            when {
                b and 0x80 == 0 -> sb.append(b.toChar())
                b and 0xE0 == 0xC0 -> {
                    val b2 = buf.get().toInt() and 0x3F
                    sb.append(((b and 0x1F) shl 6 or b2).toChar())
                }
                b and 0xF0 == 0xE0 -> {
                    val b2 = buf.get().toInt() and 0x3F
                    val b3 = buf.get().toInt() and 0x3F
                    sb.append(((b and 0x0F) shl 12 or (b2 shl 6) or b3).toChar())
                }
                b and 0xF8 == 0xF0 -> {
                    val b2 = buf.get().toInt() and 0x3F
                    val b3 = buf.get().toInt() and 0x3F
                    val b4 = buf.get().toInt() and 0x3F
                    val codePoint = (b and 0x07) shl 18 or (b2 shl 12) or (b3 shl 6) or b4
                    sb.append(Character.toChars(codePoint))
                }
            }
            i++
        }
        return sb.toString()
    }

    private fun readUtf16String(buf: ByteBuffer, @Suppress("UNUSED_PARAMETER") offset: Int): String {
        val len = readUtf16Length(buf)
        val sb = StringBuilder(len)
        for (i in 0 until len) {
            sb.append(buf.short.toInt().toChar())
        }
        return sb.toString()
    }

    private fun readUtf8Length(buf: ByteBuffer): Int {
        val b1 = buf.get().toInt() and 0xFF
        return if (b1 and 0x80 != 0) {
            val b2 = buf.get().toInt() and 0xFF
            (b1 and 0x7F shl 8) or b2
        } else {
            b1
        }
    }

    private fun readUtf16Length(buf: ByteBuffer): Int {
        val b1 = buf.short.toInt() and 0xFFFF
        return if (b1 and 0x8000 != 0) {
            val b2 = buf.short.toInt() and 0xFFFF
            (b1 and 0x7FFF shl 16) or b2
        } else {
            b1
        }
    }

    companion object {
        // Chunk type constants
        const val RES_XML_TYPE = 0x0003
        const val RES_STRING_POOL_TYPE = 0x0001
        const val RES_XML_RESOURCE_MAP_TYPE = 0x0180
        const val RES_XML_START_NAMESPACE_TYPE = 0x0100
        const val RES_XML_END_NAMESPACE_TYPE = 0x0101
        const val RES_XML_START_ELEMENT_TYPE = 0x0102
        const val RES_XML_END_ELEMENT_TYPE = 0x0103
        const val RES_XML_CDATA_TYPE = 0x0104
    }
}
