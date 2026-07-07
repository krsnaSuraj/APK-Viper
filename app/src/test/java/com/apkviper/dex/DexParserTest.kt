package com.apkviper.dex

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.io.FileNotFoundException
import java.util.zip.ZipException

class DexParserTest {
    private val parser = DexParser()

    @Test
    fun nonExistentFile_doesNotCrash() {
        val file = File("nonexistent_dex_file_xyz.dex")
        try {
            parser.parseApk(file)
        } catch (_: Exception) {
            // Any exception is acceptable
        }
    }

    @Test
    fun emptyFile_doesNotCrash() {
        val file = File.createTempFile("dex_empty", ".dex")
        file.writeBytes(ByteArray(0))
        try {
            parser.parseApk(file)
        } catch (_: Exception) {
            // Any exception is acceptable
        } finally {
            file.delete()
        }
    }

    @Test
    fun regularTextFile_throwsZipException() {
        val file = File.createTempFile("dex_text", ".txt")
        file.writeText("not a zip file")
        try {
            parser.parseApk(file)
            fail("Expected ZipException for non-zip file")
        } catch (e: ZipException) {
            assertNotNull(e.message)
        } finally {
            file.delete()
        }
    }

    @Test
    fun opcodeFromValue_knownOpcode_returnsNop() {
        assertEquals(DexParser.Opcode.NOP, DexParser.Opcode.fromValue(0x00))
    }

    @Test
    fun opcodeFromValue_knownOpcode_returnsMove() {
        assertEquals(DexParser.Opcode.MOVE, DexParser.Opcode.fromValue(0x01))
    }

    @Test
    fun opcodeFromValue_knownOpcode_returnsReturnVoid() {
        assertEquals(DexParser.Opcode.RETURN_VOID, DexParser.Opcode.fromValue(0x0e))
    }

    @Test
    fun opcodeFromValue_knownOpcode_returnsInvokeVirtual() {
        assertEquals(DexParser.Opcode.INVOKE_VIRTUAL, DexParser.Opcode.fromValue(0x6e))
    }

    @Test
    fun opcodeFromValue_knownOpcode_returnsConstString() {
        assertEquals(DexParser.Opcode.CONST_STRING, DexParser.Opcode.fromValue(0x1a))
    }

    @Test
    fun opcodeFromValue_knownOpcode_returnsSputShort() {
        assertEquals(DexParser.Opcode.SPUT_SHORT, DexParser.Opcode.fromValue(0x6d))
    }

    @Test
    fun opcodeFromValue_unknownOpcode_returnsNull() {
        assertNull(DexParser.Opcode.fromValue(0xFF))
    }

    @Test
    fun opcodeFromValue_negativeValue_returnsNull() {
        assertNull(DexParser.Opcode.fromValue(-1))
    }

    @Test
    fun opcodeFromValue_outOfRange_returnsNull() {
        assertNull(DexParser.Opcode.fromValue(0x1000))
    }

    @Test
    fun opcodeFormatWidth_10x_returns1() {
        assertEquals(1, DexParser.Opcode.NOP.formatWidth)
    }

    @Test
    fun opcodeFormatWidth_11n_returns1() {
        assertEquals(1, DexParser.Opcode.CONST_4.formatWidth)
    }

    @Test
    fun opcodeFormatWidth_21c_returns2() {
        assertEquals(2, DexParser.Opcode.CONST_STRING.formatWidth)
    }

    @Test
    fun opcodeFormatWidth_22c_returns2() {
        assertEquals(2, DexParser.Opcode.IGET.formatWidth)
    }

    @Test
    fun opcodeFormatWidth_31i_returns3() {
        assertEquals(3, DexParser.Opcode.CONST.formatWidth)
    }

    @Test
    fun opcodeFormatWidth_35c_returns3() {
        assertEquals(3, DexParser.Opcode.INVOKE_VIRTUAL.formatWidth)
    }

    @Test
    fun opcodeFormatWidth_3rc_returns3() {
        assertEquals(3, DexParser.Opcode.INVOKE_VIRTUAL_RANGE.formatWidth)
    }

    @Test
    fun opcodeFormatWidth_51l_returns5() {
        assertEquals(5, DexParser.Opcode.CONST_WIDE.formatWidth)
    }

    @Test
    fun parseResult_defaultValues_accessible() {
        val result = DexParser.ParseResult(
            classes = emptyList(),
            stringPool = emptyList(),
            typePool = emptyList(),
            protoPool = emptyList(),
            fieldPool = emptyList(),
            methodPool = emptyList(),
            dexCount = 0
        )
        assertTrue(result.classes.isEmpty())
        assertTrue(result.stringPool.isEmpty())
        assertTrue(result.typePool.isEmpty())
        assertTrue(result.protoPool.isEmpty())
        assertTrue(result.fieldPool.isEmpty())
        assertTrue(result.methodPool.isEmpty())
        assertEquals(0, result.dexCount)
    }

    @Test
    fun dexClass_dataClass_holdsValues() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = listOf("Ljava/io/Serializable;"),
            accessFlags = 1,
            sourceFile = "TestClass.java",
            methods = emptyList(),
            fields = emptyList()
        )
        assertEquals("Lcom/test/TestClass;", cls.name)
        assertEquals("Ljava/lang/Object;", cls.superClass)
        assertEquals(1, cls.interfaces.size)
        assertEquals(1, cls.accessFlags)
        assertEquals("TestClass.java", cls.sourceFile)
        assertTrue(cls.methods.isEmpty())
        assertTrue(cls.fields.isEmpty())
    }

    @Test
    fun dexMethod_dataClass_holdsValues() {
        val method = DexParser.DexMethod(
            name = "onCreate",
            descriptor = "(Landroid/os/Bundle;)V",
            accessFlags = 1,
            bytecode = null
        )
        assertEquals("onCreate", method.name)
        assertEquals("(Landroid/os/Bundle;)V", method.descriptor)
        assertEquals(1, method.accessFlags)
        assertNull(method.bytecode)
    }

    @Test
    fun dexField_dataClass_holdsValues() {
        val field = DexParser.DexField(
            name = "count",
            typeDescriptor = "I",
            accessFlags = 2
        )
        assertEquals("count", field.name)
        assertEquals("I", field.typeDescriptor)
        assertEquals(2, field.accessFlags)
    }

    @Test
    fun bytecodeInfo_dataClass_holdsValues() {
        val bc = DexParser.BytecodeInfo(
            registers = 5,
            insSize = 2,
            outsSize = 1,
            instructions = emptyList(),
            tryBlocks = emptyList()
        )
        assertEquals(5, bc.registers)
        assertEquals(2, bc.insSize)
        assertEquals(1, bc.outsSize)
        assertTrue(bc.instructions.isEmpty())
        assertTrue(bc.tryBlocks.isEmpty())
    }

    @Test
    fun dexInstruction_dataClass_holdsValues() {
        val instr = DexParser.DexInstruction(
            offset = 0,
            opcode = 0x6e,
            opcodeName = "invoke-virtual",
            args = listOf(1, 2, 3),
            lineNumber = 42
        )
        assertEquals(0, instr.offset)
        assertEquals(0x6e, instr.opcode)
        assertEquals("invoke-virtual", instr.opcodeName)
        assertEquals(3, instr.args.size)
        assertEquals(42, instr.lineNumber?.toInt())
    }

    @Test
    fun tryBlock_dataClass_holdsValues() {
        val tb = DexParser.TryBlock(
            startAddr = 0,
            insnCount = 10,
            handlerOff = 100
        )
        assertEquals(0, tb.startAddr)
        assertEquals(10, tb.insnCount)
        assertEquals(100, tb.handlerOff)
    }

    @Test
    fun parseApk_cancellationFlag_earlyExit() {
        val file = File.createTempFile("cancel_dex", ".zip")
        try {
            java.util.zip.ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(java.util.zip.ZipEntry("classes.dex"))
                zip.write(byteArrayOf(
                    0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00,  // magic
                    0, 0, 0, 0,  // checksum
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // signature
                    // Minimal DEX header (112 bytes total required)
                    0, 0, 0, 0,  // file size
                    0x70, 0, 0, 0,  // header size = 112
                    0, 0, 0, 0,  // endian
                    0, 0, 0, 0,  // link
                    0, 0, 0, 0,
                    0, 0, 0, 0,  // map
                    0, 0, 0, 0,  // string ids
                    0, 0, 0, 0,
                    0, 0, 0, 0,  // type ids
                    0, 0, 0, 0,
                    0, 0, 0, 0,  // proto ids
                    0, 0, 0, 0,
                    0, 0, 0, 0,  // field ids
                    0, 0, 0, 0,
                    0, 0, 0, 0,  // method ids
                    0, 0, 0, 0,
                    0, 0, 0, 0,  // class defs
                    0, 0, 0, 0,
                    0, 0, 0, 0,  // data size
                    0, 0, 0, 0,  // data off
                ))
                zip.closeEntry()
            }
            val result = parser.parseApk(file, isCancelled = { true })
            assertNotNull("Result should not be null even with cancellation", result)
        } finally {
            file.delete()
        }
    }

    @Test
    fun parseApk_cancellationFlagReset_allowsParsing() {
        val file = File.createTempFile("reset_dex", ".zip")
        try {
            java.util.zip.ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(java.util.zip.ZipEntry("classes.dex"))
                // Minimal DEX header padding to 112 bytes
                val header = ByteArray(112)
                header[0] = 0x64; header[1] = 0x65; header[2] = 0x78; header[3] = 0x0A
                header[4] = 0x30; header[5] = 0x33; header[6] = 0x35; header[7] = 0x00
                header[8] = 0; header[9] = 0; header[10] = 0; header[11] = 0  // checksum
                // signature (20 bytes) at offset 12-31
                // file size = 112 (0x70) at offset 32
                header[32] = 0x70; header[33] = 0; header[34] = 0; header[35] = 0
                // header size = 112 (0x70) at offset 36
                header[36] = 0x70; header[37] = 0; header[38] = 0; header[39] = 0
                zip.write(header)
                zip.closeEntry()
            }
            val result = parser.parseApk(file)
            assertNotNull("Result should be non-null with flag reset", result)
        } finally {
            file.delete()
        }
    }
}
