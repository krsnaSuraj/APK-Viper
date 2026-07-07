@file:Suppress("NAME_SHADOWING", "UNUSED_PARAMETER")
package com.apkviper.dex

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * Pure Kotlin DEX file parser. Parses the Android DEX bytecode format
 * and extracts classes, methods, strings, and opcodes for analysis.
 *
 * DEX format spec: https://source.android.com/docs/core/runtime/dex-format
 */
class DexParser {

    data class DexClass(
        val name: String,
        val superClass: String,
        val interfaces: List<String>,
        val accessFlags: Int,
        val sourceFile: String?,
        val methods: List<DexMethod>,
        val fields: List<DexField>
    )

    data class DexMethod(
        val name: String,
        val descriptor: String,
        val accessFlags: Int,
        var bytecode: BytecodeInfo?
    )

    data class DexField(
        val name: String,
        val typeDescriptor: String,
        val accessFlags: Int
    )

    data class BytecodeInfo(
        val registers: Int,
        val insSize: Int,
        val outsSize: Int,
        val instructions: List<DexInstruction>,
        val tryBlocks: List<TryBlock>
    )

    data class DexInstruction(
        val offset: Int,
        val opcode: Int,
        val opcodeName: String,
        val args: List<Int>,
        val lineNumber: Int?
    )

    data class TryBlock(
        val startAddr: Int,
        val insnCount: Int,
        val handlerOff: Int
    )

    class ParseResult(
        val classes: List<DexClass>,
        val stringPool: List<String>,
        val typePool: List<String>,
        val protoPool: List<String>,
        val fieldPool: List<String>,
        val methodPool: List<String>,
        val dexCount: Int
    )

    // Dalvik opcodes
    enum class Opcode(val value: Int, val opcodeName: String, val format: String) {
        NOP(0x00, "nop", "10x"),
        MOVE(0x01, "move", "12x"),
        MOVE_FROM16(0x02, "move/from16", "22x"),
        MOVE_16(0x03, "move/16", "32x"),
        MOVE_WIDE(0x04, "move-wide", "12x"),
        MOVE_WIDE_FROM16(0x05, "move-wide/from16", "22x"),
        MOVE_WIDE_16(0x06, "move-wide/16", "32x"),
        MOVE_OBJECT(0x07, "move-object", "12x"),
        MOVE_OBJECT_FROM16(0x08, "move-object/from16", "22x"),
        MOVE_OBJECT_16(0x09, "move-object/16", "32x"),
        MOVE_RESULT(0x0a, "move-result", "11x"),
        MOVE_RESULT_WIDE(0x0b, "move-result-wide", "11x"),
        MOVE_RESULT_OBJECT(0x0c, "move-result-object", "11x"),
        MOVE_EXCEPTION(0x0d, "move-exception", "11x"),
        RETURN_VOID(0x0e, "return-void", "10x"),
        RETURN(0x0f, "return", "11x"),
        RETURN_WIDE(0x10, "return-wide", "11x"),
        RETURN_OBJECT(0x11, "return-object", "11x"),
        CONST_4(0x12, "const/4", "11n"),
        CONST_16(0x13, "const/16", "21s"),
        CONST(0x14, "const", "31i"),
        CONST_HIGH16(0x15, "const/high16", "21h"),
        CONST_WIDE_16(0x16, "const-wide/16", "21s"),
        CONST_WIDE_32(0x17, "const-wide/32", "31i"),
        CONST_WIDE(0x18, "const-wide", "51l"),
        CONST_WIDE_HIGH16(0x19, "const-wide/high16", "21h"),
        CONST_STRING(0x1a, "const-string", "21c"),
        CONST_STRING_JUMBO(0x1b, "const-string/jumbo", "31c"),
        CONST_CLASS(0x1c, "const-class", "21c"),
        MONITOR_ENTER(0x1d, "monitor-enter", "11x"),
        MONITOR_EXIT(0x1e, "monitor-exit", "11x"),
        CHECK_CAST(0x1f, "check-cast", "21c"),
        INSTANCE_OF(0x20, "instance-of", "22c"),
        ARRAY_LENGTH(0x21, "array-length", "12x"),
        NEW_INSTANCE(0x22, "new-instance", "21c"),
        NEW_ARRAY(0x23, "new-array", "22c"),
        FILLED_NEW_ARRAY(0x24, "filled-new-array", "35c"),
        FILLED_NEW_ARRAY_RANGE(0x25, "filled-new-array/range", "3rc"),
        FILL_ARRAY_DATA(0x26, "fill-array-data", "31t"),
        THROW(0x27, "throw", "11x"),
        GOTO(0x28, "goto", "10t"),
        GOTO_16(0x29, "goto/16", "20t"),
        GOTO_32(0x2a, "goto/32", "30t"),
        PACKED_SWITCH(0x2b, "packed-switch", "31t"),
        SPARSE_SWITCH(0x2c, "sparse-switch", "31t"),
        CMPL_FLOAT(0x2d, "cmpl-float", "23x"),
        CMPG_FLOAT(0x2e, "cmpg-float", "23x"),
        CMPL_DOUBLE(0x2f, "cmpl-double", "23x"),
        CMPG_DOUBLE(0x30, "cmpg-double", "23x"),
        CMP_LONG(0x31, "cmp-long", "23x"),
        IF_EQ(0x32, "if-eq", "22t"),
        IF_NE(0x33, "if-ne", "22t"),
        IF_LT(0x34, "if-lt", "22t"),
        IF_GE(0x35, "if-ge", "22t"),
        IF_GT(0x36, "if-gt", "22t"),
        IF_LE(0x37, "if-le", "22t"),
        IF_EQZ(0x38, "if-eqz", "21t"),
        IF_NEZ(0x39, "if-nez", "21t"),
        IF_LTZ(0x3a, "if-ltz", "21t"),
        IF_GEZ(0x3b, "if-gez", "21t"),
        IF_GTZ(0x3c, "if-gtz", "21t"),
        IF_LEZ(0x3d, "if-lez", "21t"),
        AGET(0x44, "aget", "23x"),
        AGET_WIDE(0x45, "aget-wide", "23x"),
        AGET_OBJECT(0x46, "aget-object", "23x"),
        AGET_BOOLEAN(0x47, "aget-boolean", "23x"),
        AGET_BYTE(0x48, "aget-byte", "23x"),
        AGET_CHAR(0x49, "aget-char", "23x"),
        AGET_SHORT(0x4a, "aget-short", "23x"),
        APUT(0x4b, "aput", "23x"),
        APUT_WIDE(0x4c, "aput-wide", "23x"),
        APUT_OBJECT(0x4d, "aput-object", "23x"),
        APUT_BOOLEAN(0x4e, "aput-boolean", "23x"),
        APUT_BYTE(0x4f, "aput-byte", "23x"),
        APUT_CHAR(0x50, "aput-char", "23x"),
        APUT_SHORT(0x51, "aput-short", "23x"),
        IGET(0x52, "iget", "22c"),
        IGET_WIDE(0x53, "iget-wide", "22c"),
        IGET_OBJECT(0x54, "iget-object", "22c"),
        IGET_BOOLEAN(0x55, "iget-boolean", "22c"),
        IGET_BYTE(0x56, "iget-byte", "22c"),
        IGET_CHAR(0x57, "iget-char", "22c"),
        IGET_SHORT(0x58, "iget-short", "22c"),
        IPUT(0x59, "iput", "22c"),
        IPUT_WIDE(0x5a, "iput-wide", "22c"),
        IPUT_OBJECT(0x5b, "iput-object", "22c"),
        IPUT_BOOLEAN(0x5c, "iput-boolean", "22c"),
        IPUT_BYTE(0x5d, "iput-byte", "22c"),
        IPUT_CHAR(0x5e, "iput-char", "22c"),
        IPUT_SHORT(0x5f, "iput-short", "22c"),
        SGET(0x60, "sget", "21c"),
        SGET_WIDE(0x61, "sget-wide", "21c"),
        SGET_OBJECT(0x62, "sget-object", "21c"),
        SGET_BOOLEAN(0x63, "sget-boolean", "21c"),
        SGET_BYTE(0x64, "sget-byte", "21c"),
        SGET_CHAR(0x65, "sget-char", "21c"),
        SGET_SHORT(0x66, "sget-short", "21c"),
        SPUT(0x67, "sput", "21c"),
        SPUT_WIDE(0x68, "sput-wide", "21c"),
        SPUT_OBJECT(0x69, "sput-object", "21c"),
        SPUT_BOOLEAN(0x6a, "sput-boolean", "21c"),
        SPUT_BYTE(0x6b, "sput-byte", "21c"),
        SPUT_CHAR(0x6c, "sput-char", "21c"),
        SPUT_SHORT(0x6d, "sput-short", "21c"),
        INVOKE_VIRTUAL(0x6e, "invoke-virtual", "35c"),
        INVOKE_SUPER(0x6f, "invoke-super", "35c"),
        INVOKE_DIRECT(0x70, "invoke-direct", "35c"),
        INVOKE_STATIC(0x71, "invoke-static", "35c"),
        INVOKE_INTERFACE(0x72, "invoke-interface", "35c"),
        INVOKE_VIRTUAL_RANGE(0x74, "invoke-virtual/range", "3rc"),
        INVOKE_SUPER_RANGE(0x75, "invoke-super/range", "3rc"),
        INVOKE_DIRECT_RANGE(0x76, "invoke-direct/range", "3rc"),
        INVOKE_STATIC_RANGE(0x77, "invoke-static/range", "3rc"),
        INVOKE_INTERFACE_RANGE(0x78, "invoke-interface/range", "3rc"),
        NEG_INT(0x7b, "neg-int", "12x"),
        NOT_INT(0x7c, "not-int", "12x"),
        NEG_LONG(0x7d, "neg-long", "12x"),
        NOT_LONG(0x7e, "not-long", "12x"),
        NEG_FLOAT(0x7f, "neg-float", "12x"),
        NEG_DOUBLE(0x80, "neg-double", "12x"),
        INT_TO_LONG(0x81, "int-to-long", "12x"),
        INT_TO_FLOAT(0x82, "int-to-float", "12x"),
        INT_TO_DOUBLE(0x83, "int-to-double", "12x"),
        LONG_TO_INT(0x84, "long-to-int", "12x"),
        LONG_TO_FLOAT(0x85, "long-to-float", "12x"),
        LONG_TO_DOUBLE(0x86, "long-to-double", "12x"),
        FLOAT_TO_INT(0x87, "float-to-int", "12x"),
        FLOAT_TO_LONG(0x88, "float-to-long", "12x"),
        FLOAT_TO_DOUBLE(0x89, "float-to-double", "12x"),
        DOUBLE_TO_INT(0x8a, "double-to-int", "12x"),
        DOUBLE_TO_LONG(0x8b, "double-to-long", "12x"),
        DOUBLE_TO_FLOAT(0x8c, "double-to-float", "12x"),
        ADD_INT(0x90, "add-int", "23x"),
        SUB_INT(0x91, "sub-int", "23x"),
        MUL_INT(0x92, "mul-int", "23x"),
        DIV_INT(0x93, "div-int", "23x"),
        REM_INT(0x94, "rem-int", "23x"),
        AND_INT(0x95, "and-int", "23x"),
        OR_INT(0x96, "or-int", "23x"),
        XOR_INT(0x97, "xor-int", "23x"),
        SHL_INT(0x98, "shl-int", "23x"),
        SHR_INT(0x99, "shr-int", "23x"),
        USHR_INT(0x9a, "ushr-int", "23x"),
        ADD_LONG(0x9b, "add-long", "23x"),
        SUB_LONG(0x9c, "sub-long", "23x"),
        MUL_LONG(0x9d, "mul-long", "23x"),
        DIV_LONG(0x9e, "div-long", "23x"),
        REM_LONG(0x9f, "rem-long", "23x"),
        AND_LONG(0xa0, "and-long", "23x"),
        OR_LONG(0xa1, "or-long", "23x"),
        XOR_LONG(0xa2, "xor-long", "23x"),
        SHL_LONG(0xa3, "shl-long", "23x"),
        SHR_LONG(0xa4, "shr-long", "23x"),
        USHR_LONG(0xa5, "ushr-long", "23x"),
        ADD_FLOAT(0xa6, "add-float", "23x"),
        SUB_FLOAT(0xa7, "sub-float", "23x"),
        MUL_FLOAT(0xa8, "mul-float", "23x"),
        DIV_FLOAT(0xa9, "div-float", "23x"),
        REM_FLOAT(0xaa, "rem-float", "23x"),
        ADD_DOUBLE(0xab, "add-double", "23x"),
        SUB_DOUBLE(0xac, "sub-double", "23x"),
        MUL_DOUBLE(0xad, "mul-double", "23x"),
        DIV_DOUBLE(0xae, "div-double", "23x"),
        REM_DOUBLE(0xaf, "rem-double", "23x"),
        ADD_INT_2ADDR(0xb0, "add-int/2addr", "12x"),
        SUB_INT_2ADDR(0xb1, "sub-int/2addr", "12x"),
        MUL_INT_2ADDR(0xb2, "mul-int/2addr", "12x"),
        DIV_INT_2ADDR(0xb3, "div-int/2addr", "12x"),
        REM_INT_2ADDR(0xb4, "rem-int/2addr", "12x"),
        AND_INT_2ADDR(0xb5, "and-int/2addr", "12x"),
        OR_INT_2ADDR(0xb6, "or-int/2addr", "12x"),
        XOR_INT_2ADDR(0xb7, "xor-int/2addr", "12x"),
        SHL_INT_2ADDR(0xb8, "shl-int/2addr", "12x"),
        SHR_INT_2ADDR(0xb9, "shr-int/2addr", "12x"),
        USHR_INT_2ADDR(0xba, "ushr-int/2addr", "12x"),
        ADD_LONG_2ADDR(0xbb, "add-long/2addr", "12x"),
        SUB_LONG_2ADDR(0xbc, "sub-long/2addr", "12x"),
        MUL_LONG_2ADDR(0xbd, "mul-long/2addr", "12x"),
        DIV_LONG_2ADDR(0xbe, "div-long/2addr", "12x"),
        REM_LONG_2ADDR(0xbf, "rem-long/2addr", "12x"),
        AND_LONG_2ADDR(0xc0, "and-long/2addr", "12x"),
        OR_LONG_2ADDR(0xc1, "or-long/2addr", "12x"),
        XOR_LONG_2ADDR(0xc2, "xor-long/2addr", "12x"),
        SHL_LONG_2ADDR(0xc3, "shl-long/2addr", "12x"),
        SHR_LONG_2ADDR(0xc4, "shr-long/2addr", "12x"),
        USHR_LONG_2ADDR(0xc5, "ushr-long/2addr", "12x"),
        ADD_FLOAT_2ADDR(0xc6, "add-float/2addr", "12x"),
        SUB_FLOAT_2ADDR(0xc7, "sub-float/2addr", "12x"),
        MUL_FLOAT_2ADDR(0xc8, "mul-float/2addr", "12x"),
        DIV_FLOAT_2ADDR(0xc9, "div-float/2addr", "12x"),
        REM_FLOAT_2ADDR(0xca, "rem-float/2addr", "12x"),
        ADD_DOUBLE_2ADDR(0xcb, "add-double/2addr", "12x"),
        SUB_DOUBLE_2ADDR(0xcc, "sub-double/2addr", "12x"),
        MUL_DOUBLE_2ADDR(0xcd, "mul-double/2addr", "12x"),
        DIV_DOUBLE_2ADDR(0xce, "div-double/2addr", "12x"),
        REM_DOUBLE_2ADDR(0xcf, "rem-double/2addr", "12x"),
        ADD_INT_LIT16(0xd0, "add-int/lit16", "22s"),
        RSUB_INT(0xd1, "rsub-int", "22s"),
        MUL_INT_LIT16(0xd2, "mul-int/lit16", "22s"),
        DIV_INT_LIT16(0xd3, "div-int/lit16", "22s"),
        REM_INT_LIT16(0xd4, "rem-int/lit16", "22s"),
        AND_INT_LIT16(0xd5, "and-int/lit16", "22s"),
        OR_INT_LIT16(0xd6, "or-int/lit16", "22s"),
        XOR_INT_LIT16(0xd7, "xor-int/lit16", "22s"),
        ADD_INT_LIT8(0xd8, "add-int/lit8", "22b"),
        RSUB_INT_LIT8(0xd9, "rsub-int/lit8", "22b"),
        MUL_INT_LIT8(0xda, "mul-int/lit8", "22b"),
        DIV_INT_LIT8(0xdb, "div-int/lit8", "22b"),
        REM_INT_LIT8(0xdc, "rem-int/lit8", "22b"),
        AND_INT_LIT8(0xdd, "and-int/lit8", "22b"),
        OR_INT_LIT8(0xde, "or-int/lit8", "22b"),
        XOR_INT_LIT8(0xdf, "xor-int/lit8", "22b"),
        SHL_INT_LIT8(0xe0, "shl-int/lit8", "22b"),
        SHR_INT_LIT8(0xe1, "shr-int/lit8", "22b"),
        USHR_INT_LIT8(0xe2, "ushr-int/lit8", "22b");

        /** Number of 16-bit code units this opcode occupies */
        val formatWidth: Int
            get() = format.firstOrNull()?.digitToIntOrNull() ?: 1

        companion object {
            private val byValue = entries.associateBy { it.value }
            fun fromValue(value: Int): Opcode? = byValue[value]
        }
    }

    fun parseApk(file: File, isCancelled: () -> Boolean = { false }): ParseResult {
        val allClasses = mutableListOf<DexClass>()
        val allStrings = mutableListOf<String>()
        val allTypes = mutableListOf<String>()
        val allProtos = mutableListOf<String>()
        val allFields = mutableListOf<String>()
        val allMethods = mutableListOf<String>()
        var dexCount = 0
        var totalDexBytes = 0L

        ZipFile(file).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                if (isCancelled()) break
                val entry = entries.nextElement()
                if (entry.name.endsWith(".dex") && dexCount < 20) {
                    if (entry.size > 30 * 1024 * 1024) continue
                    totalDexBytes += entry.size
                    if (totalDexBytes > 200 * 1024 * 1024) break
                    try {
                        val data = zip.getInputStream(entry).readBytes()
                        val header = parseDexHeader(data)
                        val result = parseDexBody(data, header)
                        allClasses.addAll(result.classes)
                        allStrings.addAll(result.stringPool)
                        allTypes.addAll(result.typePool)
                        allProtos.addAll(result.protoPool)
                        allFields.addAll(result.fieldPool)
                        allMethods.addAll(result.methodPool)
                        dexCount++
                        if (allClasses.size > 8000) break
                    } catch (_: Exception) { }
                }
            }
        }

        return ParseResult(allClasses, allStrings, allTypes, allProtos, allFields, allMethods, dexCount)
    }

    private fun parseDexHeader(data: ByteArray): DexHeader {
        if (data.size < 112) throw IllegalArgumentException("Truncated DEX header: ${data.size} bytes")
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        return DexHeader(
            magic = ByteArray(8).also { buf.get(it) },
            checksum = buf.int,
            signature = ByteArray(20).also { buf.get(it) },
            fileSize = buf.int,
            headerSize = buf.int,
            endianTag = buf.int,
            linkSize = buf.int,
            linkOff = buf.int,
            mapOff = buf.int,
            stringIdsSize = buf.int,
            stringIdsOff = buf.int,
            typeIdsSize = buf.int,
            typeIdsOff = buf.int,
            protoIdsSize = buf.int,
            protoIdsOff = buf.int,
            fieldIdsSize = buf.int,
            fieldIdsOff = buf.int,
            methodIdsSize = buf.int,
            methodIdsOff = buf.int,
            classDefsSize = buf.int,
            classDefsOff = buf.int,
            dataSize = buf.int,
            dataOff = buf.int
        )
    }

    private fun parseDexBody(data: ByteArray, header: DexHeader): ParseResult {
        return try {
            val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

            val stringPool = readStringPool(buf, header)
            val typePool = readTypePool(buf, header, stringPool)
            val protoPool = readProtoPool(buf, header, stringPool, typePool)
            val fieldPool = readFieldPool(buf, header, stringPool, typePool)
            val methodPool = readMethodPool(buf, header, stringPool, typePool, protoPool)
            val classes = readClassDefs(buf, header, data, stringPool, typePool, fieldPool, methodPool)

            ParseResult(classes, stringPool, typePool, protoPool, fieldPool, methodPool, 1)
        } catch (e: Exception) {
            android.util.Log.e("DexParser", "Body parse failed: ${e.message}")
            ParseResult(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), 1)
        }
    }

    private fun readStringPool(buf: ByteBuffer, header: DexHeader): List<String> {
        val size = minOf(header.stringIdsSize, 50000)
        val strings = mutableListOf<String>()
        val dataSize = buf.capacity()

        for (i in 0 until size) {
            val idxPos = header.stringIdsOff + i * 4
            if (idxPos + 4 > dataSize) break
            buf.position(idxPos)
            val offset = buf.int
            if (offset < 0 || offset >= dataSize) continue
            try {
                buf.position(offset)
                strings.add(readMutf8(buf))
            } catch (_: Exception) { }
        }
        return strings
    }

    private fun readTypePool(buf: ByteBuffer, header: DexHeader, strings: List<String>): List<String> {
        val size = minOf(header.typeIdsSize, 50000)
        val types = mutableListOf<String>()
        for (i in 0 until size) {
            buf.position(header.typeIdsOff + i * 4)
            val descIdx = buf.int
            types.add(strings.getOrElse(descIdx) { "Lunknown;" })
        }
        return types
    }

    @Suppress("UNUSED_PARAMETER")
    private fun readProtoPool(buf: ByteBuffer, header: DexHeader, strings: List<String>, types: List<String>): List<String> {
        val size = minOf(header.protoIdsSize, 50000)
        val protos = mutableListOf<String>()
        for (i in 0 until size) {
            buf.position(header.protoIdsOff + i * 12)
            val shortyIdx = buf.int
            @Suppress("UNUSED_VARIABLE") val returnTypeIdx = buf.int
            @Suppress("UNUSED_VARIABLE") val paramsOff = buf.int
            protos.add(strings.getOrElse(shortyIdx) { "?" })
        }
        return protos
    }

    private fun readFieldPool(buf: ByteBuffer, header: DexHeader, strings: List<String>, types: List<String>): List<String> {
        val fields = mutableListOf<String>()
        for (i in 0 until minOf(header.fieldIdsSize, 50000)) {
            buf.position(header.fieldIdsOff + i * 8)
            val classIdx = buf.short.toInt() and 0xFFFF
            val typeIdx = buf.short.toInt() and 0xFFFF
            val nameIdx = buf.int
            fields.add("${types.getOrElse(classIdx){"?"}}->${strings.getOrElse(nameIdx){"?"}}:${types.getOrElse(typeIdx){"?"}}")
        }
        return fields
    }

    private fun readMethodPool(buf: ByteBuffer, header: DexHeader, strings: List<String>, types: List<String>, protos: List<String>): List<String> {
        val methods = mutableListOf<String>()
        for (i in 0 until minOf(header.methodIdsSize, 50000)) {
            buf.position(header.methodIdsOff + i * 8)
            val classIdx = buf.short.toInt() and 0xFFFF
            val protoIdx = buf.short.toInt() and 0xFFFF
            val nameIdx = buf.int
            val desc = protos.getOrElse(protoIdx) { "?" }
            methods.add("${types.getOrElse(classIdx){"?"}}->${strings.getOrElse(nameIdx){"?"}}$desc")
        }
        return methods
    }

    private fun readClassDefs(
        buf: ByteBuffer, header: DexHeader, data: ByteArray,
        strings: List<String>, types: List<String>,
        fieldPool: List<String>, methodPool: List<String>
    ): List<DexClass> {
        val classes = mutableListOf<DexClass>()
        val maxClasses = header.classDefsSize
        val dataSize = data.size

        for (i in 0 until maxClasses) {
            val classPos = header.classDefsOff + i * 32
            if (classPos + 32 > dataSize) break
            buf.position(classPos)
            val classIdx = buf.int
            val accessFlags = buf.int
            val superclassIdx = buf.int
            val interfacesOff = buf.int
            val sourceFileIdx = buf.int
            @Suppress("UNUSED_VARIABLE") val annotationsOff = buf.int
            val classDataOff = buf.int
            @Suppress("UNUSED_VARIABLE") val staticValuesOff = buf.int

            val className = types.getOrElse(classIdx) { "Lunknown;" }
            val superName = types.getOrElse(superclassIdx) { "Ljava/lang/Object;" }
            val sourceFile = if (sourceFileIdx >= 0) strings.getOrElse(sourceFileIdx) { null } else null

            // Parse interfaces
            val interfaces = mutableListOf<String>()
            if (interfacesOff > 0) {
                try {
                    buf.position(interfacesOff)
                    val ifCount = minOf(buf.int, 1000)
                    for (j in 0 until ifCount) {
                        val ifIdx = buf.short.toInt() and 0xFFFF
                        interfaces.add(types.getOrElse(ifIdx) { "Lunknown;" })
                    }
                } catch (_: Exception) { }
            }

            val methods = mutableListOf<DexMethod>()
            val fields = mutableListOf<DexField>()

            if (classDataOff > 0) {
                buf.position(classDataOff)
                val staticFieldsSize = readUleb128(buf)
                val instanceFieldsSize = readUleb128(buf)
                val directMethodsSize = readUleb128(buf)
                val virtualMethodsSize = readUleb128(buf)

                // Read encoded fields — delta encoded across ALL fields (static + instance)
                var fieldIdx = 0
                for (j in 0 until staticFieldsSize) {
                    fieldIdx += readUleb128(buf)
                    val accessFlags = readUleb128(buf)
                    fields.add(DexField(
                        name = extractFieldName(fieldPool.getOrElse(fieldIdx) { "?" }),
                        typeDescriptor = extractFieldType(fieldPool.getOrElse(fieldIdx) { "?" }),
                        accessFlags = accessFlags
                    ))
                }
                for (j in 0 until instanceFieldsSize) {
                    fieldIdx += readUleb128(buf)
                    val accessFlags = readUleb128(buf)
                    fields.add(DexField(
                        name = extractFieldName(fieldPool.getOrElse(fieldIdx) { "?" }),
                        typeDescriptor = extractFieldType(fieldPool.getOrElse(fieldIdx) { "?" }),
                        accessFlags = accessFlags
                    ))
                }

                // Read encoded methods — delta encoded across ALL methods (direct + virtual)
                var methodIdx = 0
                for (j in 0 until directMethodsSize) {
                    methodIdx += readUleb128(buf)
                    val accessFlags = readUleb128(buf)
                    val codeOff = readUleb128(buf)
                    val methodDef = methodPool.getOrElse(methodIdx) { "?" }
                    val bytecode = if (codeOff > 0) readCode(buf, data, codeOff) else null
                    methods.add(DexMethod(
                        name = extractMethodName(methodDef),
                        descriptor = extractMethodDesc(methodDef),
                        accessFlags = accessFlags,
                        bytecode = bytecode
                    ))
                }
                for (j in 0 until virtualMethodsSize) {
                    methodIdx += readUleb128(buf)
                    val accessFlags = readUleb128(buf)
                    val codeOff = readUleb128(buf)
                    val methodDef = methodPool.getOrElse(methodIdx) { "?" }
                    val bytecode = if (codeOff > 0) readCode(buf, data, codeOff) else null
                    methods.add(DexMethod(
                        name = extractMethodName(methodDef),
                        descriptor = extractMethodDesc(methodDef),
                        accessFlags = accessFlags,
                        bytecode = bytecode
                    ))
                }
            }

            classes.add(DexClass(className, superName, interfaces, accessFlags, sourceFile, methods, fields))
        }
        return classes
    }

    private fun readCode(buf: ByteBuffer, data: ByteArray, codeOff: Int): BytecodeInfo? {
        if (codeOff <= 0 || codeOff + 16 > data.size) return null

        val savedPos = buf.position()
        buf.position(codeOff)

        val registers = buf.short.toInt() and 0xFFFF
        val insSize = buf.short.toInt() and 0xFFFF
        val outsSize = buf.short.toInt() and 0xFFFF
        @Suppress("UNUSED_VARIABLE") val triesSize = buf.short.toInt() and 0xFFFF
        buf.int // debug_info_off
        val insnsSize = buf.int
        if (insnsSize <= 0 || codeOff + 16 + insnsSize * 2 > data.size) {
            buf.position(savedPos)
            return BytecodeInfo(registers, insSize, outsSize, emptyList(), emptyList())
        }

        val instructions = mutableListOf<DexInstruction>()
        var offset = 0
        var insnCount = 0
        val maxInsn = minOf(insnsSize, 10000)
        while (offset < insnsSize && insnCount < maxInsn) {
            val pos = codeOff + 16 + offset * 2
            if (pos + 1 >= data.size) break
            val opByte = data[pos].toInt() and 0xFF
            val opcode = Opcode.fromValue(opByte)
            val width = opcode?.formatWidth ?: 1
            if (offset + width > insnsSize) break
            val args = decodeOperands(opcode?.format ?: "10x", data, pos, width)
            instructions.add(DexInstruction(offset, opByte, opcode?.opcodeName ?: "op_${opByte.toString(16)}", args, null))
            offset += width
            insnCount++
        }

        buf.position(savedPos)
        return BytecodeInfo(registers, insSize, outsSize, instructions, emptyList())
    }

    private fun decodeOperands(format: String, data: ByteArray, pos: Int, width: Int): List<Int> {
        if (width <= 0) return emptyList()
        val unit0 = if (pos + 1 < data.size) (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8) else 0
        val unit1 = if (pos + 3 < data.size) (data[pos + 2].toInt() and 0xFF) or ((data[pos + 3].toInt() and 0xFF) shl 8) else 0
        val unit2 = if (pos + 5 < data.size) (data[pos + 4].toInt() and 0xFF) or ((data[pos + 5].toInt() and 0xFF) shl 8) else 0
        val unit3 = if (pos + 7 < data.size) (data[pos + 6].toInt() and 0xFF) or ((data[pos + 7].toInt() and 0xFF) shl 8) else 0
        val unit4 = if (pos + 9 < data.size) (data[pos + 8].toInt() and 0xFF) or ((data[pos + 9].toInt() and 0xFF) shl 8) else 0

        return when (format) {
            "10x" -> emptyList()
            "11x" -> listOf(unit0 shr 8 and 0xFF)
            "12x" -> listOf(unit0 shr 8 and 0xFF, unit0 shr 12 and 0xF)
            "21c", "21s", "21h" -> listOf(unit0 shr 8 and 0xFF, unit1)
            "22c", "22s", "22t" -> listOf(unit0 shr 8 and 0xF, unit0 shr 12 and 0xF, unit1)
            "22x" -> listOf(unit0 shr 8 and 0xFF, unit1)
            "22b" -> listOf(unit0 shr 8 and 0xFF, unit0 shr 12 and 0xFF, unit1.toByte().toInt())
            "23x" -> listOf(unit0 shr 8 and 0xFF, unit0 shr 12 and 0xF, unit1 shr 4 and 0xF)
            "10t" -> listOf((unit0 shr 8).toByte().toInt())
            "20t" -> listOf(unit0.toShort().toInt() shr 8)
            "21t" -> listOf(unit0 shr 8 and 0xFF, unit1.toShort().toInt())
            "30t" -> listOf((unit0 shr 8 and 0xFF) or (unit1 shl 8) or (unit1 shr 16 and 0xFF shl 24))
            "31i", "31c", "31t" -> listOf(unit0 shr 8 and 0xFF, unit1)
            "32x" -> listOf(unit0 shr 8 and 0xFF or (unit1 and 0xFF shl 8), unit2)
            "35c" -> {
                val A = unit0 shr 4 and 0xF
                val method = unit1 and 0xFFFF
                val C = unit2 shr 4 and 0xF
                if (A == 1) listOf(C, method)
                else {
                    val D = unit2 shr 8 and 0xF
                    val E = unit2 shr 12 and 0xF
                    listOf(C, D, E, method)
                }
            }
            "3rc" -> listOf(unit0 shr 8 and 0xFF, unit1 and 0xFFFF, unit2 and 0xFFFF)
            "51l" -> listOf(unit0 shr 8 and 0xFF, unit1, unit2, unit3, unit4)
            "11n" -> listOf(unit0 shr 8 and 0xFF, (unit0 shr 12 and 0xF).toByte().toInt())
            else -> emptyList()
        }
    }

    private fun readUleb128(buf: ByteBuffer): Int {
        var result = 0
        var shift = 0
        var i = 0
        while (i < 5 && buf.hasRemaining()) {
            val b = buf.get().toInt() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
            i++
        }
        return result
    }

    private fun readMutf8(buf: ByteBuffer): String {
        val sb = StringBuilder()
        val savedLimit = buf.limit()
        buf.limit(minOf(buf.capacity(), savedLimit))
        try {
            while (buf.hasRemaining()) {
                val b = buf.get().toInt() and 0xFF
                if (b == 0) break
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
                }
            }
        } catch (e: Exception) {
            // Truncated string
        }
        buf.limit(savedLimit)
        return sb.toString()
    }

    private fun extractMethodName(methodDef: String): String {
        val arrowIdx = methodDef.indexOf("->")
        if (arrowIdx < 0) return methodDef
        val afterArrow = methodDef.substring(arrowIdx + 2)
        val parenIdx = afterArrow.indexOf('(')
        return if (parenIdx > 0) afterArrow.substring(0, parenIdx) else afterArrow
    }

    private fun extractMethodDesc(methodDef: String): String {
        val arrowIdx = methodDef.indexOf("->")
        if (arrowIdx < 0) return methodDef
        val afterArrow = methodDef.substring(arrowIdx + 2)
        val parenIdx = afterArrow.indexOf('(')
        return if (parenIdx >= 0) afterArrow.substring(parenIdx) else afterArrow
    }

    private fun extractFieldName(fieldDef: String): String {
        val arrowIdx = fieldDef.indexOf("->")
        val nameStart = if (arrowIdx >= 0) arrowIdx + 2 else 0
        val colonIdx = fieldDef.indexOf(':', nameStart)
        return if (colonIdx > 0) fieldDef.substring(nameStart, colonIdx) else fieldDef.substring(nameStart)
    }

    private fun extractFieldType(fieldDef: String): String {
        val colonIdx = fieldDef.indexOf(':')
        return if (colonIdx > 0) fieldDef.substring(colonIdx + 1) else ""
    }

    data class DexHeader(
        val magic: ByteArray,
        val checksum: Int,
        val signature: ByteArray,
        val fileSize: Int,
        val headerSize: Int,
        val endianTag: Int,
        val linkSize: Int,
        val linkOff: Int,
        val mapOff: Int,
        val stringIdsSize: Int,
        val stringIdsOff: Int,
        val typeIdsSize: Int,
        val typeIdsOff: Int,
        val protoIdsSize: Int,
        val protoIdsOff: Int,
        val fieldIdsSize: Int,
        val fieldIdsOff: Int,
        val methodIdsSize: Int,
        val methodIdsOff: Int,
        val classDefsSize: Int,
        val classDefsOff: Int,
        val dataSize: Int,
        val dataOff: Int
    )
}
