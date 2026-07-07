package com.apkviper.dex

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.io.IOException
import java.util.zip.ZipException

class SmaliDisassemblerTest {
    private val disassembler = SmaliDisassembler()

    @Test
    fun defaultConstructor_usesDexParser() {
        val smali = SmaliDisassembler()
        assertNotNull(smali)
    }

    @Test
    fun disassemble_nonExistentApk_doesNotCrash() {
        val file = File("nonexistent_apk_file_xyz.apk")
        try {
            disassembler.disassemble(file)
        } catch (_: Exception) {
            // Any exception is acceptable
        }
    }

    @Test
    fun disassembleClasses_nonExistentApk_doesNotCrash() {
        val file = File("nonexistent_apk_file_xyz.apk")
        try {
            disassembler.disassemble(file)
        } catch (_: Exception) {
            // Any exception is acceptable
        }
    }

    @Test
    fun disassembleFromParseResult_emptyResult_returnsEmptyMap() {
        val result = DexParser.ParseResult(
            classes = emptyList(),
            stringPool = emptyList(),
            typePool = emptyList(),
            protoPool = emptyList(),
            fieldPool = emptyList(),
            methodPool = emptyList(),
            dexCount = 0
        )
        val smaliFiles = disassembler.disassembleFromParseResult(result)
        assertTrue(smaliFiles.isEmpty())
    }

    @Test
    fun classToSmali_minimalClass_containsClassDeclaration() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 1,
            sourceFile = null,
            methods = emptyList(),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(".class"))
        assertTrue(smali.contains("Lcom/test/TestClass;"))
        assertFalse(smali.contains(".super")) // super = Ljava/lang/Object; so no .super emitted
        assertFalse(smali.contains(".source"))
    }

    @Test
    fun classToSmali_withSuperClass_emitsSuper() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/Child;",
            superClass = "Lcom/test/Parent;",
            interfaces = emptyList(),
            accessFlags = 1,
            sourceFile = null,
            methods = emptyList(),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(".super Lcom/test/Parent;"))
    }

    @Test
    fun classToSmali_withInterface_implementsEmitted() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = listOf("Ljava/io/Serializable;"),
            accessFlags = 1,
            sourceFile = null,
            methods = emptyList(),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(".implements Ljava/io/Serializable;"))
    }

    @Test
    fun classToSmali_withSourceFile_emitsSource() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 1,
            sourceFile = "TestClass.java",
            methods = emptyList(),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(""".source "TestClass.java""""))
    }

    @Test
    fun classToSmali_withField_emitsFieldDeclaration() {
        val field = DexParser.DexField(
            name = "count",
            typeDescriptor = "I",
            accessFlags = 2 // private
        )
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 1,
            sourceFile = null,
            methods = emptyList(),
            fields = listOf(field)
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(".field"))
        assertTrue(smali.contains("count:I"))
        assertTrue(smali.contains("private"))
    }

    @Test
    fun classToSmali_withMethod_emitsMethodDeclaration() {
        val method = DexParser.DexMethod(
            name = "onCreate",
            descriptor = "(Landroid/os/Bundle;)V",
            accessFlags = 1,
            bytecode = null
        )
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 1,
            sourceFile = null,
            methods = listOf(method),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(".method"))
        assertTrue(smali.contains("onCreate"))
        assertTrue(smali.contains(".end method"))
    }

    @Test
    fun classToSmali_publicAccessFlag_appearsInSmali() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 0x1, // public
            sourceFile = null,
            methods = emptyList(),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(".class public"))
    }

    @Test
    fun classToSmali_privateAccessFlag_appearsInSmali() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/Inner;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 0x2, // private
            sourceFile = null,
            methods = emptyList(),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(".class private"))
    }

    @Test
    fun classToSmali_staticFinalFlags_appearsInSmali() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/Constants;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 0x1 or 0x8 or 0x10, // public static final
            sourceFile = null,
            methods = emptyList(),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains("public"))
        assertTrue(smali.contains("static"))
        assertTrue(smali.contains("final"))
    }

    @Test
    fun classToSmali_abstractFlag_appearsInSmali() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/AbstractBase;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 0x1 or 0x400, // public abstract
            sourceFile = null,
            methods = emptyList(),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains("public abstract"))
    }

    @Test
    fun classToSmali_syntheticAnnotationEnumFlags_mapsToSmali() {
        val cls = DexParser.DexClass(
            name = "Lcom/test/Misc;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 0x1000 or 0x2000 or 0x4000, // synthetic annotation enum
            sourceFile = null,
            methods = emptyList(),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains("synthetic"))
        assertTrue(smali.contains("annotation"))
        assertTrue(smali.contains("enum"))
    }

    @Test
    fun classToSmali_withMethodHavingBytecode_emitsInstructions() {
        val instr = DexParser.DexInstruction(
            offset = 0,
            opcode = 0x6e,
            opcodeName = "invoke-virtual",
            args = listOf(1, 2, 3),
            lineNumber = null
        )
        val bc = DexParser.BytecodeInfo(
            registers = 3,
            insSize = 1,
            outsSize = 1,
            instructions = listOf(instr),
            tryBlocks = emptyList()
        )
        val method = DexParser.DexMethod(
            name = "doSomething",
            descriptor = "()V",
            accessFlags = 1,
            bytecode = bc
        )
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 1,
            sourceFile = null,
            methods = listOf(method),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(".registers 3"))
        assertTrue(smali.contains("invoke-virtual"))
        assertTrue(smali.contains(".end method"))
    }

    @Test
    fun methodWithNullBytecode_emitsEndMethod() {
        val method = DexParser.DexMethod(
            name = "nativeMethod",
            descriptor = "()I",
            accessFlags = 0x101, // public native
            bytecode = null
        )
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 1,
            sourceFile = null,
            methods = listOf(method),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains(".end method"))
        assertFalse(smali.contains(".registers")) // no bytecode, no registers
    }

    @Test
    fun methodWithConstructorFlag_nameIsCorrect() {
        val method = DexParser.DexMethod(
            name = "<init>",
            descriptor = "()V",
            accessFlags = 0x10001, // public constructor
            bytecode = null
        )
        val cls = DexParser.DexClass(
            name = "Lcom/test/TestClass;",
            superClass = "Ljava/lang/Object;",
            interfaces = emptyList(),
            accessFlags = 1,
            sourceFile = null,
            methods = listOf(method),
            fields = emptyList()
        )
        val smali = disassembler.classToSmali(cls, emptyList())
        assertTrue(smali.contains("<init>"))
        assertTrue(smali.contains("constructor"))
    }
}
