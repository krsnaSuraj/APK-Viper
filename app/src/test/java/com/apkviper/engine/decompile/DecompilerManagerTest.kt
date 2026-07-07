package com.apkviper.engine.decompile

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.lang.reflect.Method

class DecompilerManagerTest {

    private val manager = DecompilerManager()

    @Test
    fun constructor_createsInstance() {
        assertNotNull(manager)
    }

    @Test
    fun decompile_withNonExistentFile_throwsException() {
        val missingFile = File("nonexistent_apk_file.apk")
        assertFalse("Precondition: file should not exist", missingFile.exists())
        runBlockingTest {
            try {
                manager.decompile(missingFile)
                fail("decompile() should throw when APK file does not exist")
            } catch (e: Exception) {
                assertNotNull("Exception should have a message", e.message)
            }
        }
    }

    @Test
    fun decompile_withEmptyFile_throwsException() {
        val emptyFile = File.createTempFile("empty", ".apk")
        emptyFile.writeText("")
        runBlockingTest {
            try {
                manager.decompile(emptyFile)
                fail("decompile() should throw on empty file")
            } catch (e: Exception) {
                assertNotNull("Exception should have a message", e.message)
            }
        }
        emptyFile.delete()
    }

    @Test
    fun parseMethodDescriptor_voidNoParams() {
        val result = invokeParseMethodDescriptor("()V")
        assertEquals("void", result.first)
        assertTrue("No params for ()V", result.second.isEmpty())
    }

    @Test
    fun parseMethodDescriptor_intParam() {
        val result = invokeParseMethodDescriptor("(I)V")
        assertEquals("void", result.first)
        assertEquals(1, result.second.size)
        assertEquals("int", result.second[0])
    }

    @Test
    fun parseMethodDescriptor_stringBooleanReturn() {
        val result = invokeParseMethodDescriptor("(Ljava/lang/String;)Z")
        assertEquals("boolean", result.first)
        assertEquals(1, result.second.size)
        assertEquals("String", result.second[0])
    }

    @Test
    fun parseMethodDescriptor_intIntListVoid() {
        val result = invokeParseMethodDescriptor("(IILjava/util/List;)V")
        assertEquals("void", result.first)
        assertEquals(3, result.second.size)
        assertEquals("int", result.second[0])
        assertEquals("int", result.second[1])
        assertEquals("List", result.second[2])
    }

    @Test
    fun parseMethodDescriptor_noReturnParams() {
        val result = invokeParseMethodDescriptor("()I")
        assertEquals("int", result.first)
        assertTrue(result.second.isEmpty())
    }

    @Test
    fun parseMethodDescriptor_longAndFloatReturnString() {
        val result = invokeParseMethodDescriptor("(JF)Ljava/lang/String;")
        assertEquals("String", result.first)
        assertEquals(2, result.second.size)
        assertEquals("long", result.second[0])
        assertEquals("float", result.second[1])
    }

    @Test
    fun simplifyType_int() {
        assertEquals("int", invokeSimplifyType("I"))
    }

    @Test
    fun simplifyType_boolean() {
        assertEquals("boolean", invokeSimplifyType("Z"))
    }

    @Test
    fun simplifyType_void() {
        assertEquals("void", invokeSimplifyType("V"))
    }

    @Test
    fun simplifyType_byte() {
        assertEquals("byte", invokeSimplifyType("B"))
    }

    @Test
    fun simplifyType_char() {
        assertEquals("char", invokeSimplifyType("C"))
    }

    @Test
    fun simplifyType_short() {
        assertEquals("short", invokeSimplifyType("S"))
    }

    @Test
    fun simplifyType_long() {
        assertEquals("long", invokeSimplifyType("J"))
    }

    @Test
    fun simplifyType_float() {
        assertEquals("float", invokeSimplifyType("F"))
    }

    @Test
    fun simplifyType_double() {
        assertEquals("double", invokeSimplifyType("D"))
    }

    @Test
    fun simplifyType_object() {
        assertEquals("String", invokeSimplifyType("Ljava/lang/String;"))
    }

    @Test
    fun simplifyType_nestedObject() {
        assertEquals("List", invokeSimplifyType("Ljava/util/List;"))
    }

    @Test
    fun simplifyType_intArray() {
        assertEquals("int[]", invokeSimplifyType("[I"))
    }

    @Test
    fun simplifyType_byteArrayArray() {
        assertEquals("byte[][]", invokeSimplifyType("[[B"))
    }

    @Test
    fun simplifyType_objectArray() {
        assertEquals("String[]", invokeSimplifyType("[Ljava/lang/String;"))
    }

    @Test
    fun simplifyType_unknown_returnsAsIs() {
        assertEquals("X", invokeSimplifyType("X"))
    }

    private fun invokeParseMethodDescriptor(desc: String): Pair<String, List<String>> {
        val method = DecompilerManager::class.java.getDeclaredMethod(
            "parseMethodDescriptor", String::class.java
        )
        method.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return method.invoke(manager, desc) as Pair<String, List<String>>
    }

    private fun invokeSimplifyType(descriptor: String): String {
        val method = DecompilerManager::class.java.getDeclaredMethod(
            "simplifyType", String::class.java
        )
        method.isAccessible = true
        return method.invoke(manager, descriptor) as String
    }

    private fun runBlockingTest(block: suspend kotlinx.coroutines.CoroutineScope.() -> Unit) {
        kotlinx.coroutines.runBlocking { block() }
    }
}
