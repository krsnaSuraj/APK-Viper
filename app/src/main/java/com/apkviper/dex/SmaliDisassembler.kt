package com.apkviper.dex

import java.io.File

/**
 * Disassembles DEX bytecode into smali-like text format.
 * Uses DexParser to read the DEX structure and generates
 * human-readable smali for pattern matching and analysis.
 */
class SmaliDisassembler(private val dexParser: DexParser = DexParser()) {

    fun disassemble(apkFile: File): Map<String, String> {
        val result = dexParser.parseApk(apkFile)
        return disassembleFromParseResult(result)
    }

    fun disassembleFromParseResult(result: DexParser.ParseResult): Map<String, String> {
        val smaliFiles = mutableMapOf<String, String>()

        result.classes.forEach { cls ->
            val smaliCode = classToSmali(cls, result.stringPool)
            val fileName = cls.name.replace('/', '_').replace(';', '_').removePrefix("L")
            smaliFiles["$fileName.smali"] = smaliCode
        }

        return smaliFiles
    }

    fun classToSmali(cls: DexParser.DexClass, @Suppress("UNUSED_PARAMETER") strings: List<String>): String {
        val sb = StringBuilder()

        // Class declaration
        sb.append(".class ")
        sb.append(accessFlagsToSmali(cls.accessFlags))
        sb.append(" ${cls.name}\n")

        if (cls.superClass != "Ljava/lang/Object;") {
            sb.append(".super ${cls.superClass}\n")
        }

        cls.interfaces.forEach { iface ->
            sb.append(".implements $iface\n")
        }

        cls.sourceFile?.let { sb.append(".source \"$it\"\n") }

        sb.append("\n")

        // Fields
        cls.fields.forEach { field ->
            sb.append(".field ")
            sb.append(accessFlagsToSmali(field.accessFlags))
            sb.append(" ${field.name}:${field.typeDescriptor}\n")
        }

        if (cls.fields.isNotEmpty()) sb.append("\n")

        // Methods
        cls.methods.forEach { method ->
            sb.append(".method ")
            sb.append(accessFlagsToSmali(method.accessFlags))
            sb.append(" ${method.name}${method.descriptor}\n")

            method.bytecode?.let { bc ->
                sb.append("    .registers ${bc.registers}\n")
                sb.append("    .locals ${bc.registers - bc.insSize}\n")

                bc.tryBlocks.forEach { tb ->
                    sb.append("    :try_start_${tb.startAddr.toString(16)}\n")
                    sb.append("    .catch ${tb.handlerOff.toString(16)}\n")
                }

                sb.append("\n")
                bc.instructions.forEach { instr ->
                    sb.append("    ${instr.opcodeName}")
                    if (instr.opcodeName.length < 16) sb.append(" ".repeat(16 - instr.opcodeName.length))
                    if (instr.args.isNotEmpty()) {
                        sb.append(instr.args.joinToString(", "))
                        sb.append(" ")
                    }
                    sb.append("# 0x${instr.offset.toString(16)}\n")
                }

                bc.tryBlocks.forEach { tb ->
                    sb.append("    :try_end_${(tb.startAddr + tb.insnCount).toString(16)}\n")
                }

                sb.append(".end method\n")
            } ?: run {
                sb.append(".end method\n")
            }

            sb.append("\n")
        }

        return sb.toString()
    }

    private fun accessFlagsToSmali(flags: Int): String {
        val parts = mutableListOf<String>()

        if (flags and 0x1 != 0) parts.add("public")
        if (flags and 0x2 != 0) parts.add("private")
        if (flags and 0x4 != 0) parts.add("protected")
        if (flags and 0x8 != 0) parts.add("static")
        if (flags and 0x10 != 0) parts.add("final")
        if (flags and 0x20 != 0) parts.add("synchronized")
        if (flags and 0x200 != 0) parts.add("interface")
        if (flags and 0x400 != 0) parts.add("abstract")
        if (flags and 0x1000 != 0) parts.add("synthetic")
        if (flags and 0x2000 != 0) parts.add("annotation")
        if (flags and 0x4000 != 0) parts.add("enum")
        if (flags and 0x10000 != 0) parts.add("constructor")
        if (flags and 0x20000 != 0) parts.add("declared-synchronized")

        return parts.joinToString(" ")
    }
}
