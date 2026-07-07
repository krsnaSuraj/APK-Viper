package com.apkviper.engine.decompile

import com.apkviper.dex.AxmlDecoder
import com.apkviper.dex.DexParser
import com.apkviper.dex.SmaliDisassembler
import com.apkviper.model.DecompileResult
import java.io.File
import java.util.zip.ZipFile
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class DecompilerManager {

    companion object {
        private const val MAX_TOTAL_SOURCE_BYTES = 80L * 1024 * 1024
        private const val CONCURRENT_WORKERS = 4
    }

    private val dexParser = DexParser()
    private val axmlDecoder = AxmlDecoder()
    private val smaliDisassembler = SmaliDisassembler(dexParser)
    private val workerSemaphore = Semaphore(CONCURRENT_WORKERS)

    suspend fun decompile(
        apkFile: File,
        onProgress: (String) -> Unit = {},
        isCancelled: () -> Boolean = { false },
        maxClasses: Int = Int.MAX_VALUE
    ): DecompileResult {
        val startTime = System.currentTimeMillis()

        onProgress("Parsing DEX header...")
        var parseResult = dexParser.parseApk(apkFile, isCancelled)
        val totalClasses = parseResult.classes.size.coerceAtMost(maxClasses)
        onProgress("Parsed $totalClasses classes")

        // ── Step 1: Generate smali (gated: max 4 parallel workers, 80MB ceiling) ──
        var smaliSource: MutableMap<String, String> = mutableMapOf()
        onProgress("Generating smali (0/$totalClasses)...")
        try {
            smaliSource = generateSmaliGated(parseResult, parseResult.classes.size) { done, total ->
                onProgress("Generating smali ($done/$total)...")
            }
        } catch (e: OutOfMemoryError) {
            System.gc()
            android.util.Log.w("Decompiler", "Smali OOM, returning partial")
        }

        // Drop bytecodes from ParseResult to free 50-200MB before Java generation.
        for (cls in parseResult.classes) {
            for (m in cls.methods) { m.bytecode = null }
        }
        System.gc()

        onProgress("Decoding AndroidManifest...")
        val manifest = decodeManifest(apkFile)

        // ── Step 2: Generate Java stubs ──
        var javaSource: MutableMap<String, String> = mutableMapOf()
        onProgress("Decompiling to Java (0/$totalClasses)...")
        try {
            javaSource = decompileToJavaGated(parseResult, parseResult.classes.size) { done, total ->
                onProgress("Decompiling to Java ($done/$total)...")
            }
        } catch (e: OutOfMemoryError) {
            System.gc()
            android.util.Log.w("Decompiler", "Java OOM, returning partial")
        }

        // ── Step 3: Build text from java only (smali is for analytical passes, dropped above)
        //     Java stubs contain class names, method signatures, field types — sufficient for text-based keyword matching
        val sb = StringBuilder(javaSource.size * 4096)
        for (s in javaSource.values) { sb.append(s).append('\n') }

        onProgress("Extracting binaries...")
        val (resources, dexFiles, nativeLibs) = extractBinaries(apkFile)

        val duration = System.currentTimeMillis() - startTime
        onProgress("Decompile complete: ${javaSource.size} classes, ${javaSource.size} smali")

        System.gc()
        return DecompileResult(
            javaSource = javaSource,
            smaliSource = smaliSource,
            manifest = manifest,
            resources = resources,
            dexFiles = dexFiles,
            nativeLibs = nativeLibs,
            decompileTimeMs = duration,
            allSourceText = sb.toString()
        )
    }

    private suspend fun generateSmaliGated(
        parseResult: DexParser.ParseResult,
        total: Int,
        onProgress: (done: Int, total: Int) -> Unit
    ): MutableMap<String, String> {
        if (total == 0) return mutableMapOf()
        val chunkSize = maxOf(1, total / (CONCURRENT_WORKERS * 2))
        val chunks = parseResult.classes.chunked(chunkSize)
        // Shared byte ceiling — workers check this first, stop producing when exceeded
        val bytesAllocated = AtomicLong(0L)
        val progressCounter = AtomicInteger(0)
        val result = mutableMapOf<String, String>()

        try {
            val chunkResults = kotlinx.coroutines.withTimeout(120_000L) {
                coroutineScope {
                    chunks.map { chunk ->
                        async(Dispatchers.Default) {
                            workerSemaphore.withPermit {
                                val local = mutableMapOf<String, String>()
                                for (cls in chunk) {
                                    if (!isActive) break
                                    if (bytesAllocated.get() > MAX_TOTAL_SOURCE_BYTES / 2) break
                                    try {
                                        val smaliCode = smaliDisassembler.classToSmali(cls, parseResult.stringPool)
                                        val fileName = cls.name.replace('/', '_').replace(';', '_').removePrefix("L")
                                        local["$fileName.smali"] = smaliCode
                                        bytesAllocated.addAndGet(smaliCode.length.toLong())
                                    } catch (_: Exception) {}
                                }
                                onProgress(progressCounter.addAndGet(local.size), total.coerceAtMost(total))
                                local
                            }
                        }
                    }.awaitAll()
                }
            }
            for (chunkMap in chunkResults) {
                result.putAll(chunkMap)
            }
        } catch (_: TimeoutCancellationException) {
            android.util.Log.w("Decompiler", "Smali timeout after 120s, returning partial")
            System.gc()
        } catch (_: OutOfMemoryError) {
            System.gc()
        }

        onProgress(result.size.coerceAtMost(total), total)
        return result
    }

    private suspend fun decompileToJavaGated(
        parseResult: DexParser.ParseResult,
        total: Int,
        onProgress: (done: Int, total: Int) -> Unit
    ): MutableMap<String, String> {
        if (total == 0) return mutableMapOf()
        val chunkSize = maxOf(1, total / (CONCURRENT_WORKERS * 2))
        val chunks = parseResult.classes.chunked(chunkSize)
        val bytesAllocated = AtomicLong(0L)
        val progressCounter = AtomicInteger(0)
        val result = mutableMapOf<String, String>()

        try {
            val chunkResults = kotlinx.coroutines.withTimeout(120_000L) {
                coroutineScope {
                    chunks.map { chunk ->
                        async(Dispatchers.Default) {
                            workerSemaphore.withPermit {
                                val local = mutableMapOf<String, String>()
                                for (cls in chunk) {
                                    if (!isActive) break
                                    if (bytesAllocated.get() > MAX_TOTAL_SOURCE_BYTES / 2) break
                                    try {
                                        val sb = StringBuilder()
                                        val simpleName = cls.name.substringAfterLast("/").removeSuffix(";")
                                        val packageName = cls.name
                                            .substringBeforeLast("/")
                                            .removePrefix("L")
                                            .replace('/', '.')
                                        if (packageName.isNotEmpty()) sb.append("package $packageName;\n\n")
                                        sb.append("public class $simpleName")
                                        if (cls.superClass != "Ljava/lang/Object;") {
                                            val superSimple = cls.superClass.substringAfterLast("/").removeSuffix(";")
                                            sb.append(" extends $superSimple")
                                        }
                                        sb.append(" {\n")
                                        for (field in cls.fields) {
                                            val typeName = simplifyType(field.typeDescriptor)
                                            sb.append("    $typeName ${field.name};\n")
                                        }
                                        for (method in cls.methods) {
                                            val (returnType, params) = parseMethodDescriptor(method.descriptor)
                                            sb.append("    $returnType ${method.name}(${params.joinToString(", ")});\n")
                                        }
                                        sb.append("}")
                                        local[simpleName + ".java"] = sb.toString()
                                        bytesAllocated.addAndGet(sb.length.toLong())
                                    } catch (_: Exception) {}
                                }
                                onProgress(progressCounter.addAndGet(local.size), total.coerceAtMost(total))
                                local
                            }
                        }
                    }.awaitAll()
                }
            }
            for (chunkMap in chunkResults) {
                result.putAll(chunkMap)
            }
        } catch (_: TimeoutCancellationException) {
            android.util.Log.w("Decompiler", "Java timeout after 120s, returning partial")
            System.gc()
        } catch (_: OutOfMemoryError) {
            System.gc()
        }

        onProgress(result.size.coerceAtMost(total), total)
        return result
    }

    private fun parseMethodDescriptor(desc: String): Pair<String, List<String>> {
        val endParams = desc.indexOf(')')
        if (endParams <= 1) return simplifyType(desc.substring(endParams + 1)) to emptyList()
        val params = mutableListOf<String>()
        var i = 1
        while (i < endParams) {
            val start = i
            if (desc[i] == 'L') { while (desc[i] != ';') i++; i++ }
            else if (desc[i] == '[') { while (desc[i] == '[') i++; if (desc[i] == 'L') { while (desc[i] != ';') i++ }; i++ }
            else i++
            params.add(simplifyType(desc.substring(start, i)))
        }
        return simplifyType(desc.substring(endParams + 1)) to params
    }

    private fun simplifyType(descriptor: String): String = when {
        descriptor == "V" -> "void"
        descriptor == "Z" -> "boolean"
        descriptor == "B" -> "byte"
        descriptor == "C" -> "char"
        descriptor == "S" -> "short"
        descriptor == "I" -> "int"
        descriptor == "J" -> "long"
        descriptor == "F" -> "float"
        descriptor == "D" -> "double"
        descriptor.startsWith("L") -> descriptor.substringAfterLast("/").removeSuffix(";")
        descriptor.startsWith("[") -> simplifyType(descriptor.drop(1)) + "[]"
        else -> descriptor
    }

    private fun decodeManifest(apkFile: File): String {
        return try {
            ZipFile(apkFile).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml") ?: return "<manifest>AndroidManifest.xml not found</manifest>"
                val bytes = zip.getInputStream(entry).readBytes()
                axmlDecoder.decode(bytes)
            }
        } catch (e: Exception) {
            android.util.Log.w("Decompiler", "Manifest decode failed", e)
            "<manifest>Decode error: ${e.message}</manifest>"
        }
    }

    private fun extractBinaries(apkFile: File): Triple<Map<String, ByteArray>, List<String>, List<String>> {
        val resources = mutableMapOf<String, ByteArray>()
        val dexFiles = mutableListOf<String>()
        val nativeLibs = mutableListOf<String>()

        try {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                val maxEntryErrors = 10
                var errors = 0

                while (entries.hasMoreElements()) {
                    try {
                        val entry = entries.nextElement()
                        val name = entry.name

                        when {
                            name == "resources.arsc" -> {
                                if (entry.size < 10 * 1024 * 1024) {
                                    resources[name] = zip.getInputStream(entry).readBytes()
                                }
                            }
                            name.startsWith("res/") && name.length < 80 -> {
                                if (entry.size < 5 * 1024 * 1024) {
                                    resources[name] = zip.getInputStream(entry).readBytes()
                                }
                            }
                            name.endsWith(".dex", ignoreCase = true) -> dexFiles.add(name)
                            name.startsWith("lib/") && name.endsWith(".so") -> nativeLibs.add(name)
                        }
                    } catch (e: Exception) {
                        errors++
                        if (errors >= maxEntryErrors) break
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.w("Decompiler", "ZIP read failed", e)
        }

        return Triple(resources, dexFiles, nativeLibs)
    }
}
