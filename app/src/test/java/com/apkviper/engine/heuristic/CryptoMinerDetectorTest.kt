package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class CryptoMinerDetectorTest {
    private val detector = CryptoMinerDetector()

    @Test
    fun cleanCode_noMinerFindings() {
        val result = DecompileResult(
            javaSource = mapOf("Main.java" to "class Main { void run() { } }"),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).isEmpty())
    }

    @Test
    fun stratumTcp_detected() {
        val code = "String pool = \"stratum+tcp://pool.xmr.com\";"
        val result = DecompileResult(
            javaSource = mapOf("Miner.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Crypto Miner Detected" })
        assertEquals(Severity.CRITICAL, findings.first { it.title == "Crypto Miner Detected" }.severity)
    }

    @Test
    fun cryptonight_detected() {
        val code = "algorithm = \"cryptonight\";"
        val result = DecompileResult(
            javaSource = mapOf("Miner.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).any { it.title == "Crypto Miner Detected" })
    }

    @Test
    fun miningPoolDomain_detected() {
        val code = "String url = \"pool.minexmr.com:4444\";"
        val result = DecompileResult(
            javaSource = mapOf("Config.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Mining Pool Connection" })
    }

    @Test
    fun webWorker_withCoinHive_triggers() {
        val code = """
            Worker worker = new Worker();
            worker.onmessage = function(e) { };
            coin-hive miner
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Web.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Crypto Mining Worker Detected" })
        assertEquals(Severity.HIGH, findings.first { it.title == "Crypto Mining Worker Detected" }.severity)
    }

    @Test
    fun webWorker_withoutMiningContext_noTrigger() {
        val code = """
            Worker worker = new Worker();
            worker.onmessage = function(e) { console.log(e); };
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Web.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title == "Crypto Mining Worker Detected" })
    }

    @Test
    fun wasm_withMiningContext_triggers() {
        val code = """
            WebAssembly.Module module;
            WebAssembly.Instance inst;
            crypto hash
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Wasm.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "WASM Crypto Module Detected" })
        assertEquals(Severity.HIGH, findings.first { it.title == "WASM Crypto Module Detected" }.severity)
    }

    @Test
    fun wasm_withoutMiningContext_noTrigger() {
        val code = """
            WebAssembly.Module module;
            WebAssembly.Instance inst;
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Wasm.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title == "WASM Crypto Module Detected" })
    }

    @Test
    fun cpuProbing_withMiningContext_triggers() {
        val code = """
            Runtime.getRuntime().availableProcessors();
            /proc/cpuinfo read
            crypto context
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Probe.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "CPU Probing with Crypto Context" })
        assertEquals(Severity.MEDIUM, findings.first { it.title == "CPU Probing with Crypto Context" }.severity)
    }

    @Test
    fun cpuProbing_withoutMiningContext_noTrigger() {
        val code = """
            Runtime.getRuntime().availableProcessors();
            /proc/cpuinfo read
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Probe.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title == "CPU Probing with Crypto Context" })
    }

    @Test
    fun stratumCaseInsensitive() {
        val code = "Stratum+tcp connection"
        val result = DecompileResult(
            javaSource = mapOf("Test.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).any { it.title == "Crypto Miner Detected" })
    }

    @Test
    fun multipleMiningSignatures_multipleFindings() {
        val code = """
            stratum+tcp connection
            cryptonight algorithm
            xmrig config
            coin-hive script
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Miner.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        val minerFindings = findings.filter { it.title == "Crypto Miner Detected" }
        assertTrue(minerFindings.size >= 3)
    }

    @Test
    fun smaliSource_miningDetection() {
        val smali = "stratum+tcp pool address"
        val result = DecompileResult(
            javaSource = emptyMap(),
            smaliSource = mapOf("Miner.smali" to smali),
            manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).any { it.title == "Crypto Miner Detected" })
    }
}
