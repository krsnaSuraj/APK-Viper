package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class CryptoMinerDetector {

    private val miningSignatures = listOf(
        "stratum+tcp" to "Stratum mining protocol detected",
        "stratum+ssl" to "Stratum SSL mining protocol",
        "mining.subscribe" to "Mining subscription command",
        "mining.authorize" to "Mining authorization command",
        "mining.notify" to "Mining notification",
        "cryptonight" to "CryptoNight algorithm (Monero miner)",
        "cryptonight-lite" to "CryptoNight-Lite algorithm",
        "cn/r" to "CryptoNight variant R",
        "rx/0" to "RandomX algorithm",
        "argon2" to "Argon2 memory-hard algorithm",
        "xmrig" to "XMRig miner signature",
        "coinhive" to "Coinhive web miner",
        "coin-hive" to "Coin-Hive miner",
        "cryptoloot" to "CryptoLoot miner",
        "authedmine" to "AuthedMine miner",
        "webminer" to "Web miner detected"
    )

    private val miningPoolDomains = listOf(
        "pool.minexmr.com",
        "xmrpool.eu",
        "monerohash.com",
        "moneropool.com",
        "pool.supportxmr.com",
        "xmr.crypto-pool.fr",
        "mine.xmrpool.net"
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val allCode = decompiled.allSourceText
            ?: (decompiled.javaSource.values + decompiled.smaliSource.values).joinToString("\n")
        return analyzeText(allCode)
    }

    fun analyzeIndexed(keywordMatches: Set<String>): List<Finding> {
        val findings = mutableListOf<Finding>()
        miningSignatures.forEach { (sig, desc) ->
            if (sig.lowercase() in keywordMatches) findings.add(Finding(
                FindingCategory.CRYPTO_MINER, Severity.CRITICAL, "Crypto Miner Detected", desc))
        }
        miningPoolDomains.forEach { domain ->
            if (domain.lowercase() in keywordMatches) findings.add(Finding(
                FindingCategory.CRYPTO_MINER, Severity.CRITICAL, "Mining Pool Connection", "Connection to mining pool: $domain"))
        }
        if ("worker" in keywordMatches && ("coin-hive" in keywordMatches || "cryptonight" in keywordMatches ||
            "webassembly" in keywordMatches || "wasm" in keywordMatches))
            findings.add(Finding(FindingCategory.CRYPTO_MINER, Severity.HIGH,
                "Crypto Mining Worker Detected", "Web Worker with cryptomining indicators"))
        val wm = listOf("webassembly.module","webassembly.instance","instantiatestreaming","compilestreaming","webassembly.memory").count{it in keywordMatches}
        val mc = "crypto" in keywordMatches || "hash" in keywordMatches || "mine" in keywordMatches
        if (wm >= 2 && mc) findings.add(Finding(FindingCategory.CRYPTO_MINER, Severity.HIGH, "WASM Crypto Module Detected", "WebAssembly with crypto/hash context"))
        val cp = listOf("availableprocessors","cpucount","cpu_count","getcpucount").count{it in keywordMatches}
        if (cp >= 2 && mc) findings.add(Finding(FindingCategory.CRYPTO_MINER, Severity.MEDIUM, "CPU Probing with Crypto Context", "CPU enumeration with crypto references"))
        return findings
    }

    private fun analyzeText(allCode: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        miningSignatures.forEach { (sig, desc) ->
            if (allCode.contains(sig, true)) findings.add(Finding(
                FindingCategory.CRYPTO_MINER, Severity.CRITICAL, "Crypto Miner Detected", desc))
        }
        miningPoolDomains.forEach { domain ->
            if (allCode.contains(domain, true)) findings.add(Finding(
                FindingCategory.CRYPTO_MINER, Severity.CRITICAL, "Mining Pool Connection", "Connection to mining pool: $domain"))
        }
        if ((allCode.contains("Worker", true) && allCode.contains("onmessage", true)) &&
            (allCode.contains("coin-hive", true) || allCode.contains("cryptonight", true) ||
             allCode.contains("miner", true) || allCode.contains("WebAssembly", true) || allCode.contains("wasm", true)))
            findings.add(Finding(FindingCategory.CRYPTO_MINER, Severity.HIGH, "Crypto Mining Worker Detected", "Web Worker with cryptomining indicators"))
        val wm = listOf("WebAssembly.Module","WebAssembly.Instance","instantiateStreaming","compileStreaming","WebAssembly.Memory").count{allCode.contains(it,true)}
        val mc = allCode.contains("crypto", true) || allCode.contains("hash", true) || allCode.contains("mine", true)
        if (wm >= 2 && mc) findings.add(Finding(FindingCategory.CRYPTO_MINER, Severity.HIGH, "WASM Crypto Module Detected", "WebAssembly with crypto/hash context"))
        val cp = listOf("Runtime.getRuntime().availableProcessors","availableProcessors","cpuCount","CPU_COUNT","getCpuCount").count{allCode.contains(it,true)}
        if (cp >= 2 && mc) findings.add(Finding(FindingCategory.CRYPTO_MINER, Severity.MEDIUM, "CPU Probing with Crypto Context", "CPU enumeration with crypto references"))
        return findings
    }
}
