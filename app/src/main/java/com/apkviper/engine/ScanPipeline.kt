package com.apkviper.engine

import android.content.Context
import android.net.Uri
import com.apkviper.engine.advanced.*
import com.apkviper.engine.decompile.DecompilerManager
import com.apkviper.engine.dex.DexOpcodeAnalyzer
import com.apkviper.engine.heuristic.*
import com.apkviper.engine.classification.ThreatClassifier
import com.apkviper.engine.classification.ClassificationResult
import com.apkviper.engine.malware.KnownMalwareDB
import com.apkviper.engine.native.NativeAnalyzer
import com.apkviper.engine.network.NetworkAnalyzer
import com.apkviper.engine.scoring.*
import com.apkviper.engine.static.*
import com.apkviper.engine.supplychain.SDKAnalyzer
import com.apkviper.engine.taint.TaintAnalyzer
import com.apkviper.engine.update.AutoUpdateEngine
import com.apkviper.dex.AxmlDecoder
import com.apkviper.engine.xapk.XapkExtractor
import com.apkviper.engine.yara.YaraEngine
import com.apkviper.model.*
import com.apkviper.ui.terminal.LineType
import com.apkviper.util.HashUtils
import kotlinx.coroutines.*
import java.io.File
import java.util.zip.ZipFile

class ScanPipeline(private val context: Context) {

    private val job = SupervisorJob()
    private val mainScope = CoroutineScope(Dispatchers.IO + job)
    private val decompiler = DecompilerManager()
    private val manifestAnalyzer = ManifestAnalyzer()
    private val permissionAnalyzer = PermissionAnalyzer()
    private val codeAnalyzer = CodeAnalyzer()
    private val stringExtractor = StringExtractor()
    private val certificateAnalyzer = CertificateAnalyzer()
    private val packerDetector = PackerDetector()
    private val entropyAnalyzer = EntropyAnalyzer()
    private val obfuscationDetector = ObfuscationDetector()
    private val malwareDetector = MalwarePatternDetector()
    private val cryptoMinerDetector = CryptoMinerDetector()
    private val nativeAnalyzer = NativeAnalyzer()
    private val networkAnalyzer = NetworkAnalyzer()
    private val threatScorer = ThreatScorer()
    private val xapkExtractor = XapkExtractor()
    private val yaraEngine = YaraEngine()
    private val dexOpcodeAnalyzer = DexOpcodeAnalyzer()
    private val taintAnalyzer = TaintAnalyzer()
    private val sdkAnalyzer = SDKAnalyzer()
    private val behavioralDetector = BehavioralDetector()
    private val apiCallGraphAnalyzer = ApiCallGraphAnalyzer()
    private val apkIntegrityVerifier = ApkIntegrityVerifier()
    private val cfgAnalyzer = CfgStructuralAnalyzer()
    private val entropyPackerDetector = EntropyPackerDetector()
    private val frameworkIntegrityChecker = FrameworkIntegrityChecker()
    private val nativeCallGraphCorrelator = NativeCallGraphCorrelator()
    private val antiEvasionDetector = AntiEvasionDetector()
    private val opcodeNgramAnalyzer = OpcodeNgramAnalyzer()
    private val intentGraphAnalyzer = IntentRelationGraphAnalyzer()
    private val nativeBytecodeScanner = NativeBytecodeScanner()
    private val ruleWatcher = LocalRuleWatcher(context)
    private val permissionRiskMatrix = PermissionRiskMatrix()
    private val nativeLibraryDiffer = NativeLibraryDiffer()
    private val secretLeakScanner = SecretLeakScanner()
    private val backgroundResourceMonitor = BackgroundResourceMonitor()
    private val nativeBehaviorAnalyzer = NativeBehaviorAnalyzer()
    private val stringDeobfuscator = StringDeobfuscator()
    private val phishingOverlayAnalyzer = PhishingOverlayAnalyzer()
    private val networkBehaviorProfiler = NetworkBehaviorProfiler()
    private val behaviorTimelineAnalyzer = BehaviorTimelineAnalyzer()
    private val autoUpdateEngine = AutoUpdateEngine(context)
    private val mlClassifier = TinyMLClassifier()
    private val threatClassifier = ThreatClassifier()
    private val privacyScorer = PrivacyScorer()
    private val modApkDetector = ModApkDetector()
    private val shizukuDetector = ShizukuDetector()
    private val virtualAppDetector = VirtualAppDetector()
    private val accessibilityChainAnalyzer = AccessibilityChainAnalyzer()

    init {
        loadYaraRules()
        ruleWatcher.start()
        // Trigger auto-update in background (non-blocking)
        mainScope.launch {
            try {
                val result = autoUpdateEngine.checkAndUpdate()
                val store = com.apkviper.data.SettingsDataStore(context)
                store.updateSignatureStatus(
                    result.yaraRuleCount.toLong(),
                    result.hashCount.toLong(),
                    com.apkviper.engine.advanced.ThreatIntelDB.getIpCount().toLong(),
                    com.apkviper.engine.advanced.ThreatIntelDB.getDomainCount().toLong()
                )
                if (result.yaraRulesUpdated || result.yaraRuleCount > 0) {
                    loadYaraRules()
                }
            } catch (_: Exception) {
                android.util.Log.w("ScanPipeline", "Auto-update failed")
            }
        }
    }

    @Volatile var parseCancelled = false

    fun cancel() { parseCancelled = true }

    companion object {
        const val TOTAL_PHASE_COUNT = 9
        private val PERMISSION_REGEX = Regex("""android\.permission\.[A-Z_]+""")
        private val EXPORTED_SERVICE_REGEX = Regex("""<service[^>]*exported\s*=\s*"true"""", RegexOption.IGNORE_CASE)
        private val DANGEROUS_PERM_REGEX = Regex("""READ_(CONTACTS|SMS|PHONE_STATE|EXTERNAL_STORAGE|CALENDAR)|INTERNET|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|SEND_SMS|READ_SMS|RECEIVE_SMS|INSTALL_PACKAGES|REQUEST_INSTALL_PACKAGES|SYSTEM_ALERT_WINDOW""")
        private val API_CALL_REGEX = Regex("""\.(send|open|connect|execute|load|insert|update|delete|query|start)\(""")
        private val COMPONENT_REGEX = Regex("""<(activity|service|receiver|provider)""", RegexOption.IGNORE_CASE)
        private val OBFUSCATION_REGEX = Regex("""[a-zA-Z]\.a[a-zA-Z]\(""")
        private val DYNAMIC_LOAD_REGEX = Regex("""DexClassLoader|PathClassLoader|loadClass|forName|invoke|exec\(|Runtime\.exec""")
        private val IP_REGEX = Regex("""\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""")
        private val APP_LABEL_REGEX = Regex("""android:label="([^"]*)"""")
        private const val MAX_CACHED_NATIVE_BYTES = 80L * 1024 * 1024
        private const val MAX_NATIVE_LIB_SIZE = 20L * 1024 * 1024
        private const val GIANT_APK_THRESHOLD = 300L * 1024 * 1024
        private const val MASSIVE_APK_THRESHOLD = 1L * 1024 * 1024 * 1024
    }

    fun shutdown() {
        job.cancel()
        parseCancelled = true
        ruleWatcher.stop()
    }

    private fun buildNativeLibCache(
        apkFile: File,
        nativeLibs: List<String>,
        onProgress: (Int, Int, String) -> Unit = { _, _, _ -> }
    ): Map<String, ByteArray> {
        if (nativeLibs.isEmpty() || apkFile.length() > GIANT_APK_THRESHOLD) return emptyMap()
        val cache = mutableMapOf<String, ByteArray>()
        try {
            ZipFile(apkFile).use { zip ->
                var totalBytes = 0L
                val total = nativeLibs.size
                for ((idx, libPath) in nativeLibs.withIndex()) {
                    if (parseCancelled || totalBytes > MAX_CACHED_NATIVE_BYTES) break
                    if (idx % 5 == 0 && parseCancelled) break
                    val entry = zip.getEntry(libPath) ?: continue
                    if (entry.size > MAX_NATIVE_LIB_SIZE) continue
                    val bytes = zip.getInputStream(entry).readBytes()
                    cache[libPath] = bytes
                    totalBytes += bytes.size
                    if (idx % 3 == 0) onProgress(2, TOTAL_PHASE_COUNT, "Native lib cache ${idx + 1}/$total (${totalBytes / 1024} KB)")
                }
            }
        } catch (_: Exception) { }
        return cache
    }

    /**
     * OSINT lookup cache — prevents redundant lookups across scan lifetime
     * Maps package name to known-good probability (0.0 = unknown, 1.0 = confirmed)
     */
    private val osintCache = mutableMapOf<String, Float>()

    private fun osintLookup(packageName: String): Float {
        return osintCache.getOrPut(packageName) {
            if (packageName.isBlank()) return@getOrPut 0f
            val parts = packageName.split(".")
            if (parts.size < 2) return@getOrPut 0f
            val tld = parts[0]
            val org = parts[1]
            val knownOrgs = setOf("google", "mozilla", "microsoft", "apple", "amazon",
                "facebook", "twitter", "spotify", "netflix", "telegram", "signal",
                "discord", "slack", "dropbox", "adobe", "linkedin", "whatsapp",
                "instagram", "uber", "lyft", "airbnb", "paypal", "shopify",
                "walmart", "ebay", "flipkart", "alibaba", "tencent", "alipay")
            val wellKnownDomains = setOf("com", "org", "io", "net", "app", "co")
            if (tld in wellKnownDomains && org in knownOrgs) 0.9f
            else if (tld in wellKnownDomains && parts.size >= 3) 0.5f
            else 0.1f
        }
    }

    suspend fun scan(
        apkUri: String,
        apkName: String,
        onProgress: (phase: Int, total: Int, message: String) -> Unit,
        onFinding: (severity: String, message: String) -> Unit,
        onLog: (message: String, type: LineType) -> Unit
    ): ScanResult = withContext(Dispatchers.IO) {
        certificateAnalyzer.resetDedupState()
        parseCancelled = false
        osintCache.clear()

        suspend fun checkCancelled() {
            if (parseCancelled || !isActive) throw CancellationException("Scan cancelled")
            ensureActive()
        }

        checkCancelled()
        val startTime = System.currentTimeMillis()
        val totalPhases = TOTAL_PHASE_COUNT
        val allFindings = mutableListOf<Finding>()
        var currentPhase = 0

        // Helper: wrap each analyzer in try-catch with timeout so one hang doesn't block the scan
        suspend fun tryAnalyze(tag: String, block: suspend () -> List<Finding>): List<Finding> {
            return try {
                withTimeout(45_000L) { block() }
            } catch (e: TimeoutCancellationException) {
                onLog("[!] $tag timed out after 45s", LineType.WARNING)
                emptyList()
            } catch (e: CancellationException) {
                throw e // user cancelled — propagate
            } catch (e: Exception) {
                onLog("[!] $tag error: ${e.message}", LineType.WARNING)
                emptyList()
            }
        }

        // Phase 1: Extract and hash APK
        currentPhase++
        onProgress(currentPhase, totalPhases, "Extracting APK")
        checkCancelled()
        val apkFile = try {
            extractApk(apkUri, apkName)
        } catch (e: Exception) {
            onLog("[!!!] Failed to extract APK: ${e.message}", LineType.DANGER)
            throw e
        }

        checkCancelled()
        // XAPK detection — extract base APK if XAPK format
        val actualApkFile: File
        val xapkFindings: MutableList<Finding> = mutableListOf()
        var splitApks: List<File> = emptyList()
        var fromXapk = false
        if (xapkExtractor.isXapk(apkFile)) {
            fromXapk = true
            onLog("[+] XAPK detected — extracting base APK...", LineType.SYSTEM)
            val extracted = xapkExtractor.extract(context, apkFile)
            if (!extracted.success) {
                onLog("[!!!] XAPK extraction failed: ${extracted.error}", LineType.DANGER)
                throw Exception("XAPK extraction failed: ${extracted.error}")
            }
            actualApkFile = extracted.baseApk
            splitApks = extracted.splitApks
            xapkFindings.addAll(xapkExtractor.analyzeFindings(extracted))
            onLog("[+] XAPK extracted: ${extracted.splitApks.size + 1} APKs total", LineType.SUCCESS)
        } else {
            actualApkFile = apkFile
        }

        checkCancelled()
        val sha256 = HashUtils.sha256(actualApkFile)
        val md5 = HashUtils.md5(actualApkFile)
        onLog("[+] SHA256: ${sha256.take(16)}...", LineType.SUCCESS)
        onLog("[+] MD5: $md5", LineType.SUCCESS)
        onLog("[+] File size: ${formatSize(actualApkFile.length())}", LineType.SUCCESS)

        allFindings.addAll(xapkFindings)

        // APK Integrity check (skip for XAPK-extracted APKs — container is the distribution format)
        if (!fromXapk) {
            tryAnalyze("integrity") {
                val integrityCheck = apkIntegrityVerifier.verify(actualApkFile)
                if (!integrityCheck.isValid) {
                    onLog("[!!!] APK integrity check FAILED: ${integrityCheck.error}", LineType.DANGER)
                } else {
                    onLog("[+] APK integrity: ${integrityCheck.totalFiles} files, ${integrityCheck.signatureFiles.size} signatures", LineType.SUCCESS)
                }
                integrityCheck.findings
            }.let { allFindings.addAll(it) }
        } else {
            onLog("[+] APK integrity: skipped (XAPK — individual APKs validated separately)", LineType.SUCCESS)
        }

        // Known malware hash check (skip if app is known-good to prevent false positives)
        checkCancelled()
        val ai = try {
            context.packageManager.getPackageArchiveInfo(actualApkFile.absolutePath, 0)
        } catch (_: Exception) { null }
        val knownGoodPkg = ai?.packageName ?: ""
        // Self-scan guard: APK Viper must never flag its own package (its bundled rules /
        // dynamic-rule strings legitimately appear in its own code). Treat as known-good and
        // skip the YARA pass so the scanner cannot detect itself as malware.
        val isSelfScan = ai?.packageName == context.packageName
        val knownGood = if (isSelfScan) {
            true
        } else {
            com.apkviper.engine.malware.KnownGoodDB.isKnownGood(context, knownGoodPkg, actualApkFile.absolutePath)
        }
        if (!knownGood) {
            val knownMalware = KnownMalwareDB.generateFinding(sha256)
            if (knownMalware != null) {
                allFindings.add(knownMalware)
                onFinding(knownMalware.severity.name, "MATCH: ${knownMalware.title}")
                onLog("[!!!] Known malware hash matched: ${knownMalware.title}", LineType.DANGER)
            }
        } else {
            onLog("[+] Known-good app — skipping hash DB to avoid false positive", LineType.SUCCESS)
        }

        // Self-scan guard: APK Viper must never report itself as a threat. Its own
        // YARA strings, dynamic rules and bundled code legitimately trip every
        // heuristic, so instead of running the full pipeline (which would flag the
        // scanner itself), short-circuit to a clean SAFE result.
        if (isSelfScan) {
            onLog("[+] Self-scan detected - APK Viper does not scan itself. Returning clean result.", LineType.SUCCESS)
            try { if (apkFile.exists()) apkFile.delete() } catch (_: Exception) {}
            ruleWatcher.stop()
            val self = ai
            return@withContext ScanResult(
                apkName = apkName,
                apkPath = apkUri,
                sha256 = sha256,
                fileSize = actualApkFile.length(),
                scanMode = "brutal",
                threatLevel = ThreatLevel.SAFE,
                threatScore = 0,
                findings = emptyList(),
                decompileTime = 0L,
                scanTime = System.currentTimeMillis() - startTime,
                classification = null,
                remediations = emptyList(),
                appLabel = self?.applicationInfo?.loadLabel(context.packageManager)?.toString() ?: self?.packageName,
                packageName = self?.packageName,
                versionName = self?.versionName,
                versionCode = if (android.os.Build.VERSION.SDK_INT >= 28) self?.longVersionCode
                else @Suppress("DEPRECATION") self?.versionCode?.toLong(),
                minSdk = safeMinSdk(self),
                targetSdk = self?.applicationInfo?.targetSdkVersion?.let { if (it > 0) it else null }
            )
        }

        // Phase 2: Decompile APK with sub-phase progress and timeout
        // Size gate: skip full decompilation for massive APKs (>2GB) to prevent OOM
        currentPhase++
        onProgress(currentPhase, totalPhases, "Decompiling DEX...")
        checkCancelled()
        val apkSize = actualApkFile.length()
        val isGiantApk = apkSize > GIANT_APK_THRESHOLD
        val isMassiveApk = apkSize > MASSIVE_APK_THRESHOLD

        val decompileStart = System.currentTimeMillis()
        var decompiled: DecompileResult
        if (isMassiveApk) {
            onLog("[!] APK size ${formatSize(apkSize)} > 2GB — skipping full decompilation", LineType.WARNING)
            onLog("[+] Extracting manifest and resources only...", LineType.SYSTEM)
            val manifest = try {
                ZipFile(actualApkFile).use { zip ->
                    val entry = zip.getEntry("AndroidManifest.xml")
                    if (entry == null) { "<manifest/>" } else {
                        val bytes = zip.getInputStream(entry).readBytes()
                        com.apkviper.dex.AxmlDecoder().decode(bytes)
                    }
                }
            } catch (_: Exception) { "<manifest/>" }
            val libs = try {
                ZipFile(actualApkFile).use { zip ->
                    val entries = zip.entries()
                    val libList = mutableListOf<String>()
                    while (entries.hasMoreElements()) {
                        val e = entries.nextElement()
                        if (e.name.startsWith("lib/") && e.name.endsWith(".so")) libList.add(e.name)
                    }
                    libList
                }
            } catch (_: Exception) { emptyList() }
            val dexCount = try {
                ZipFile(actualApkFile).use { zip ->
                    val entries = zip.entries()
                    var count = 0
                    while (entries.hasMoreElements()) {
                        if (entries.nextElement().name.endsWith(".dex", ignoreCase = true)) count++
                    }
                    count
                }
            } catch (_: Exception) { 0 }
            onLog("[+] Manifest extracted, $dexCount DEX files, ${libs.size} native libs", LineType.SUCCESS)
            decompiled = DecompileResult(
                javaSource = emptyMap(), smaliSource = emptyMap(), manifest = manifest,
                resources = emptyMap(), dexFiles = emptyList(), nativeLibs = libs, decompileTimeMs = 0L,
                allSourceText = "", permissions = emptyList(), exportedServiceCount = 0
            )
        } else {
            decompiled = try {
                withContext(Dispatchers.Default) {
                    // For giant APKs (>500MB), use shorter timeout (120s)
                    val timeout = if (isGiantApk) 120_000L else 300_000L
                    withTimeout(timeout) {
                        decompiler.decompile(
                            actualApkFile,
                            onProgress = { msg -> onProgress(currentPhase, totalPhases, msg) },
                            isCancelled = { parseCancelled }
                        )
                    }
                }
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) {
                onLog("[!!!] Decompilation failed: ${e.message}", LineType.DANGER)
                throw Exception("Decompilation failed", e)
            }
        }
        val decompileTime = System.currentTimeMillis() - decompileStart
        onLog("[+] ${decompiled.javaSource.size} Java classes extracted", LineType.SUCCESS)
        onLog("[+] ${decompiled.smaliSource.size} smali files generated", LineType.SUCCESS)
        onLog("[+] ${decompiled.dexFiles.size} DEX files parsed", LineType.SUCCESS)
        onLog("[+] ${decompiled.nativeLibs.size} native libraries found", LineType.SYSTEM)
        onLog("[+] Decompilation time: ${decompileTime}ms", LineType.SYSTEM)

        // allSourceText pre-built by decompiler from java stubs — ready for text analyzers
        val allSourceText = decompiled.allSourceText ?: ""

        // ── Phase 2.5a: Smali-level analyzers (need smali entries, run before smali dropped) ──
        onProgress(currentPhase, totalPhases, "Opcode analysis...")
        val opcodeFindings = tryAnalyze("opcode") { dexOpcodeAnalyzer.analyze(decompiled, actualApkFile) }
        allFindings.addAll(opcodeFindings)
        // Batch large finding sets — 4938 individual UI updates = 12min ETA
        var ob = 0; opcodeFindings.forEach { if (ob++ % 200 == 0) onFinding(it.severity.name, it.title) }
        onLog("[+] opcode done (${opcodeFindings.size})", LineType.INFO)

        val taintSmaliFindings = tryAnalyze("taint-smali") { taintAnalyzer.analyzeSmali(decompiled) }
        allFindings.addAll(taintSmaliFindings); taintSmaliFindings.forEach { onFinding(it.severity.name, it.title) }
        onLog("[+] taint smali done (${taintSmaliFindings.size})", LineType.INFO)

        // ── Phase 2.5b: Drop smaliSource — opcode/taint smali passes complete ──
        decompiled = decompiled.copy(smaliSource = emptyMap())
        System.gc()
        onLog("[+] Smali maps dropped", LineType.SYSTEM)

        // ── Phase 2.5c: Java-level analyzers ──
        onProgress(currentPhase, totalPhases, "Java per-class analysis...")
        var sc = 0
        val s1 = tryAnalyze("code") { codeAnalyzer.analyze(decompiled) }
        allFindings.addAll(s1); sc += s1.size; onLog("[+] code done (${s1.size})", LineType.INFO)

        val s2 = tryAnalyze("packer") { packerDetector.detect(decompiled) }
        allFindings.addAll(s2); sc += s2.size; onLog("[+] packer done (${s2.size})", LineType.INFO)

        val s3 = tryAnalyze("taint") { taintAnalyzer.analyze(decompiled) }
        allFindings.addAll(s3); sc += s3.size; onLog("[+] taint done (${s3.size})", LineType.INFO)
        System.gc()

        val s4 = tryAnalyze("secrets") { secretLeakScanner.scanFromText(allSourceText).first }
        allFindings.addAll(s4); sc += s4.size; onLog("[+] secrets done (${s4.size})", LineType.INFO)

        val s5 = tryAnalyze("cfg") { cfgAnalyzer.analyze(decompiled) }
        allFindings.addAll(s5); sc += s5.size; onLog("[+] cfg done (${s5.size})", LineType.INFO)

        val s6 = tryAnalyze("intent") { intentGraphAnalyzer.analyze(decompiled) }
        allFindings.addAll(s6); sc += s6.size; onLog("[+] intent done (${s6.size})", LineType.INFO)

        val s7 = tryAnalyze("deobStrings") { stringDeobfuscator.analyze(decompiled, allSourceText) }
        allFindings.addAll(s7); sc += s7.size; onLog("[+] deobStrings done (${s7.size})", LineType.INFO)

        // ── Phase 2.5d: Drop javaSource — only allSourceText remains ──
        decompiled = decompiled.copy(javaSource = emptyMap())
        System.gc()
        onLog("[+] Java maps dropped — allSourceText retained", LineType.SYSTEM)
        onLog("[+] Per-class complete — ${sc + opcodeFindings.size + taintSmaliFindings.size} findings", LineType.SUCCESS)

        // Build shared context — compute once, share across all analyzers
        onProgress(currentPhase, totalPhases, "Performing permission analysis...")
        val permissions = PERMISSION_REGEX.findAll(decompiled.manifest)
            .map { it.value }.distinct().toList()
        val exportedServiceCount = EXPORTED_SERVICE_REGEX
            .findAll(decompiled.manifest).count()

        onProgress(currentPhase, totalPhases, "Building native lib cache...")
        val nativeLibBytes = buildNativeLibCache(actualApkFile, decompiled.nativeLibs) { _, _, msg ->
            onProgress(currentPhase, totalPhases, msg)
        }
        onLog("[+] Native lib cache: ${nativeLibBytes.size}/${decompiled.nativeLibs.size} libs loaded", LineType.SYSTEM)

        decompiled = decompiled.copy(
            allSourceText = allSourceText,
            permissions = permissions,
            exportedServiceCount = exportedServiceCount,
            nativeLibBytes = nativeLibBytes
        )

        // Strategic GC before Phase 3 — Phase 2 allocated the most memory (ParseResult/smali/Java/native cache)
        // Free fragmented heap before launching 13 parallel analyzers
        System.runFinalization()
        System.gc()

        // Phase 3: Parallel engine batch — remaining text-based analyzers use allSourceText
        currentPhase++
        onProgress(currentPhase, totalPhases, "Static Analysis Engines")
        checkCancelled()
        supervisorScope {
            val dManifest   = async { tryAnalyze("manifest") { manifestAnalyzer.analyze(decompiled) } }
            val dPermission = async { tryAnalyze("permission") { permissionAnalyzer.analyze(decompiled) } }
            val dStrings    = async { tryAnalyze("strings") { stringExtractor.analyze(decompiled) } }
            val dMiner      = async { tryAnalyze("miner") { cryptoMinerDetector.analyze(decompiled) } }
            val dBehavioral = async { tryAnalyze("behavioral") { behavioralDetector.analyze(decompiled) } }
            val dCallgraph  = async { tryAnalyze("callgraph") { apiCallGraphAnalyzer.analyze(decompiled) } }
            val dPermMatrix = async { tryAnalyze("permMatrix") { permissionRiskMatrix.analyze(permissions, exportedServiceCount) } }
            val dMl         = async { tryAnalyze("ml") { mlScanFast(decompiled) } }

            onLog("[+] Phase 3 analyzers launched...", LineType.INFO)
            val results = mapOf(
                "manifest" to dManifest.await(), "permission" to dPermission.await(),
                "strings" to dStrings.await(), "miner" to dMiner.await(),
                "behavioral" to dBehavioral.await(), "callgraph" to dCallgraph.await(),
                "permMatrix" to dPermMatrix.await(), "ml" to dMl.await()
            )

            for ((tag, findings) in results) {
                allFindings.addAll(findings)
                // Batch-feed findings to UI — every 50th instead of every single one
                var bc = 0
                for (f in findings) {
                    if (bc++ % 50 == 0) onFinding(f.severity.name, if (tag == "callgraph") "CHAIN: ${f.title}" else "${f.title}")
                }
            }
            onLog("[+] Static analysis: ${allFindings.size} total findings", LineType.SUCCESS)
        }
        currentPhase++
        onProgress(currentPhase, totalPhases, "Deep Analysis Engines")
        checkCancelled()
        supervisorScope {
            val deferred = listOf(
                async { checkCancelled(); tryAnalyze("obfuscation") { obfuscationDetector.analyze(decompiled) } } to "obfuscation",
                async { checkCancelled(); tryAnalyze("entropy") { entropyAnalyzer.analyze(decompiled) } } to "entropy",
                async { checkCancelled(); tryAnalyze("ngram") { opcodeNgramAnalyzer.analyze(actualApkFile) } } to "ngram",
            ).map { (def, tag) -> def.await() to tag }

            for ((findings, tag) in deferred) {
                allFindings.addAll(findings)
                val prefix = when (tag) { "ngram" -> "NGRAM: "; else -> "" }
                findings.forEach { onFinding(it.severity.name, "$prefix${it.title}") }
            }
            onLog("[+] N-Gram: ${deferred.find { it.second == "ngram" }?.first?.size ?: 0} pattern matches", LineType.SUCCESS)
        }

        // Phase 5: Parallel — Malware + YARA + Certificate + Native + Entropy-Packer + Network
        currentPhase++
        onProgress(currentPhase, totalPhases, "Signature & Native Analysis")
        checkCancelled()
        supervisorScope {
            val deferred = listOf(
                async { tryAnalyze("malware") { malwareDetector.analyze(decompiled) } } to "malware",
                async { tryAnalyze("yara") { if (isSelfScan) emptyList() else yaraEngine.scan(decompiled) } } to "yara",
                async { tryAnalyze("deepCert") { certificateAnalyzer.analyzeCertificate(actualApkFile) } } to "deepCert",
                async { tryAnalyze("native") { nativeAnalyzer.analyze(decompiled) } } to "native",
                async { tryAnalyze("deepNative") { nativeAnalyzer.deepScan(actualApkFile, decompiled.nativeLibs, decompiled.nativeLibBytes) } } to "deepNative",
                async { tryAnalyze("callGraphNative") { nativeCallGraphCorrelator.analyze(actualApkFile, decompiled.nativeLibs, decompiled.nativeLibBytes) } } to "callGraphNative",
                async { tryAnalyze("bytecode") { nativeBytecodeScanner.analyze(actualApkFile, decompiled.nativeLibs) } } to "bytecode",
                async { tryAnalyze("libDiff") { nativeLibraryDiffer.analyze(actualApkFile, decompiled.nativeLibs) } } to "libDiff",
                async { tryAnalyze("entropyPacker") { entropyPackerDetector.analyze(actualApkFile, decompiled.nativeLibs, decompiled.nativeLibBytes) } } to "entropyPacker",
                async { tryAnalyze("network") { networkAnalyzer.analyze(decompiled) } } to "network",
            ).map { (def, tag) -> def.await() to tag }

            for ((findings, tag) in deferred) {
                allFindings.addAll(findings)
                val prefix = when (tag) { "yara" -> "YARA: "; "callGraphNative" -> "CALLGRAPH: "; "entropyPacker" -> "ENTROPY: "; else -> "" }
                findings.forEach { onFinding(it.severity.name, "$prefix${it.title}") }
            }

            onLog("[+] YARA: ${deferred.find { it.second == "yara" }?.first?.size ?: 0} rule matches", LineType.SUCCESS)
            val nativeChainCount = deferred.find { it.second == "callGraphNative" }?.first?.size ?: 0
            onLog("[+] Native call-graph: $nativeChainCount chains", if (nativeChainCount > 0) LineType.DANGER else LineType.SUCCESS)
        }

        // Phase 6: Parallel — SDK + Framework Integrity + CFG
        currentPhase++
        onProgress(currentPhase, totalPhases, "Supply Chain & Integrity")
        checkCancelled()
        supervisorScope {
            val deferred = listOf(
                async { tryAnalyze("sdk") { sdkAnalyzer.analyze(decompiled) } } to "sdk",
                async { tryAnalyze("integrity") { frameworkIntegrityChecker.analyze(decompiled, actualApkFile) } } to "integrity",
            ).map { (def, tag) -> def.await() to tag }

            for ((findings, tag) in deferred) {
                allFindings.addAll(findings)
                val prefix = when (tag) { "integrity" -> "INTEGRITY: "; else -> "" }
                findings.forEach { onFinding(it.severity.name, "$prefix${it.title}") }
            }
            onLog("[+] Framework integrity: ${deferred.find { it.second == "integrity" }?.first?.size ?: 0} issues", LineType.SUCCESS)
        }

        // Phase 7: Parallel — Anti-Evasion + Threat Intel + Scoring
        currentPhase++
        onProgress(currentPhase, totalPhases, "Anti-Evasion + Threat Intel + Scoring")
        checkCancelled()
        supervisorScope {
            val evasionDeferred = async { tryAnalyze("evasion") { antiEvasionDetector.analyze(decompiled, actualApkFile) } }
            val intelDeferred = async { tryAnalyze("intel") {
                val ips = Regex("""\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""").findAll(allSourceText).map { it.value }.toSet()
                val matches = ips.mapNotNull { ip ->
                    val m = ThreatIntelDB.checkIp(ip)
                    if (m.level != ThreatIntelDB.MatchLevel.CLEAN) m else null
                }
                ThreatIntelDB.generateFindings(matches)
            } }

            val evasionFindings = evasionDeferred.await()
            allFindings.addAll(evasionFindings)
            evasionFindings.forEach { onFinding(it.severity.name, "EVASION: ${it.title}") }
            onLog("[+] Anti-evasion: ${evasionFindings.size} indicators", if (evasionFindings.size >= 3) LineType.DANGER else LineType.SUCCESS)

            val intelFindings = intelDeferred.await()
            allFindings.addAll(intelFindings)
            intelFindings.forEach { onFinding(it.severity.name, "INTEL: ${it.title}") }
            onLog("[+] Threat intel: ${intelFindings.size} C2 matches", LineType.SUCCESS)
        }

        // Phase 8: Behavioral Profiling Engines
        currentPhase++
        onProgress(currentPhase, totalPhases, "Behavioral Profiling Engines")
        checkCancelled()
        val srcForAnalyzers = allSourceText
        supervisorScope {
            val deferred = listOf(
                async { tryAnalyze("nativeBehaviors") { nativeBehaviorAnalyzer.analyze(decompiled, actualApkFile) } } to "nativeBehaviors",
                async { tryAnalyze("phishing") { phishingOverlayAnalyzer.analyze(decompiled) } } to "phishing",
                async { tryAnalyze("netProfile") { networkBehaviorProfiler.analyze(srcForAnalyzers) } } to "netProfile",
                async { tryAnalyze("timeline") { behaviorTimelineAnalyzer.analyze(decompiled) } } to "timeline",
                async { tryAnalyze("resourceMonitor") {
                    backgroundResourceMonitor.analyze(decompiled.manifest, permissions, emptyList(), emptyList())
                } } to "resourceMonitor",
                async { tryAnalyze("modApk") {
                    val sooAnomaly = modApkDetector.detectSooAnomaly(actualApkFile)
                    val assessment = modApkDetector.assess(context, actualApkFile, decompiled, null)
                    modApkDetector.generateFindings(assessment, sooAnomaly)
                } } to "modApk",
                async { tryAnalyze("shizuku") { shizukuDetector.analyze(decompiled) } } to "shizuku",
                async { tryAnalyze("vApp") { virtualAppDetector.analyze(decompiled) } } to "vApp",
                async { tryAnalyze("accessChain") { accessibilityChainAnalyzer.analyze(decompiled) } } to "accessChain",
            ).map { (def, tag) -> def.await() to tag }

            for ((findings, label) in deferred) {
                allFindings.addAll(findings)
                when {
                    findings.any { it.severity == Severity.CRITICAL } -> onLog("[+] [$label] ${findings.size} findings (CRITICAL)", LineType.DANGER)
                    findings.any { it.severity == Severity.HIGH } -> onLog("[+] [$label] ${findings.size} findings (HIGH)", LineType.WARNING)
                    findings.isNotEmpty() -> onLog("[+] [$label] ${findings.size} findings", LineType.SUCCESS)
                }
                findings.forEach { onFinding(it.severity.name, "${label.uppercase()}: ${it.title}") }
            }
        }

        // ── Split APK Analysis (XAPK only) ──
        var totalJavaSources = decompiled.javaSource.size
        var totalSmaliSources = decompiled.smaliSource.size
        var totalDexFiles = decompiled.dexFiles.size

        if (splitApks.isNotEmpty()) {
            currentPhase++
            onProgress(currentPhase, totalPhases, "Split APK Analysis (${splitApks.size} APKs)")
            val axmlDecoder = AxmlDecoder()
            for ((i, splitApk) in splitApks.withIndex()) {
                checkCancelled()
                val tag = splitApk.name
                val splitSize = splitApk.length()

                // Size gate: skip oversized split APKs entirely
                if (splitSize > 500 * 1024 * 1024) {
                    onLog("[!] Split $tag too large (${formatSize(splitSize)}), skipping", LineType.WARNING)
                    continue
                }

                onLog("[+] Analyzing split APK ${i + 1}/${splitApks.size}: $tag (${formatSize(splitSize)})", LineType.SYSTEM)
                onProgress(currentPhase, totalPhases, "Split ${i + 1}/${splitApks.size}: $tag")

                // Lightweight manifest extraction + decode
                val manifestText = try {
                    java.util.zip.ZipFile(splitApk).use { zip ->
                        val entry = zip.getEntry("AndroidManifest.xml") ?: return@use null
                        val bytes = zip.getInputStream(entry).readBytes()
                        axmlDecoder.decode(bytes)
                    }
                } catch (_: Exception) { null }

                if (manifestText != null) {
                    val dec = com.apkviper.model.DecompileResult(
                        javaSource = emptyMap(), smaliSource = emptyMap(),
                        manifest = manifestText, resources = emptyMap(),
                        dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
                    )
                    allFindings.addAll(tryAnalyze("split_manifest[$tag]") { manifestAnalyzer.analyze(dec) }
                        .onEach { onFinding(it.severity.name, "SPLIT[$tag]: ${it.title}") })
                    allFindings.addAll(tryAnalyze("split_perms[$tag]") { permissionAnalyzer.analyze(dec) }
                        .onEach { onFinding(it.severity.name, "SPLIT[$tag]: ${it.title}") })
                    allFindings.addAll(tryAnalyze("split_code[$tag]") { codeAnalyzer.analyze(dec) }
                        .onEach { onFinding(it.severity.name, "SPLIT[$tag]: ${it.title}") })
                    allFindings.addAll(tryAnalyze("split_strings[$tag]") { stringExtractor.analyze(dec) }
                        .onEach { onFinding(it.severity.name, "SPLIT[$tag]: ${it.title}") })

                    // Check if split APK has DEX files — count only, don't do heavy analysis
                    // (YARA, ML, opcode, miner, malware already ran on the base APK)
                    val hasDex = try {
                        var dexCount = 0
                        java.util.zip.ZipFile(splitApk).use { z ->
                            dexCount = z.entries().asSequence().count { it.name.endsWith(".dex", ignoreCase = true) }
                        }
                        if (dexCount > 0) {
                            onLog("[+] $tag has $dexCount DEX file(s) — counting for summary, skipping heavy split analysis", LineType.INFO)
                            totalDexFiles += dexCount
                        }
                        dexCount > 0
                    } catch (_: Exception) { false }

                    // Only decompile if split is small and not too many classes
                    if (hasDex && splitSize < 50 * 1024 * 1024) {
                        onLog("[+] $tag is small (${formatSize(splitSize)}) — running decompilation for smali/java counts...", LineType.INFO)
                        val splitDec = try {
                            withContext(Dispatchers.Default) {
                                kotlinx.coroutines.withTimeout(60_000L) { decompiler.decompile(splitApk, onProgress = {}, isCancelled = { parseCancelled }, maxClasses = 500) }
                            }
                        } catch (_: Exception) { null }

                        if (splitDec != null) {
                            totalJavaSources += splitDec.javaSource.size
                            totalSmaliSources += splitDec.smaliSource.size
                        }
                        System.gc()
                    } else if (hasDex) {
                        onLog("[!] $tag is large (${formatSize(splitSize)}) — skipping deep analysis, counting DEX only", LineType.WARNING)
                    }
                    if (splitSize > 50 * 1024 * 1024) System.gc()
                }

                // File-based analyses (don't need decompilation)
                allFindings.addAll(tryAnalyze("split_cert_file[$tag]") { certificateAnalyzer.analyzeCertificate(splitApk) }
                    .onEach { onFinding(it.severity.name, "SPLIT[$tag]: ${it.title}") })
                allFindings.addAll(tryAnalyze("split_entropy_packer[$tag]") { entropyPackerDetector.analyze(splitApk, emptyList()) }
                    .onEach { onFinding(it.severity.name, "SPLIT[$tag]: ${it.title}") })
                allFindings.addAll(tryAnalyze("split_native[$tag]") { nativeAnalyzer.deepScan(splitApk, emptyList()) }
                    .onEach { onFinding(it.severity.name, "SPLIT[$tag]: ${it.title}") })
                allFindings.addAll(tryAnalyze("split_integrity[$tag]") { apkIntegrityVerifier.verify(splitApk, isSplitApk = true).findings }
                    .onEach { onFinding(it.severity.name, "SPLIT[$tag]: ${it.title}") })
            }
            onLog("[+] Split APK analysis complete — ${splitApks.size} APKs processed", LineType.SUCCESS)
            onLog("[+] Total (base + splits): ${totalJavaSources} Java, ${totalSmaliSources} smali, ${totalDexFiles} DEX", LineType.SUCCESS)
        }

        checkCancelled()
        // OSINT-based false positive reduction — downgrade CERTIFICATE findings for well-known apps
        val pkgName = ai?.packageName ?: ""
        val osintScore = osintLookup(pkgName)
        if (osintScore >= 0.5f) {
            val before = allFindings.size
            allFindings.removeAll { f ->
                f.category == FindingCategory.CERTIFICATE && f.severity == Severity.MEDIUM
            }
            val after = allFindings.size
            if (before != after) {
                onLog("[+] OSINT: downgraded ${before - after} certificate findings for known app package", LineType.SUCCESS)
            }
        }

        checkCancelled()
        onLog("[+] Calculating threat score from ${allFindings.size} findings...", LineType.INFO)

        val scanTime = System.currentTimeMillis() - startTime
        val rawScore = threatScorer.calculate(allFindings, knownGood)

        // Defense-in-depth verdict gate: a MALICIOUS verdict (>=91) requires corroborated
        // strong malware evidence — a confirmed known-malware hash, or at least two independent
        // strong findings (curated YARA family, crypto-miner, high-confidence ML). Without it,
        // benign/modded apps that merely trip noisy heuristics (native syscalls, trackers,
        // standard permissions, community YARA strings) can at most reach HIGH — never
        // MALICIOUS. This mirrors how top-tier detectors (VirusTotal, MobSF, DREBIN) refuse to
        // call an app malware on heuristic volume alone.
        val threatScore = threatScorer.gateVerdict(rawScore, allFindings, knownGood)
        if (threatScore < rawScore) {
            onLog("[+] Verdict gated: insufficient corroborated evidence — capped at HIGH ($threatScore/100)", LineType.SUCCESS)
        }
        val threatLevel = threatScorer.getThreatLevel(threatScore)

        // Phase 9: Privacy Assessment + Threat Classification & Remediation
        currentPhase++
        onProgress(currentPhase, totalPhases, "Privacy Assessment & Threat Classification")
        checkCancelled()
        val privResult = try {
            privacyScorer.assess(decompiled)
        } catch (e: CancellationException) { throw e }
        catch (e: Exception) {
            onLog("[!] privacy assessment error: ${e.message}", LineType.WARNING)
            null
        }
        if (privResult != null) {
            allFindings.addAll(privResult.findings)
            privResult.findings.forEach { onFinding(it.severity.name, "PRIVACY: ${it.title}") }
            onLog("[+] Privacy score: ${privResult.privacyScore}/100 (${privResult.trackersFound.size} trackers)", LineType.SUCCESS)
        }
        val cr = try {
            threatClassifier.classify(allFindings)
        } catch (e: CancellationException) { throw e }
        catch (e: Exception) {
            onLog("[!] classification error: ${e.message}", LineType.WARNING)
            ClassificationResult()
        }
        onLog("", LineType.OUTPUT)
        onLog("═══ SCAN COMPLETE ═══", LineType.HEADER)
        onLog("  Total time: ${scanTime}ms", LineType.SYSTEM)
        onLog("  Total findings: ${allFindings.size}", LineType.SYSTEM)
        onLog("  Threat score: $threatScore/100 ($threatLevel)", LineType.DANGER)
        onLog("  Classes: ${totalJavaSources}", LineType.SYSTEM)
        onLog("  Smali files: ${totalSmaliSources}", LineType.SYSTEM)
        onLog("  DEX files: ${totalDexFiles}", LineType.SYSTEM)
        onLog("  Native libs: ${decompiled.nativeLibs.size}", LineType.SYSTEM)
        onLog("", LineType.OUTPUT)

        onLog("[+] Scan complete — cleaning up...", LineType.SYSTEM)
        parseCancelled = false
        ruleWatcher.stop()

        // Save file size BEFORE cleanup — the temp file gets deleted below
        val actualFileSize = actualApkFile.length()

        // Cleanup temp scan files and XAPK extraction directories
        try {
            if (apkFile.exists()) apkFile.delete()
            if (actualApkFile !== apkFile) {
                val extractDir = actualApkFile.parentFile
                if (extractDir != null && extractDir.name.startsWith("xapk_extract_")) {
                    extractDir.deleteRecursively()
                }
            }
        } catch (_: Exception) {}

        val appLabel = APP_LABEL_REGEX.find(decompiled.manifest)
            ?.groupValues?.getOrNull(1)
            ?.takeIf { it.isNotBlank() && !it.startsWith("@") && !it.startsWith("0x") }

        ScanResult(
            apkName = apkName,
            apkPath = apkUri,
            sha256 = sha256,
            fileSize = actualFileSize,
            scanMode = "brutal",
            threatLevel = threatLevel,
            threatScore = threatScore,
            findings = allFindings,
            decompileTime = decompileTime,
            scanTime = scanTime,
            classification = cr.classification,
            remediations = cr.remediations,
            appLabel = appLabel,
            packageName = ai?.packageName,
            versionName = ai?.versionName,
            versionCode = if (android.os.Build.VERSION.SDK_INT >= 28) {
                ai?.longVersionCode
            } else {
                @Suppress("DEPRECATION") val vc = ai?.versionCode; vc?.toLong()
            },
            minSdk = safeMinSdk(ai),
            targetSdk = ai?.applicationInfo?.targetSdkVersion?.let { if (it > 0) it else null }
        )
    }

    private fun extractApk(uri: String, apkName: String): File {
        return try {
            val apkUri = Uri.parse(uri)
            // Preserve original extension for XAPK detection
            val ext = apkName.substringAfterLast('.', "apk")
            val file = File(context.cacheDir, "scan_${System.currentTimeMillis()}.$ext")
            context.contentResolver.openInputStream(apkUri)?.use { input ->
                file.outputStream().use { output -> input.copyTo(output) }
            } ?: throw IllegalStateException("Cannot open APK file")
            if (file.length() == 0L) throw IllegalStateException("APK file is empty")
            file
        } catch (e: Exception) {
            throw IllegalStateException("Failed to extract APK: ${e.message}", e)
        }
    }

    private fun formatSize(bytes: Long): String = StorageCleaner(context).formatBytes(bytes)

    private suspend fun mlScanFast(decompiled: DecompileResult): List<Finding> {
        val allText = decompiled.allSourceText ?: return emptyList()
        val manifest = decompiled.manifest
        var lineCount = 0
        for (ch in allText) if (ch == '\n') lineCount++
        if (lineCount == 0) lineCount = 1
        val totalPerms = decompiled.permissions.size
        val dangerousPerms = DANGEROUS_PERM_REGEX.findAll(manifest).count()
        val apiCallCount = API_CALL_REGEX.findAll(allText).count()
        val density = apiCallCount.toFloat() / lineCount * 1000f
        val nativeCount = decompiled.nativeLibs.size
        val componentCount = COMPONENT_REGEX.findAll(manifest).count()
        val obfuscationHits = OBFUSCATION_REGEX.findAll(allText).count()
        val obfScore = minOf(obfuscationHits.toFloat() / lineCount * 10f, 1f)
        val dynamicLoads = DYNAMIC_LOAD_REGEX.findAll(allText).count()
        val c2Count = IP_REGEX.findAll(allText).count()
        val exportServiceCount = decompiled.exportedServiceCount

        val features = TinyMLClassifier.FeatureVector(
            totalPermissions = totalPerms, dangerousPermissions = dangerousPerms,
            apiCallDensity = density, nativeLibCount = nativeCount,
            componentCount = componentCount, obfuscationScore = obfScore,
            entropyScore = 0f, dynamicLoadingFlags = dynamicLoads,
            c2IndicatorCount = c2Count, exportServiceCount = exportServiceCount
        )
        val prediction = mlClassifier.predictDetailed(features)
        val findings = mutableListOf<Finding>()
        val score = prediction.maliciousProbability
        val confidence = prediction.confidence
        val confLabel = if (prediction.isUncertain) " (LOW CONFIDENCE)" else ""
        // CRITICAL is reserved for genuinely high-probability, confident predictions so the
        // ML signal cannot by itself push a genuine/modded app into MALICIOUS (it is a
        // supporting signal, not a sole verdict driver).
        if (score > 85f && !prediction.isUncertain) {
            findings.add(Finding(FindingCategory.BEHAVIORAL,
                Severity.CRITICAL,
                "ML Classifier: High Malicious Probability$confLabel",
                "Random forest model predicts ${"%.0f".format(score)}% malicious (${"%.0f".format(confidence*100)}% confidence)",
                "Perms:$totalPerms API:${"%.0f".format(density)}/kLOC Natives:$nativeCount Components:$componentCount Obf:${"%.2f".format(obfScore)} Loads:$dynamicLoads C2:$c2Count Export:$exportServiceCount"
            ))
        } else if (score > 70f) {
            findings.add(Finding(FindingCategory.BEHAVIORAL,
                if (prediction.isUncertain) Severity.MEDIUM else Severity.HIGH,
                "ML Classifier: Suspicious$confLabel",
                "ML scores ${"%.0f".format(score)}% (${"%.0f".format(confidence*100)}% confidence)", null))
        } else if (score > 50f) {
            findings.add(Finding(FindingCategory.BEHAVIORAL,
                Severity.MEDIUM,
                "ML Classifier: Suspicious$confLabel",
                "ML scores ${"%.0f".format(score)}% (${"%.0f".format(confidence*100)}% confidence)", null))
        } else if (score > 35f) {
            findings.add(Finding(FindingCategory.BEHAVIORAL,
                Severity.LOW,
                "ML Classifier: Slightly Suspicious$confLabel",
                "ML scores ${"%.0f".format(score)}% (${"%.0f".format(confidence*100)}% confidence)", null))
        }
        return findings
    }

    private fun loadYaraRules() {
        val rulesFromAsset = try {
            context.assets.open("yara_rules/default.yar").bufferedReader().use { it.readText() }
        } catch (e: Exception) {
            android.util.Log.w("ScanPipeline", "No asset YARA rules: ${e.message}")
            ""
        }
        val rulesFromCache = try {
            val cacheFile = java.io.File(context.filesDir, "yara_rules_cache.yar")
            if (cacheFile.exists() && cacheFile.length() > 0L) cacheFile.readText() else ""
        } catch (e: Exception) { "" }

        // Prefer the auto-updated cache (it already embeds the curated baseline + filtered
        // community rules) to avoid duplicating the bundled ruleset.
        val baseRules = if (rulesFromCache.isNotBlank()) rulesFromCache else rulesFromAsset
        val dynamic = autoUpdateEngine.getDynamicRules()
        val combined = baseRules + "\n" + dynamic
        if (combined.isNotBlank()) {
            yaraEngine.loadRules(combined)
        }
    }

    /**
     * Reads ApplicationInfo.minSdkVersion defensively. The field is only present on newer
     * platform stubs (API 24+); some test shadows / vendor ROMs lack it, so reflect and
     * fall back to null instead of throwing.
     */
    private fun safeMinSdk(ai: android.content.pm.PackageInfo?): Int? {
        return try {
            val appInfo = ai?.applicationInfo ?: return null
            val f = appInfo.javaClass.getField("minSdkVersion")
            val v = f.getInt(appInfo)
            if (v > 0) v else null
        } catch (_: Exception) {
            null
        }
    }
}
