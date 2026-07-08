# APK Viper

**On-device Android APK security analyzer** — 38+ detection engines, 9-phase pipeline, 100% offline.

```
┌─────────────────────────────────────────────────────────────┐
│                    APK VIPER v1.1.0                         │
├─────────────────────────────────────────────────────────────┤
│  Static → Heuristic → Advanced → Deep → Detection → Profiling → Score    │
│  All analysis runs on-device. Zero data leaves your phone.  │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Prerequisites: JDK 17+, Android SDK 34+
# Build
./gradlew assembleDebug

# Run tests
./gradlew cleanTest testDebugUnitTest
# → 1194 unit tests, all passing (0 failures)

# Install
./gradlew installDebug
```

## Features

### Detection Engines (38+ across a 9-phase pipeline)

| Phase | Engines | What They Detect |
|-------|---------|------------------|
| **1 · Extract & Hash** | XapkExtractor, HashUtils (SHA256/MD5), ApkIntegrityVerifier, KnownMalwareDB, KnownGoodDB | File/XAPK extraction, integrity check, known-good & known-bad hash matching |
| **2 · Decompile** | DecompilerManager, DexParser, SmaliDisassembler, AxmlDecoder, DexOpcodeAnalyzer, TaintAnalyzer (smali) | DEX→Smali→Java stubs, binary AXML manifest decode, opcode & smali-level taint |
| **3 · Static (13 parallel)** | ManifestAnalyzer, PermissionAnalyzer, CodeAnalyzer, StringExtractor, CertificateAnalyzer, PackerDetector, CryptoMinerDetector, BehavioralDetector, ApiCallGraphAnalyzer, PermissionRiskMatrix, SecretLeakScanner, TinyMLClassifier, TaintAnalyzer | Manifest/permission/cert issues, code & string patterns, hardcoded secrets, miners, behaviors, ML probability |
| **4 · Deep (3 parallel)** | ObfuscationDetector, EntropyAnalyzer, OpcodeNgramAnalyzer | Obfuscation, entropy, N-gram byte patterns |
| **5 · Signature & Native (11 parallel)** | MalwarePatternDetector, YaraEngine, NativeAnalyzer, NativeCallGraphCorrelator, NativeBytecodeScanner, NativeLibraryDiffer, EntropyPackerDetector, NetworkAnalyzer, FrameworkIntegrityChecker, CfgStructuralAnalyzer, IntentRelationGraphAnalyzer | YARA rules, native .so behavior, network sinks, CFG similarity, intent graphs, framework tampering |
| **6 · Supply Chain (2)** | SDKAnalyzer, FrameworkIntegrityChecker | Vulnerable/outdated SDKs, framework integrity |
| **7 · Anti-Evasion + Intel (2)** | AntiEvasionDetector, ThreatIntelDB | Evasion (debugger/VM/sandbox), C2 IPs & malicious domains |
| **8 · Behavioral Profiling (9 parallel)** | NativeBehaviorAnalyzer, PhishingOverlayAnalyzer, NetworkBehaviorProfiler, BehaviorTimelineAnalyzer, BackgroundResourceMonitor, ModApkDetector, ShizukuDetector, VirtualAppDetector, AccessibilityChainAnalyzer | Overlay phishing, virtual environments, modded/repackaged apps, accessibility abuse, resource abuse |
| **9 · Scoring (3)** | PrivacyScorer, ThreatScorer, ThreatClassifier | Privacy risk, weighted threat score, classification + remediation |

### Additional Capabilities

- **PDF Report Generation** — Multi-page professional PDF with cover page, real app icon (composited from ic_launcher_foreground + ic_launcher_background — no fallbacks), severity gauge, info cards, severity breakdown bar, MITRE ATT&CK table, finding detail cards, remediation checklist, file analysis table
- **9-Phase Scan Pipeline** — 38+ analyzers running in parallel (supervisorScope + 45s per-analyzer timeout) with cancellation support and per-phase progress
- **Verdict Gating (FP-safe)** — a MALICIOUS verdict (score ≥ 91) requires ≥ 2 independent *strong* findings; noisy heuristics can at most reach HIGH. See [Verdict Gating](#verdict-gating-false-positive-safety)
- **Real-time Terminal Log** — Live scan progress with current analyzer activity and dynamic weighted ETA
- **APK File Monitor** — Background service watching Downloads/ for new APKs
- **Threat Timeline** — Per-package score trend in dashboard
- **Scan History** — Room database with timeline queries and package-name grouping (confidence + ruleSource preserved)
- **Auto-Update Engine** — Background rules + hashes + threat intel sync
- **XAPK Support** — Split APK extraction and per-split analysis
- **Storage Cleaner** — Temp file cleanup (scan extracts, XAPK dirs, stale logs) with size/age guards
- **1194 Unit Tests** — All passing (0 failures), covering every analyzer, data layer, service, UI logic, and PDF generation

## What's New in v1.1.0

APK Viper v1.1.0 hardens the scanner so **modded, legitimate, and sideloaded apps are never
mislabeled as malware / RAT**, and fixes a crash that could occur when scanning large APKs.

### False-Positive Safety (mod-aware)
- **Benign obfuscation whitelist** — Facebook Audience Network's `redex` tooling emits classes
  named `Lcom_facebook_ads_redexgen_X_*` whose `new-array → fill-array-data` and dead-code
  patterns look like encrypted payloads. These are now skipped (mirrors the native-framework
  downgrade list), eliminating thousands of bogus "Suspicious Opcode Sequence" findings on any
  app that bundles the Facebook ads SDK.
- **Keylogger rule requires a real IME** — ordinary keyboard handling (`onKey` / `KeyEvent` /
  `dispatchKeyEvent`) in games no longer triggers a `Keylogger` verdict. A genuine keylogger
  needs an `InputMethodService` (or accessibility key-capture), which is now mandatory.
- **Verdict gate preserved** — a `MALICIOUS` verdict still requires ≥ 2 independent *strong*
  findings or a known-malware hash; noisy heuristics are capped at `HIGH`.

### Stability
- **Foreground-service crash fixed** — `ScanForegroundService` now always promotes to foreground
  (with a safe fallback notification) even on redelivered intents, eliminating
  `RemoteServiceException$ForegroundServiceDidNotStartInTimeException` on scan resume.
- **Crash-safe scan coroutine** — `ScanViewModel` and `ApkFileMonitorService` now catch
  `Throwable` (including R8/ART `VerifyError`) so a single engine or ART error can never kill
  the process and trigger a redelivery crash.
- **R8 `-dontoptimize`** added to ProGuard rules to prevent verifier-rejected-class crashes on
  some devices.

## Architecture

### 9-Phase Pipeline

```mermaid
graph TB
    subgraph "Phase 1: Extract + Hash"
        P1[APK Extraction<br/>SHA256/MD5<br/>Integrity Check<br/>Known Malware Hash]
    end

    subgraph "Phase 2: Decompile"
        P2[DEX Parsing<br/>Smali Generation<br/>Java Decompilation<br/>Manifest Decode<br/>Native Lib Cache]
    end

    subgraph "Phase 3: Static Analysis 5 engines"
        P3[Manifest Analyzer<br/>Permission Analyzer<br/>Code Analyzer<br/>String Extractor<br/>Certificate Analyzer<br/>+ Packer, Miner, Opcode<br/>Taint, Behavioral, CallGraph<br/>PermMatrix, Secrets, ML]
    end

    subgraph "Phase 4: Deep Analysis 4 engines"
        P4[Obfuscation Detector<br/>Entropy Analyzer<br/>N-gram Analyzer<br/>Intent Graph]
    end

    subgraph "Phase 5: Signature + Native 11 engines"
        P5[YARA Engine<br/>Native Analyzer<br/>Network Analyzer<br/>Certificate Deep Scan<br/>Native Call Graph<br/>Bytecode Scanner<br/>Library Differ<br/>Entropy Packer<br/>+ MalwarePattern]
    end

    subgraph "Phase 6: Supply Chain 3 engines"
        P6[SDK Analyzer<br/>Framework Integrity<br/>CFG Structural]
    end

    subgraph "Phase 7: Anti-Evasion + Intel 2 engines"
        P7[Anti-Evasion Detector<br/>Threat Intel DB]
    end

    subgraph "Phase 8: Behavioral Profiling 10 engines"
        P8[Native Behaviors<br/>String Deobfuscator<br/>Phishing Overlay<br/>Network Profiler<br/>Behavior Timeline<br/>Mod APK Detector<br/>Shizuku Detector<br/>Virtual App Detector<br/>Accessibility Chain<br/>Resource Monitor]
    end

    subgraph "Phase 9: Scoring"
        P9[Privacy Scorer<br/>Threat Scorer<br/>Threat Classifier<br/>→ Score + Classification]
    end

    P1 --> P2 --> P3 --> P4 --> P5 --> P6 --> P7 --> P8 --> P9

    style P1 fill:#1e293b,color:#fff
    style P2 fill:#1e293b,color:#fff
    style P3 fill:#1e293b,color:#fff
    style P4 fill:#334155,color:#fff
    style P5 fill:#1e293b,color:#fff
    style P6 fill:#334155,color:#fff
    style P7 fill:#1e293b,color:#fff
    style P8 fill:#334155,color:#fff
    style P9 fill:#eab308,color:#000
```

### Data Flow

```mermaid
flowchart TD
    APK[APK/XAPK File] --> P1[Phase 1: Extract + Hash<br/>SHA256/MD5 + ZIP parse<br/>Integrity Verification<br/>Known Malware Check]
    P1 --> P2[Phase 2: Decompile<br/>DEX parse → Smali + Java<br/>AXML manifest decode<br/>Native lib caching]
    P2 --> P2B[Phase 2.5: Process Sources<br/>allSourceText join<br/>Permission extraction<br/>Native lib cache build]
    P2B --> P3[Phase 3: Static Analysis<br/>13 engines in parallel<br/>supervisorScope + async/awaitAll]
    P3 --> P4[Phase 4: Deep Analysis<br/>4 engines: Obfuscation, Entropy<br/>N-Gram, Intent Graph]
    P4 --> P5[Phase 5: Signature + Native<br/>11 engines: YARA, Native<br/>Network, Cert, EntropyPacker]
    P5 --> P6[Phase 6: Supply Chain<br/>3 engines: SDK, Integrity, CFG]
    P6 --> P7[Phase 7: Anti-Evasion<br/>2 engines: Evasion + Threat Intel]
    P7 --> P8[Phase 8: Behavioral Profiling<br/>10 engines in parallel]
    P8 --> P9[Phase 9: Scoring<br/>PrivacyScorer → ThreatScorer<br/>→ ThreatClassifier]
    P9 --> DB[(Room DB: Scan History)]
    P9 --> PDF[PDF Report<br/>Cover + Summary + MITRE<br/>+ Findings Detail Pages]
    DB --> DASH[Dashboard<br/>Per-package score trend]

    style APK fill:#334155,color:#fff
    style P9 fill:#eab308,color:#000
    style PDF fill:#eab308,color:#000
    style DB fill:#1e293b,color:#fff
    style DASH fill:#22c55e,color:#000
```

### Scan Progress Flow

```mermaid
sequenceDiagram
    participant User
    participant HomeScreen
    participant ScanViewModel
    participant ScanPipeline
    participant Decompiler
    participant Analyzers
    participant DB as Room DB

    User->>HomeScreen: Select APK file
    HomeScreen->>ScanViewModel: startScan(uri, name)
    ScanViewModel->>ScanViewModel: state = PREPARING
    Note over ScanViewModel: acquire WakeLock<br/>start ForegroundService

    rect rgb(30, 41, 59)
        Note over ScanPipeline: Phase 1: Extract + Hash
        ScanPipeline->>ScanPipeline: copy APK to cache<br/>SHA256/MD5 hash<br/>XAPK detection
        ScanPipeline-->>ScanViewModel: progress(1/9, "Extracting APK")
    end

    rect rgb(30, 41, 59)
        Note over ScanPipeline,Decompiler: Phase 2: Decompile
        ScanPipeline->>Decompiler: decompile(apkFile)
        Decompiler->>Decompiler: DEX parse → smali → Java<br/>manifest decode<br/>withTimeout(120-300s)
        Decompiler-->>ScanPipeline: DecompileResult
        ScanPipeline-->>ScanViewModel: progress(2/9, "11358 classes extracted")
        Note over ScanPipeline: Phase 2.5: Process Sources<br/>join allSourceText<br/>build native lib cache<br/>WITH progress updates
        ScanPipeline-->>ScanViewModel: progress update every 500 sources
    end

    rect rgb(30, 41, 59)
        Note over ScanPipeline,Analyzers: Phase 3-8: Main Analysis
        loop Each Phase (3 through 8)
            ScanPipeline->>Analyzers: supervisorScope { async(...) }
            par All Analyzers In Phase
                Analyzers-->>ScanPipeline: List<Finding>
            end
            ScanPipeline-->>ScanViewModel: progress(N/9, "Analyzer activity...")
            ScanPipeline-->>ScanViewModel: onFinding(severity, title)
        end
    end

    rect rgb(234, 179, 8)
        Note over ScanPipeline: Phase 9: Scoring
        ScanPipeline->>Analyzers: PrivacyScorer → ThreatScorer → ThreatClassifier
        Analyzers-->>ScanPipeline: scores + classification
    end

    ScanPipeline-->>ScanViewModel: ScanResult
    ScanViewModel->>DB: insert(result)
    ScanViewModel->>ScanViewModel: state = COMPLETE
    ScanViewModel-->>HomeScreen: auto-navigate to Results
    ScanViewModel->>ScanViewModel: release WakeLock<br/>stop ForegroundService
```

### Clean Architecture Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                    UI LAYER (Jetpack Compose + Material3)        │
│  HomeScreen │ ScanScreen │ ResultsScreen │ Dashboard │ Settings │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐     ┌──────────────────┐
                    │   ScanViewModel      │     │  Room DB /        │
                    │  State Machine        │     │  DataStore        │
                    │  IDLE→PREPARING→     │     │  (Scan History)   │
                    │  SCANNING→COMPLETE    │     └──────────────────┘
                    └──────────┬──────────┘
                               │ withContext(IO)
                    ┌──────────▼──────────────────────────────────┐
                    │             ScanPipeline                     │
                    │  supervisorScope / async / awaitAll          │
                    │  Phases 1-9 → 38+ analyzers in parallel     │
                    ├──────────────────────────────────────────────┤
                    │  Cancellation: parseCancelled flag checked   │
                    │  before every phase and every 100 sources    │
                    │  OOM Guard: 5000 classes / 50MB cap          │
                    │  Per-analyzer: 45s timeout via tryAnalyze    │
                    │  Decompile: 120-300s timeout + partial return │
                    └──────────────────────────────────────────────┘
```

## Threat Scoring

| Level | Score | Criteria |
|-------|-------|----------|
| SAFE | 0–25 | No suspicious indicators |
| LOW | 26–50 | Minor concerns (debug cert, backup enabled) |
| MEDIUM | 51–65 | Several moderate indicators |
| HIGH | 66–80 | Major findings (packer, evasion) |
| CRITICAL | 81–90 | Severe threats (ransomware, banking trojan) |
| MALICIOUS | 91–100 | Confirmed malicious payload |

```
SAFE ████████████████████████████████████████████░░░░░░░░░░░░  0-25
LOW  ████████████████████████████████████████████████████████ 26-50
MED  ████████████████████████████████████████████████████████ 51-65
HIGH ████████████████████████████████████████████████████████ 66-80
CRIT ████████████████████████████████████████████████████████ 81-90
 MAL  ████████████████████████████████████████████████████████ 91-100
 ```

## Verdict Gating (False-Positive Safety)

A `MALICIOUS` verdict (score ≥ 91) is deliberately hard to reach so that legitimate,
modded, or sideloaded apps are never mislabeled as malware. This mirrors how top-tier
detectors (VirusTotal, MobSF, DREBIN) refuse to call an app malware on heuristic volume alone.

```
┌────────────────────────────────────────────────────────────────────┐
│              VERDICT GATE — False-Positive SAFETY                   │
├────────────────────────────────────────────────────────────────────┤
│  Each Finding has confidence ∈ {HIGH, MEDIUM, LOW} and ruleSource.  │
│  STRONG evidence = confidence != LOW  AND  ruleSource != "community"│
│                                                                     │
│  MALICIOUS (score >= 91) is ONLY emitted when:                      │
│     • a known-malware HASH matched (HIGH),  OR                      │
│     • >= 2 independent STRONG findings agree                       │
│                                                                     │
│  Otherwise the verdict is capped at HIGH (<= 80) — never MALICIOUS. │
│                                                                     │
│  High-fidelity malware (Keylogger / Accessibility Abuse /           │
│  Device-Admin Abuse) emits MEDIUM confidence (strong, not noisy).   │
│  Noisy heuristics (API chains, data-exfil combos, generic          │
│  anti-analysis) emit LOW confidence and can NEVER alone drive a     │
│  MALICIOUS verdict — modded / genuine apps stay capped.            │
│                                                                     │
│  Extra FP guards: known-benign obfuscation packages (e.g. Facebook  │
│  redexgen) are skipped, and the Keylogger rule requires a real IME. │
└────────────────────────────────────────────────────────────────────┘
```

```mermaid
flowchart TD
    F[Scan Findings] --> G{"\u2265 2 independent STRONG findings\nOR known-malware hash?"}
    G -- "No" --> CAP["Capped at HIGH \u2264 80\nModded / genuine apps stay safe"]
    G -- "Yes" --> M["MALICIOUS \u2265 91"]
    STRONG["STRONG = confidence != LOW\nAND ruleSource != community"] --> G
    style CAP fill:#22c55e,color:#000
    style M fill:#ef4444,color:#fff
    style STRONG fill:#1e293b,color:#fff
```

## Mod APK Detection (3-Tier)

```
┌───────────────────────────────────────────────────────────┐
│              ModApkDetector — 3-Tier Hybrid                │
├───────────────┬───────────────────┬───────────────────────┤
│   TIER 1      │     TIER 2        │      TIER 3           │
│  SOO Anomaly  │  Cross-Validation  │  Confidence Scoring   │
│               │                   │                       │
│  DEX string   │ Check if findings │ isLikelyGenuineMod(): │
│  offset order │ span multiple     │ downgrade if only     │
│  disruption   │ categories (perm, │ harmless perms +      │
│  detection    │ api, native, comp)│ known mod signers     │
└───────────────┴───────────────────┴───────────────────────┘
```

## Project Structure

```
app/src/main/java/com/apkviper/
├── App.kt                       # Application — schedules auto-update
├── MainActivity.kt              # Entry point + Compose navigation
├── data/
│   ├── AppDatabase.kt           # Room DB + Gson TypeConverters
│   ├── ScanDao.kt               # DAO: recent, timeline, package queries
│   └── SettingsDataStore.kt     # DataStore: auto-update, signature counts
├── dex/
│   ├── AxmlDecoder.kt           # Binary AndroidManifest → text
│   ├── DexParser.kt             # Custom DEX parser (string/field/method/class)
│   └── SmaliDisassembler.kt     # DEX bytecode → smali text
├── engine/
│   ├── ScanPipeline.kt          # Central orchestrator — 9 phases
│   ├── StorageCleaner.kt        # Temp file cleanup + entropy-based ranking
│   ├── advanced/                # 26 advanced analysis engines
│   ├── classification/          # ThreatClassifier
│   ├── decompile/               # DecompilerManager
│   ├── dex/                     # DexOpcodeAnalyzer
│   ├── heuristic/               # 6 heuristic detectors
│   ├── malware/                 # KnownMalwareDB, KnownGoodDB
│   ├── native/                  # FrameworkWhitelist, NativeAnalyzer
│   ├── network/                 # NetworkAnalyzer
│   ├── report/                  # PdfGenerator (real app logo, no fallbacks)
│   ├── scoring/                 # ThreatScorer, PrivacyScorer
│   ├── static/                  # 5 static analyzers
│   ├── supplychain/             # SDKAnalyzer
│   ├── taint/                   # TaintAnalyzer
│   ├── update/                  # AutoUpdateEngine, UpdateScheduler
│   ├── xapk/                    # XapkExtractor
│   └── yara/                    # YaraEngine (Aho-Corasick automaton)
├── model/
│   └── ScanModels.kt            # ScanResult, Finding, DecompileResult, enums
├── service/
│   ├── ApkFileMonitorService.kt # FileObserver: watches Downloads for APKs
│   └── ScanForegroundService.kt # BG scan notification with progress
├── ui/
│   ├── dashboard/               # History dashboard + per-package score trend
│   ├── home/                    # Main screen + tab navigation + file picker
│   ├── results/                 # Scan results with expandable finding cards
│   ├── scan/                    # ScanView: terminal + progress + ETA
│   ├── settings/                # Configuration + APK monitor toggle
│   ├── terminal/                # Terminal log models
│   └── theme/                   # Colors (copper/amber, warm surfaces), typography, theme
└── util/
    └── HashUtils.kt             # Streaming SHA256/MD5 hashing
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Kotlin 1.9.21 |
| UI | Jetpack Compose + Material3 (BOM 2024.06.00) |
| Database | Room 2.6.1 + Gson + KSP |
| Preferences | DataStore Preferences 1.0.0 |
| PDF | `android.graphics.pdf.PdfDocument` (zero external deps) |
| Async | Kotlin Coroutines 1.7.3 + Flow |
| DEX Parsing | Custom binary parser (31 KB, no deps) |
| YARA | Custom Aho-Corasick automaton (no native deps) |
| ML | Custom TinyML Random Forest (20 trees) |
| Networking | OkHttp 4.12.0 (update checks only) |
| Testing | JUnit 4.13.2 + Robolectric 4.11.1 + Espresso 3.5.1 |
| Build | AGP 8.5.0, Kotlin 1.9.21, KSP |
| SDK | compileSdk=34, targetSdk=34, minSdk=26 |

## Key Flows

### Memory-Adaptive Decompilation

```mermaid
flowchart TD
    START([Enter DecompilerManager]) --> CAP{classes > 0?}
    CAP -- Yes --> PROCESS[Process class N<br/>Parse DEX → Generate Smali/Java]
    PROCESS --> MEM{Free mem < 15% max?}
    MEM -- No --> NEXT[Increment counter]
    MEM -- Yes --> GC["System.gc()<br/>Thread.yield()"]
    GC --> CHK{counter % 200 == 0?}
    CHK -- No --> CAP
    NEXT --> CHK
    CHK -- Yes --> MEM2{Free mem < 15% max?}
    MEM2 -- No --> CAP
    MEM2 -- Yes --> TRUNC[Drop remaining classes<br/>return partial result]
    CAP -- No --> DONE([Return DecompileResult])

    style START fill:#22c55e,color:#fff
    style DONE fill:#22c55e,color:#fff
    style GC fill:#eab308,color:#000
    style TRUNC fill:#ef4444,color:#fff
```

### Dynamic Weighted ETA

```mermaid
flowchart LR
    PHASE["Phase N completes"] --> TRACK["Record actual wall-clock duration<br/>stored per-phase in phaseActualDurations[]"]
    TRACK --> WEIGHT["Sub-elapsed: (now - phaseStart) / 1000<br/>estPhase = max(subElapsed, actualDur or default)"]
    WEIGHT --> PROGRESS["timeBased = (subElapsed / estPhase) * (1/total)<br/>smooth = min(stepBased + timeBased, 1.0)"]
    PROGRESS --> ETA["Weighted ETA:<br/>remaining = Σ(actualDur or defaults)<br/>× (1 - subElapsed/estPhase)"]
    ETA --> UI["Display: '~45s remaining'"]

    style PHASE fill:#1e293b,color:#fff
    style ETA fill:#eab308,color:#000
```

### MITRE ATT&CK PDF Table Layout

```mermaid
flowchart TD
    ROW[Each row = 1 MITRE technique] --> L1["Line 1: ID + count pill + Technique name"]
    L1 --> L2["Line 2+: Description word-wrapped across N lines"]
    L2 --> H["rowH = maxOf(line1H+2, line1H+descLines*10+2)"]
    H --> COL["Columns: ID(58pt) | Technique(148pt) | Description(fill)"]
    COL --> PILL["Count pill: compact starburst<br/>fits within ID column"]
    PILL --> ALT["Alt-row shading with padding<br/>via fillRect on even rows"]
    ALT --> NEXT[next row]

    style ROW fill:#1e293b,color:#fff
    style PILL fill:#eab308,color:#000
```

## Edge Case Handling

```mermaid
flowchart TD
    subgraph "Null Safety"
        NS1["Safe calls: ?."]
        NS2["Elvis defaults: ?: ''"]
        NS3["firstOrNull > first()"]
    end
    subgraph "Memory Protection"
        MP1["5000-class / 50MB dual cap"]
        MP2["Adaptive GC every 200 classes"]
        MP3["ZipFile .use {} auto-close"]
    end
    subgraph "Cancellation Safety"
        CC1["parseCancelled checked<br/>before every phase"]
        CC2["checkCancelled() every<br/>100 sources during join"]
        CC3["buildNativeLibCache<br/>checks parseCancelled"]
    end
    subgraph "Error Resilience"
        ER1["tryAnalyze → emptyList()"]
        ER2["Phase isolation via<br/>supervisorScope"]
        ER3["Decompiler 120s timeout<br/>with partial results"]
    end

    NS1 --> MP1 --> CC1 --> ER1
    NS2 --> MP2 --> CC2 --> ER2
    NS3 --> MP3 --> CC3 --> ER3
```

| Scenario | Protection | Location |
|----------|-----------|----------|
| Empty scan history | Returns empty view, no crash | DashboardScreen.kt |
| Null taint register | `?: continue` guard (no NPE) | TaintAnalyzer.kt |
| Missing icon resource | Throws clear error at startup | PdfGenerator.kt |
| Negative notification ID | `Math.abs(name.hashCode())` | ApkFileMonitorService.kt |
| Memory pressure in decompile | `System.gc()` every 200 classes | DecompilerManager.kt |
| 5000+ classes or 50MB+ sources | Null allSourceText; sampled analyzers | ScanPipeline.kt |
| ZipFile leak | `.use {}` auto-close on exception | ScanPipeline.kt, all analyzers |
| Race on scan start | `isScanning`/`isPreparing`/`result` guards | HomeScreen.kt |
| Scan resume after kill | SharedPreferences `scan_active` checkpoint | ScanForegroundService.kt |
| WakeLock timeout | 10-minute timeout prevents battery drain | ScanViewModel.kt |
| Source join for 11K+ classes | Progress every 500 sources, cancellation every 100 | ScanPipeline.kt |
| Decompile timeout | 120s smali + 120s java timeouts with partial results | DecompilerManager.kt |

## Security

```
┌──────────────────────────────────────────────────────────┐
│                 SECURITY PROPERTIES                       │
├──────────────────────────────────────────────────────────┤
│  ✓ 100% on-device — no data ever leaves                   │
│  ✓ No network permission needed for scanning              │
│  ✓ Temp files deleted after scan via StorageCleaner       │
│  ✓ 5000-class / 50MB dual OOM guard on source joins      │
│  ✓ ZipFile .use{} — no file descriptor leaks              │
│  ✓ parseCancelled flag checked at every phase + sub-step  │
│  ✓ Foreground service preserves scan across background    │
│  ✓ Wake lock prevents CPU sleep during scan               │
│  ✓ PDF report uses real app icon only (no fallbacks)     │
│  ✓ DecompilerManager: 120s timeouts prevent hangs         │
│  ✓ ProGuard keep rules for Room entities + Gson models    │
└──────────────────────────────────────────────────────────┘
```

## License

Distributed under the MIT License. See [`LICENSE`](./LICENSE) for full text.

Copyright (c) 2026 — APK Viper

All analysis is performed on-device. No data leaves your device.
