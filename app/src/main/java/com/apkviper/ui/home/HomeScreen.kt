package com.apkviper.ui.home

import android.app.Application
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.widget.Toast
import com.apkviper.MainActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DateRange
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.apkviper.R
import com.apkviper.ui.dashboard.DashboardScreen
import com.apkviper.ui.scan.ScanScreen
import com.apkviper.ui.scan.ScanViewModel
import com.apkviper.ui.settings.SettingsScreen
import com.apkviper.ui.theme.*

private val ALL_FILES = arrayOf("*/*")

@Composable
fun HomeScreen(modifier: Modifier = Modifier) {
    var selectedTab by remember { mutableIntStateOf(0) }
    var scanPath by remember { mutableStateOf<String?>(null) }
    var scanName by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current
    val app = context.applicationContext as Application

    val scanViewModel = remember { ScanViewModel(app) }
    val scanState by scanViewModel.uiState.collectAsState()

    val activity = context as? MainActivity
    LaunchedEffect(activity?.observableIntent?.value) {
        val intent = activity?.observableIntent?.value ?: activity?.intent ?: return@LaunchedEffect
        val tab = intent.getIntExtra("navigate_tab", -1)
        if (tab in 0..2) {
            selectedTab = tab
            val path = intent.getStringExtra("scan_path")
            val name = intent.getStringExtra("scan_name")
            if (!path.isNullOrBlank() && !name.isNullOrBlank()) {
                if (scanState.isScanning || scanState.isPreparing) return@LaunchedEffect
                if (scanState.result != null && path == scanState.apkPath) return@LaunchedEffect
                val prefs = context.getSharedPreferences("scan_checkpoint", android.content.Context.MODE_PRIVATE)
                if (prefs.getBoolean("scan_active", false)) {
                    prefs.edit().clear().apply()
                    return@LaunchedEffect
                }
                scanPath = path
                scanName = name
                scanViewModel.startScan(path, name)
            }
        }
    }
    var showStopDialog by remember { mutableStateOf(false) }

    BackHandler(enabled = (scanState.isScanning || scanState.scanComplete) && selectedTab == 0) {
        if (scanState.isScanning) showStopDialog = true
        else { scanViewModel.reset(); scanPath = null; scanName = null }
    }

    LaunchedEffect(scanState.errorMessage) {
        if (scanState.errorMessage == "Cancelled") {
            scanViewModel.reset()
            scanPath = null
            scanName = null
        }
    }

    if (showStopDialog) {
        AlertDialog(
            onDismissRequest = { showStopDialog = false },
            title = { Text("Stop scan?") },
            text = { Text("Scan is in progress. Stop and go back?") },
            confirmButton = {
                TextButton(onClick = {
                    scanViewModel.cancelScan()
                    showStopDialog = false
                }) { Text("Stop", color = Danger) }
            },
            dismissButton = {
                TextButton(onClick = { showStopDialog = false }) { Text("Continue scan") }
            }
        )
    }

    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri?.let {
            val name = getFileNameFromUri(context, it) ?: it.lastPathSegment ?: "unknown"
            val ext = name.substringAfterLast('.', "").lowercase()
            if (ext != "apk") { Toast.makeText(context, "Only APK files are supported", Toast.LENGTH_SHORT).show(); return@let }
            try { context.contentResolver.takePersistableUriPermission(it, Intent.FLAG_GRANT_READ_URI_PERMISSION) } catch (_: SecurityException) {}
            scanPath = it.toString(); scanName = name
            scanViewModel.startScan(it.toString(), scanName ?: "unknown.apk")
        }
    }

    val xapkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri?.let {
            val name = getFileNameFromUri(context, it) ?: it.lastPathSegment ?: "unknown"
            val ext = name.substringAfterLast('.', "").lowercase()
            if (ext != "xapk") { Toast.makeText(context, "Only XAPK files are supported", Toast.LENGTH_SHORT).show(); return@let }
            try { context.contentResolver.takePersistableUriPermission(it, Intent.FLAG_GRANT_READ_URI_PERMISSION) } catch (_: SecurityException) {}
            scanPath = it.toString(); scanName = name
            scanViewModel.startScan(it.toString(), scanName ?: "unknown.xapk")
        }
    }

    Scaffold(
        modifier = modifier,
        containerColor = Bg0,
        bottomBar = {
            NavigationBar(containerColor = Bg1, tonalElevation = 0.dp) {
                NavigationBarItem(selected = selectedTab == 0, onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.AutoMirrored.Filled.List, "Home", tint = if (selectedTab == 0) Accent else TextMuted) },
                    label = { Text("Home", style = MaterialTheme.typography.labelSmall) },
                    colors = NavigationBarItemDefaults.colors(selectedTextColor = Accent, unselectedTextColor = TextMuted, indicatorColor = AccentBg))
                NavigationBarItem(selected = selectedTab == 1, onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Default.DateRange, "History", tint = if (selectedTab == 1) Accent else TextMuted) },
                    label = { Text("History", style = MaterialTheme.typography.labelSmall) },
                    colors = NavigationBarItemDefaults.colors(selectedTextColor = Accent, unselectedTextColor = TextMuted, indicatorColor = AccentBg))
                NavigationBarItem(selected = selectedTab == 2, onClick = { selectedTab = 2 },
                    icon = { Icon(Icons.Default.Settings, "Settings", tint = if (selectedTab == 2) Accent else TextMuted) },
                    label = { Text("Settings", style = MaterialTheme.typography.labelSmall) },
                    colors = NavigationBarItemDefaults.colors(selectedTextColor = Accent, unselectedTextColor = TextMuted, indicatorColor = AccentBg))
            }
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            Crossfade(targetState = selectedTab, animationSpec = tween(200), label = "tabCrossfade") { tab ->
                when (tab) {
                0 -> {
                    val p = scanPath ?: scanState.apkPath.ifEmpty { null }
                    if (scanState.isScanning || scanState.isPreparing || scanState.scanComplete || scanState.errorMessage != null) {
                        if (p != null || scanState.result != null) {
                            ScanScreen(viewModel = scanViewModel,
                                apkPath = scanPath ?: scanState.apkPath,
                                apkName = scanName ?: scanState.apkName.ifEmpty { "unknown.apk" },
                                onBack = { scanViewModel.reset(); scanPath = null; scanName = null })
                        } else {
                            HomeTab(onScanApk = { apkPicker.launch(ALL_FILES) }, onScanXapk = { xapkPicker.launch(ALL_FILES) })
                        }
                    } else {
                        HomeTab(onScanApk = { apkPicker.launch(ALL_FILES) }, onScanXapk = { xapkPicker.launch(ALL_FILES) })
                    }
                }
                1 -> DashboardScreen(onBack = { selectedTab = 0 })
                2 -> SettingsScreen(onBack = { selectedTab = 0 })
                }
            }

            if (scanState.isScanning || scanState.isPreparing) {
                ScanOverlay(isPreparing = scanState.isPreparing, progress = scanState.progress,
                    onClick = { selectedTab = 0 }, modifier = Modifier.align(Alignment.BottomCenter).padding(8.dp))
            }
        }
    }
}

private fun getFileNameFromUri(context: android.content.Context, uri: Uri): String? {
    var name: String? = null
    context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
        val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (nameIndex >= 0 && cursor.moveToFirst()) name = cursor.getString(nameIndex)
    }
    return name
}

@Composable
private fun HomeTab(onScanApk: () -> Unit, onScanXapk: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp).verticalScroll(rememberScrollState())) {

        // ── Header: logo + identity, flush left ──
        Spacer(modifier = Modifier.height(40.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Image(painter = painterResource(R.drawable.ic_launcher_foreground),
                contentDescription = "APK Viper", modifier = Modifier.size(48.dp))
            Spacer(modifier = Modifier.width(12.dp))
            Column {
                Text("APK Viper", style = MaterialTheme.typography.headlineLarge, color = TextPrimary)
                Text("On-Device Threat Analysis", style = MaterialTheme.typography.labelMedium, color = Accent,
                    letterSpacing = MaterialTheme.typography.labelMedium.letterSpacing)
            }
        }

        // ── Accent glow line ──
        Spacer(modifier = Modifier.height(16.dp))
        Box(modifier = Modifier.fillMaxWidth().height(2.dp).background(
            Brush.horizontalGradient(listOf(Accent, Accent.copy(alpha = 0.05f)))))

        Spacer(modifier = Modifier.height(32.dp))

        // ── Command Panel — scan actions ──
        Surface(shape = RoundedCornerShape(10.dp), color = Bg2, modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(18.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(modifier = Modifier.size(6.dp).background(Accent, RoundedCornerShape(3.dp)))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("New Scan", style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold, color = Accent,
                        letterSpacing = MaterialTheme.typography.labelMedium.letterSpacing)
                }
                Spacer(modifier = Modifier.height(14.dp))

                Button(
                    onClick = onScanApk,
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Bg0),
                    elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp)
                ) { Text("Scan APK File", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold) }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedButton(
                    onClick = onScanXapk,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary),
                    border = ButtonDefaults.outlinedButtonBorder.copy(brush = androidx.compose.ui.graphics.SolidColor(Border1))
                ) { Text("Scan XAPK File", style = MaterialTheme.typography.titleSmall) }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))

        // ── Detection engines — mirrors the real 9-phase / 38+ engine pipeline ──
        Surface(shape = RoundedCornerShape(10.dp), color = Bg2, modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(modifier = Modifier.size(5.dp).background(Accent, RoundedCornerShape(2.dp)))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Detection Pipeline", style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold, color = Accent)
                }
                Spacer(modifier = Modifier.height(12.dp))
                EngineLine("Manifest & Permission Analysis", "Parses AndroidManifest for exported components, dangerous permissions, and privilege-escalation surfaces; flags debuggable builds, missing protections, and over-broad exports.")
                EngineLine("Certificate & Signing Analysis", "Inspects APK signing certificates for debug/test keys, weak algorithms (MD5/SHA1), expiry, self-signed and repackaged signatures via deep META-INF inspection.")
                EngineLine("DEX / Smali / Java Decompilation", "A custom binary DEX parser reconstructs smali and Java stubs, resolves string/field/method tables, and decodes the binary AXML manifest — fully on-device, no external tools or network.")
                EngineLine("Opcode & Structural Analysis", "DexOpcodeAnalyzer and CfgStructuralAnalyzer examine bytecode patterns, control-flow graphs, and N-gram sequences for obfuscation, packing, and anti-analysis stubs.")
                EngineLine("Static Code, String & Secret Scanning", "CodeAnalyzer, StringExtractor, and SecretLeakScanner hunt hardcoded API keys, tokens, credentials, and suspicious code patterns across all decompiled sources.")
                EngineLine("Heuristic Behavioral Detection", "Pattern-based analysis for crypto-miners, keyloggers, SMS/call abuse, clipboard interception, credential harvesting, and accessibility / device-admin abuse.")
                EngineLine("YARA Signatures & Known Malware Hash DB", "Auto-updated community YARA rules plus a cryptographic hash blocklist catch known malware families, trojans, ransomware, and spyware by pattern and signature.")
                EngineLine("Native Library (.so) Analysis", "Scans embedded shared libraries for suspicious imports, process-injection primitives, privilege-escalation chains, rootkit behavior, VM/emulator detection, and packed or encrypted payload stubs.")
                EngineLine("Taint / Data-Flow & API Call-Graph", "TaintAnalyzer and ApiCallGraphAnalyzer track sensitive data flows (SMS, contacts, location, mic/camera) to network sinks and detect dangerous API call chains.")
                EngineLine("Anti-Evasion, Threat Intel & MITRE ATT&CK", "AntiEvasionDetector and ThreatIntelDB cross-reference C2 IPs/domains; every finding is mapped to MITRE ATT&CK Mobile technique IDs.")
                EngineLine("ML Random Forest + Privacy & Threat Scoring", "A 10-feature random-forest classifier with PrivacyScorer and ThreatClassifier produce a calibrated threat score, privacy rating, and final classification with remediation.")
                EngineLine("Mod APK & Environment Detection", "ModApkDetector, PhishingOverlayAnalyzer, ShizukuDetector, VirtualAppDetector, and AccessibilityChainAnalyzer identify repackaged/modded apps, overlay phishing, virtual environments, and accessibility-abuse chains.")
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        // ── Status line ──
        Box(modifier = Modifier.fillMaxWidth().height(1.dp).background(Border1))
        Spacer(modifier = Modifier.height(12.dp))
        Row(modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
            verticalAlignment = Alignment.CenterVertically) {
            Box(modifier = Modifier.size(5.dp).background(Safe, RoundedCornerShape(2.dp)))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Offline · On-device · Zero telemetry", style = MaterialTheme.typography.labelSmall,
                color = TextMuted, letterSpacing = MaterialTheme.typography.labelSmall.letterSpacing)
        }
    }
}

@Composable
private fun EngineLine(title: String, desc: String) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(modifier = Modifier.size(4.dp).background(Accent.copy(alpha = 0.4f), RoundedCornerShape(2.dp)))
            Spacer(modifier = Modifier.width(8.dp))
            Text(title, style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.SemiBold, color = TextPrimary)
        }
        Spacer(modifier = Modifier.height(2.dp))
        Text(desc, style = MaterialTheme.typography.labelSmall, color = TextSecondary,
            modifier = Modifier.padding(start = 12.dp))
    }
}

@Composable
private fun ScanOverlay(isPreparing: Boolean, progress: Float, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier.clickable(onClick = onClick),
        color = AccentBg,
        shape = RoundedCornerShape(20.dp),
        shadowElevation = 0.dp
    ) {
        Row(modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(
                modifier = Modifier.size(18.dp),
                progress = { if (isPreparing) 0f else progress },
                strokeWidth = 2.dp, color = Accent,
                trackColor = Accent.copy(alpha = 0.15f))
            Spacer(Modifier.width(10.dp))
            Text(
                text = if (isPreparing) "Analyzing..." else "${(progress * 100).toInt()}%",
                style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Medium, color = Accent)
        }
    }
}
