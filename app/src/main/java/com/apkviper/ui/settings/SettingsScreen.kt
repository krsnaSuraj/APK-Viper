package com.apkviper.ui.settings

import android.app.Application
import android.content.Context
import android.app.ActivityManager
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.apkviper.BuildConfig
import com.apkviper.data.AppDatabase
import com.apkviper.data.SettingsDataStore
import com.apkviper.engine.StorageCleaner
import com.apkviper.engine.advanced.ThreatIntelDB
import com.apkviper.engine.update.AutoUpdateEngine
import com.apkviper.service.ApkFileMonitorService
import com.apkviper.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val app = LocalContext.current.applicationContext as Application
    val scope = rememberCoroutineScope()
    val settings = remember { SettingsDataStore(app) }
    val autoUpdate by settings.autoUpdate.collectAsState(initial = true)
    val lastUpdate by settings.lastUpdateTimestamp.collectAsState(initial = 0L)
    val yaraCount by settings.yaraRuleCount.collectAsState(initial = 0L)
    val hashCount by settings.hashDbSize.collectAsState(initial = 0L)
    val ipCount by settings.intelIpCount.collectAsState(initial = 0L)
    val domainCount by settings.intelDomainCount.collectAsState(initial = 0L)
    var showClearDialog by remember { mutableStateOf(false) }
    var showCleanerDialog by remember { mutableStateOf(false) }
    val cleaner = remember { StorageCleaner(app) }
    var updating by remember { mutableStateOf(false) }
    var apkMonitor by remember { mutableStateOf(false) }
    var toast by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        val am = app.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        apkMonitor = am.getRunningServices(Int.MAX_VALUE).any {
            it.service.className == ApkFileMonitorService::class.java.name
        }
    }

    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            containerColor = Bg2, titleContentColor = TextPrimary, textContentColor = TextSecondary,
            title = { Text("Clear all scans?") },
            text = { Text("This removes every past scan result and cannot be undone.") },
            confirmButton = {
                Button(onClick = {
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { AppDatabase.getInstance(app).scanDao().deleteAll() }
                            toast = "History cleared"
                        } catch (e: Exception) { toast = "Clear failed: ${e.message}" }
                        showClearDialog = false
                    }
                }, colors = ButtonDefaults.buttonColors(containerColor = Danger)) { Text("Clear") }
            },
            dismissButton = { OutlinedButton(onClick = { showClearDialog = false }) { Text("Cancel") } }
        )
    }

    if (showCleanerDialog) {
        AlertDialog(
            onDismissRequest = { showCleanerDialog = false },
            containerColor = Bg2, titleContentColor = TextPrimary, textContentColor = TextSecondary,
            title = { Text("Clean temp files?") },
            text = { Text("Removes old scan extracts, temp files, stale logs, and orphaned cache data. Scan history is not affected.") },
            confirmButton = {
                Button(onClick = {
                    scope.launch {
                        val result = withContext(Dispatchers.IO) { cleaner.clean() }
                        showCleanerDialog = false
                        toast = if (result.deletedFiles == 0) "Nothing to clean"
                        else "Cleaned ${result.deletedFiles} files, ${cleaner.formatBytes(result.freedBytes)}"
                    }
                }, colors = ButtonDefaults.buttonColors(containerColor = Accent)) { Text("Clean") }
            },
            dismissButton = { OutlinedButton(onClick = { showCleanerDialog = false }) { Text("Cancel") } }
        )
    }

    Scaffold(
        containerColor = Bg0,
        topBar = {
            TopAppBar(
                title = { Text("Settings", style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold, color = TextPrimary) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = TextSecondary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Bg1)
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.padding(padding).fillMaxSize().padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(vertical = 16.dp)
        ) {
            // ── Signatures & Updates ──
            item(key = "updates") {
                Surface(shape = RoundedCornerShape(10.dp), color = Bg2) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        SectionTitle("Signatures & Updates")
                        Spacer(Modifier.height(4.dp))
                        Text("Auto-download YARA rules, malware hashes, and threat intel every 6 hours.",
                            style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        Spacer(Modifier.height(12.dp))

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("Auto-Update", style = MaterialTheme.typography.bodySmall,
                                color = TextPrimary, modifier = Modifier.weight(1f))
                            Switch(
                                checked = autoUpdate,
                                onCheckedChange = { scope.launch { settings.setAutoUpdate(it) } },
                                colors = SwitchDefaults.colors(
                                    checkedTrackColor = Accent, uncheckedTrackColor = Border1,
                                    checkedThumbColor = TextPrimary, uncheckedThumbColor = Border2)
                            )
                        }

                        Spacer(Modifier.height(8.dp))
                        val dateStr = if (lastUpdate > 0) SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(lastUpdate)) else "Never"
                        Row {
                            Text("Last: ", style = MaterialTheme.typography.labelSmall, color = TextMuted)
                            Text(dateStr, style = MonoLabel, color = TextMuted)
                        }
                        Row {
                            Text("Rules: ", style = MaterialTheme.typography.labelSmall, color = TextMuted)
                            Text("YARA $yaraCount · Hashes $hashCount · IPs $ipCount · Domains $domainCount",
                                style = MonoLabel, color = TextMuted)
                        }

                        Spacer(Modifier.height(10.dp))
                        OutlinedButton(
                            onClick = {
                                updating = true
                                scope.launch {
                                    try {
                                        val result = withContext(Dispatchers.IO) { AutoUpdateEngine(app).checkAndUpdate() }
                                        settings.updateSignatureStatus(
                                            result.yaraRuleCount.toLong(), result.hashCount.toLong(),
                                            ThreatIntelDB.getIpCount().toLong(), ThreatIntelDB.getDomainCount().toLong())
                                        val parts = mutableListOf<String>()
                                        if (result.yaraRuleCount > 0) parts.add("${result.yaraRuleCount} YARA rules")
                                        if (result.hashCount > 0) parts.add("${result.hashCount} hashes")
                                        if (result.intelCount > 0) parts.add("${result.intelCount} intel")
                                        toast = "Updated: ${parts.joinToString(", ")}"
                                    } catch (e: Exception) { toast = "Update failed: ${e.message}" }
                                    finally { updating = false }
                                }
                            },
                            modifier = Modifier.fillMaxWidth().height(44.dp),
                            shape = RoundedCornerShape(6.dp),
                            enabled = !updating,
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Accent),
                            border = ButtonDefaults.outlinedButtonBorder.copy(
                                brush = androidx.compose.ui.graphics.SolidColor(Border1))
                        ) { Text(if (updating) "Updating..." else "Update Now", fontWeight = FontWeight.Medium) }

                        if (updating) {
                            Spacer(Modifier.height(6.dp))
                            LinearProgressIndicator(
                                modifier = Modifier.fillMaxWidth(),
                                color = Accent, trackColor = Border1)
                        }
                    }
                }
            }

            // ── Services ──
            item(key = "services") {
                Surface(shape = RoundedCornerShape(10.dp), color = Bg2) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        SectionTitle("Services")
                        Spacer(Modifier.height(8.dp))

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("APK File Monitor", style = MaterialTheme.typography.bodySmall,
                                    color = TextPrimary)
                                Text("Watch Downloads folder for new APK files",
                                    style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                            }
                            Switch(
                                checked = apkMonitor,
                                onCheckedChange = { enabled ->
                                    apkMonitor = enabled
                                    if (enabled) { ApkFileMonitorService.start(app) }
                                    else { app.stopService(android.content.Intent(app, ApkFileMonitorService::class.java)) }
                                },
                                colors = SwitchDefaults.colors(
                                    checkedTrackColor = Accent, uncheckedTrackColor = Border1,
                                    checkedThumbColor = TextPrimary, uncheckedThumbColor = Border2)
                            )
                        }
                    }
                }
            }

            // ── Data Management ──
            item(key = "data") {
                Surface(shape = RoundedCornerShape(10.dp), color = Bg2) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        SectionTitle("Data Management")
                        Spacer(Modifier.height(8.dp))

                        OutlinedButton(
                            onClick = { showClearDialog = true },
                            modifier = Modifier.fillMaxWidth().height(44.dp),
                            shape = RoundedCornerShape(6.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Danger),
                            border = ButtonDefaults.outlinedButtonBorder.copy(
                                brush = androidx.compose.ui.graphics.SolidColor(Border1))
                        ) {
                            Box(Modifier.size(4.dp).background(Danger, RoundedCornerShape(2.dp)))
                            Spacer(Modifier.width(8.dp))
                            Text("Clear scan history", fontWeight = FontWeight.Medium,
                                style = MaterialTheme.typography.labelSmall)
                        }

                        Spacer(Modifier.height(8.dp))

                        OutlinedButton(
                            onClick = { showCleanerDialog = true },
                            modifier = Modifier.fillMaxWidth().height(44.dp),
                            shape = RoundedCornerShape(6.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary),
                            border = ButtonDefaults.outlinedButtonBorder.copy(
                                brush = androidx.compose.ui.graphics.SolidColor(Border1))
                        ) {
                            Box(Modifier.size(4.dp).background(Accent, RoundedCornerShape(2.dp)))
                            Spacer(Modifier.width(8.dp))
                            Text("Clean temp files", fontWeight = FontWeight.Medium,
                                style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }

            // ── About ──
            item(key = "about") {
                Surface(shape = RoundedCornerShape(10.dp), color = Bg2) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        SectionTitle("About")
                        Spacer(Modifier.height(6.dp))
                        Text("APK Viper", style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.SemiBold, color = TextPrimary)
                        Text("Version ${BuildConfig.VERSION_NAME} (build ${BuildConfig.VERSION_CODE})",
                            style = MonoLabel, color = TextMuted)
                        Spacer(Modifier.height(4.dp))
                        Text("On-device threat diagnostics with auto-updating signatures. Multi-engine detection: YARA, ML, heuristics, taint analysis, threat intel, and MITRE ATT&CK mapping.",
                            style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                }
            }

            // ── Toast ──
            toast?.let { msg ->
                item(key = "toast") {
                    var visible by remember { mutableStateOf(false) }
                    LaunchedEffect(msg) { visible = true; delay(3500); visible = false; delay(500); toast = null }
                    androidx.compose.animation.AnimatedVisibility(
                        visible = visible,
                        enter = androidx.compose.animation.fadeIn(animationSpec = tween(200)) +
                                androidx.compose.animation.expandVertically(animationSpec = tween(200)),
                        exit = androidx.compose.animation.fadeOut(animationSpec = tween(200)) +
                                androidx.compose.animation.shrinkVertically(animationSpec = tween(200))
                    ) {
                        Surface(shape = RoundedCornerShape(6.dp), color = Copper05,
                            modifier = Modifier.fillMaxWidth()) {
                            Text(msg, modifier = Modifier.padding(12.dp),
                                style = MaterialTheme.typography.labelSmall, color = Accent)
                        }
                    }
                }
            }

            item(key = "spacer") { Spacer(Modifier.height(24.dp)) }
        }
    }
}

@Composable
private fun SectionTitle(title: String) {
    Text(title, style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.SemiBold, color = TextPrimary)
}
