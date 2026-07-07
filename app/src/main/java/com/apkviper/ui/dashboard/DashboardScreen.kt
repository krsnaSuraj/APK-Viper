package com.apkviper.ui.dashboard

import android.app.Application
import android.widget.Toast
import androidx.compose.animation.core.*
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.apkviper.R
import com.apkviper.data.AppDatabase
import com.apkviper.model.ScanResult
import com.apkviper.model.ThreatLevel
import com.apkviper.ui.results.ResultsScreen
import com.apkviper.ui.scan.ScanEventBus
import com.apkviper.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun DashboardScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val db = remember { AppDatabase.getInstance(context.applicationContext as Application) }
    val scope = rememberCoroutineScope()
    var scans by remember { mutableStateOf<List<ScanResult>>(emptyList()) }
    var total by remember { mutableIntStateOf(0) }
    var malicious by remember { mutableIntStateOf(0) }
    var avg by remember { mutableStateOf<Double?>(null) }
    var selectedScan by remember { mutableStateOf<ScanResult?>(null) }
    var showResults by remember { mutableStateOf(false) }
    var showDeleteDialog by remember { mutableStateOf<ScanResult?>(null) }
    var timeline by remember { mutableStateOf<List<ScanResult>>(emptyList()) }

    fun refresh() {
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    scans = db.scanDao().getRecent()
                    total = db.scanDao().getCount()
                    malicious = db.scanDao().getMaliciousCount()
                    avg = db.scanDao().getAverageScore()
                    timeline = db.scanDao().getTimeline()
                }
            } catch (e: Exception) {
                android.util.Log.w("Dashboard", "DB read failed", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "Failed to load history: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    LaunchedEffect(Unit) {
        refresh()
        ScanEventBus.scanCompleted.collect { refresh() }
    }

    if (showResults && selectedScan != null) {
        val scan = selectedScan
        if (scan != null) {
            ResultsScreen(result = scan, onBack = { showResults = false; selectedScan = null })
            return
        }
    }

    if (showDeleteDialog != null) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = null },
            containerColor = Bg2, titleContentColor = TextPrimary, textContentColor = TextSecondary,
            title = { Text("Delete scan?") },
            text = { Text("Remove this scan result from history?") },
            confirmButton = {
                Button(onClick = {
                    val dialog = showDeleteDialog ?: return@Button
                    scope.launch {
                        try { withContext(Dispatchers.IO) { db.scanDao().delete(dialog) } } catch (_: Exception) {}
                        showDeleteDialog = null; refresh()
                    }
                }, colors = ButtonDefaults.buttonColors(containerColor = Danger)) { Text("Delete") }
            },
            dismissButton = { OutlinedButton(onClick = { showDeleteDialog = null }) { Text("Cancel") } }
        )
    }

    Scaffold(
        containerColor = Bg0,
        topBar = {
            TopAppBar(
                title = { Text("History", style = MaterialTheme.typography.titleLarge,
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
            modifier = Modifier.padding(padding).fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {

            // ── Stat strip — monospace values, compact ──
            item {
                val animTotal by animateIntAsState(total, tween(400), label = "t")
                val animMal by animateIntAsState(malicious, tween(400), label = "m")
                val animAvg by animateIntAsState(avg?.toInt() ?: 0, tween(400), label = "a")
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    StatCard("Scans", "$animTotal", Accent, Modifier.weight(1f))
                    StatCard("Threats", "$animMal", Danger, Modifier.weight(1f))
                    StatCard("Avg Score", "$animAvg", Warning, Modifier.weight(1f))
                }
            }

            if (scans.isNotEmpty()) {
                item(key = "summary") {
                    Surface(shape = RoundedCornerShape(6.dp), color = Bg2,
                        modifier = Modifier.fillMaxWidth()) {
                        Row(modifier = Modifier.padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(4.dp).background(Accent, RoundedCornerShape(2.dp)))
                            Spacer(Modifier.width(8.dp))
                            Text("${timeline.size} total · ${scans.size} recent",
                                style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                        }
                    }
                }
            }

            if (scans.isEmpty()) {
                item {
                    Box(modifier = Modifier.fillMaxWidth().padding(48.dp),
                        contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Image(painter = painterResource(R.drawable.ic_launcher_foreground),
                                contentDescription = "Empty",
                                modifier = Modifier.size(48.dp).alpha(0.12f))
                            Spacer(modifier = Modifier.height(14.dp))
                            Text("No scans yet", style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.Medium, color = TextSecondary)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("Tap Scan to analyze your first APK",
                                style = MaterialTheme.typography.bodySmall, color = TextMuted)
                        }
                    }
                }
            }

            items(scans, key = { it.id }) { scan ->
                val color = when (scan.threatLevel) {
                    ThreatLevel.SAFE -> SevSafe; ThreatLevel.LOW -> SevLow
                    ThreatLevel.MEDIUM -> SevMedium; ThreatLevel.HIGH -> SevHigh
                    ThreatLevel.CRITICAL, ThreatLevel.MALICIOUS -> SevCritical
                }
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = Bg2,
                    modifier = Modifier.fillMaxWidth().combinedClickable(
                        onClick = { selectedScan = scan; showResults = true },
                        onLongClick = { showDeleteDialog = scan }
                    ).semantics { contentDescription = "${scan.threatLevel.name} scan: ${scan.apkName}, score ${scan.threatScore}, ${scan.findings.size} findings" }
                ) {
                    Row(modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        // Severity dot + score column
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text("${scan.threatScore}",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold, color = color,
                                fontFamily = FontFamily.Monospace)
                            Text(scan.threatLevel.name.take(4),
                                style = MaterialTheme.typography.labelSmall, color = color,
                                fontFamily = FontFamily.Monospace)
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(scan.apkName, style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Medium, color = TextPrimary, maxLines = 1)
                            Spacer(modifier = Modifier.height(2.dp))
                            Text("${scan.findings.size} findings · ${SimpleDateFormat("MMM dd, HH:mm", Locale.US).format(Date(scan.timestamp))}",
                                style = MaterialTheme.typography.labelSmall, color = TextMuted,
                                fontFamily = FontFamily.Monospace)
                        }
                    }
                }
            }

            if (scans.isNotEmpty()) {
                item {
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                try { withContext(Dispatchers.IO) { db.scanDao().deleteAll() } } catch (_: Exception) {}
                                refresh()
                                Toast.makeText(context, "History cleared", Toast.LENGTH_SHORT).show()
                            }
                        },
                        modifier = Modifier.fillMaxWidth().height(44.dp),
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextMuted),
                        border = ButtonDefaults.outlinedButtonBorder
                    ) {
                        Text("Clear all", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }

            item { Spacer(modifier = Modifier.height(16.dp)) }
        }
    }
}

@Composable
private fun StatCard(title: String, value: String, color: androidx.compose.ui.graphics.Color,
                     modifier: Modifier) {
    Surface(modifier = modifier, shape = RoundedCornerShape(8.dp), color = Bg2) {
        Column(modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally) {
            Text(value, style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold, color = color,
                fontFamily = FontFamily.Monospace)
            Spacer(modifier = Modifier.height(2.dp))
            Text(title, style = MaterialTheme.typography.labelSmall, color = TextMuted)
        }
    }
}
