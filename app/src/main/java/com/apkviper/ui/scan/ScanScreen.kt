package com.apkviper.ui.scan

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.apkviper.ui.results.ResultsScreen
import com.apkviper.ui.terminal.LineType
import com.apkviper.ui.terminal.LogEntry
import com.apkviper.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(viewModel: ScanViewModel, apkPath: String, apkName: String, onBack: () -> Unit) {
    val uiState by viewModel.uiState.collectAsState()
    var showLog by remember { mutableStateOf(false) }

    LaunchedEffect(apkPath) {
        if (apkPath.isBlank()) return@LaunchedEffect
        if (!uiState.isScanning && uiState.result == null) {
            viewModel.startScan(apkPath, apkName)
        }
    }

    val cancelled = uiState.errorMessage == "Cancelled"
    val scanResult = uiState.result

    if (uiState.scanComplete && scanResult != null && !cancelled) {
        ResultsScreen(result = scanResult, onBack = onBack)
        return
    }

    if (!uiState.isScanning && !uiState.isPreparing && !uiState.scanComplete &&
        uiState.errorMessage == null && uiState.result == null) {
        LaunchedEffect(Unit) { onBack() }
        return
    }

    if (cancelled && !uiState.isScanning) {
        LaunchedEffect(Unit) { viewModel.reset(); onBack() }
        return
    }

    val isScanning by rememberUpdatedState(uiState.isScanning)
    val progress by rememberUpdatedState(uiState.progress)
    val currentActivity by rememberUpdatedState(uiState.currentActivity)
    val currentPhase by rememberUpdatedState(uiState.currentPhase)
    val totalPhases by rememberUpdatedState(uiState.totalPhases)
    val etaSeconds by rememberUpdatedState(uiState.etaSeconds)

    Scaffold(
        containerColor = Bg0,
        topBar = {
            TopAppBar(
                title = { Text(apkName, style = MaterialTheme.typography.titleMedium, maxLines = 1, color = TextPrimary) },
                navigationIcon = {
                    IconButton(onClick = { onBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = TextSecondary)
                    }
                },
                actions = {
                    if (isScanning) {
                        TextButton(onClick = { viewModel.cancelScan() }) {
                            Text("Cancel", color = Danger, style = MaterialTheme.typography.labelMedium)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Bg1)
            )
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {

            // ── Progress lane — thin, copper, command-grade ──
            if (isScanning) {
                LinearProgressIndicator(
                    progress = { progress },
                    modifier = Modifier.fillMaxWidth().height(2.dp),
                    color = Accent,
                    trackColor = Border1
                )

                // Phase header — tight, typographic
                Row(
                    modifier = Modifier.fillMaxWidth()
                        .background(Bg1)
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(14.dp),
                        strokeWidth = 1.5.dp,
                        color = Accent,
                        trackColor = Border1
                    )
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(currentActivity, style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium, color = TextPrimary, maxLines = 1)
                        Text("Phase $currentPhase/$totalPhases · ${(progress * 100).toInt()}%",
                            style = MaterialTheme.typography.labelSmall, color = TextMuted)
                    }
                    if (etaSeconds > 0 && etaSeconds < 3600) {
                        Text(
                            if (etaSeconds < 60) "~${etaSeconds}s" else "~${etaSeconds / 60}m",
                            style = MaterialTheme.typography.labelMedium,
                            fontFamily = FontFamily.Monospace,
                            color = Accent
                        )
                    }
                }
            }

            // Findings counter — compact, pulse-colored
            val findingCount = uiState.lines.count { it.type == LineType.WARNING || it.type == LineType.DANGER }
            if (findingCount > 0) {
                Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(modifier = Modifier.size(5.dp).background(
                            if (findingCount > 5) Danger else Warning, RoundedCornerShape(2.dp)))
                        Spacer(Modifier.width(6.dp))
                        Text("$findingCount findings", style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = if (findingCount > 5) Danger else Warning)
                    }
                    TextButton(onClick = { showLog = !showLog }) {
                        Text(if (showLog) "Collapse" else "Expand",
                            style = MaterialTheme.typography.labelSmall, color = TextMuted)
                    }
                }
            }

            // ── Terminal log — monospace, compact, operational ──
            AnimatedVisibility(visible = showLog || findingCount == 0,
                enter = slideInVertically(), exit = slideOutVertically()) {
                val listState = rememberLazyListState()
                val allLines = uiState.lines
                val maxVisible = 500
                val displayLines = if (allLines.size > maxVisible) allLines.takeLast(maxVisible) else allLines
                val isTruncated = allLines.size > maxVisible

                LaunchedEffect(showLog) {
                    if (showLog && displayLines.isNotEmpty()) listState.scrollToItem(displayLines.size - 1)
                }

                LaunchedEffect(displayLines.size) {
                    if (displayLines.isNotEmpty()) {
                        val lm = listState.layoutInfo
                        val atBottom = lm.visibleItemsInfo.lastOrNull()?.index == lm.totalItemsCount - 1
                        if (atBottom) listState.animateScrollToItem(displayLines.size - 1)
                    }
                }

                if (isTruncated && !showLog) {
                    Text("${allLines.size} entries (showing last $maxVisible)",
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = TextMuted,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
                }

                LazyColumn(
                    state = listState,
                    modifier = Modifier.weight(1f).padding(horizontal = 12.dp, vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(0.5.dp)
                ) {
                    if (isTruncated) {
                        item(key = "truncated") {
                            Text("... ${allLines.size - maxVisible} earlier",
                                style = MonoLabel, color = TextMuted,
                                modifier = Modifier.padding(4.dp))
                        }
                    }
                    items(displayLines.size, key = { displayLines[it].id }) { idx ->
                        LogDot(displayLines[idx])
                    }
                    if (uiState.isScanning) {
                        item(key = "scanning_indicator") {
                            Row(modifier = Modifier.padding(6.dp), verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(modifier = Modifier.size(8.dp),
                                    strokeWidth = 1.5.dp, color = Accent)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("active", style = MonoLabel, color = TextMuted)
                            }
                        }
                    }
                }
            }

            // ── Error surface ──
            if (uiState.errorMessage != null) {
                val msg = uiState.errorMessage ?: return@Column
                Surface(color = Danger05, modifier = Modifier.fillMaxWidth().padding(12.dp),
                    shape = RoundedCornerShape(6.dp)) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Scan interrupted", style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold, color = Danger)
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(msg, style = MonoType, color = Danger.copy(alpha = 0.75f))
                    }
                }
            }

            if (!uiState.isScanning && !uiState.scanComplete) Spacer(modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun LogDot(entry: LogEntry) {
    val tint = when (entry.type) {
        LineType.SUCCESS -> Safe
        LineType.WARNING -> Warning
        LineType.DANGER -> Danger
        LineType.INFO -> Accent
        else -> TextMuted
    }
    Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 2.dp, vertical = 1.dp),
        verticalAlignment = Alignment.Top) {
        Box(modifier = Modifier.size(4.dp).offset(y = 5.dp)
            .background(tint, RoundedCornerShape(2.dp)))
        Spacer(modifier = Modifier.width(6.dp))
        Text(entry.text,
            style = MonoType,
            color = if (entry.type == LineType.DANGER) Danger else TextSecondary)
    }
}
