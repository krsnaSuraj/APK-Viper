package com.apkviper.ui.results

import android.app.Application
import android.widget.Toast
import java.util.*
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.apkviper.R
import com.apkviper.data.AppDatabase
import com.apkviper.engine.report.PdfGenerator
import com.apkviper.model.*
import com.apkviper.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResultsScreen(result: ScanResult, onBack: (() -> Unit)? = null) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pdfGenerating by remember { mutableStateOf(false) }
    var severityFilter by remember { mutableStateOf<Severity?>(null) }
    val animatedScore by animateIntAsState(targetValue = result.threatScore,
        animationSpec = tween(600, easing = EaseOutCubic), label = "score")

    val scoreColor = when (result.threatLevel) {
        ThreatLevel.SAFE -> SevSafe; ThreatLevel.LOW -> SevLow
        ThreatLevel.MEDIUM -> SevMedium; ThreatLevel.HIGH -> SevHigh
        ThreatLevel.CRITICAL, ThreatLevel.MALICIOUS -> SevCritical
    }

    val filteredFindings = if (severityFilter != null) {
        result.findings.filter { it.severity == severityFilter }
    } else result.findings

    val severityGrouped = filteredFindings
        .sortedByDescending { it.severity.ordinal }
        .groupBy { it.severity }
    val severityOrder = listOf(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    val counts = severityGrouped.mapValues { it.value.size }

    val displayItems = remember(result.findings, severityFilter) {
        severityOrder.flatMap { severity ->
            val findings = severityGrouped[severity] ?: return@flatMap emptyList()
            listOf<Any>(DisplayHeader(severity, findings.size)) + findings.map { DisplayFinding(it) }
        }
    }

    val displayKey = remember(result.findings, severityFilter) {
        displayItems.mapIndexed { idx, item ->
            when (item) {
                is DisplayHeader -> "hdr_${item.severity.name}"
                is DisplayFinding -> "fc_${item.finding.severity.name}_${idx}"
                else -> ""
            }
        }
    }

    Scaffold(
        containerColor = Bg0,
        topBar = {
            if (onBack != null) {
                TopAppBar(
                    title = { Text("Analysis Report", color = TextPrimary) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = TextSecondary)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Bg1)
                )
            }
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.padding(padding).fillMaxSize().padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 80.dp)
        ) {

            // ── Verdict shelf — tight, asymmetric, score-dominant ──
            item {
                Surface(
                    color = Bg2,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(result.threatLevel.name, style = MaterialTheme.typography.headlineMedium,
                                fontWeight = FontWeight.Bold, color = scoreColor)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("${result.findings.size} findings detected",
                                style = MaterialTheme.typography.labelMedium, color = TextSecondary)
                        }

                        // Score — the dominant number
                        Column(horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.semantics { contentDescription = "Score $animatedScore out of 100" }) {
                            Text("$animatedScore", style = MaterialTheme.typography.displayLarge,
                                fontFamily = FontFamily.Default, fontWeight = FontWeight.Bold,
                                color = scoreColor, lineHeight = MaterialTheme.typography.displayLarge.lineHeight)
                            Text("/100", style = MaterialTheme.typography.labelSmall, color = TextMuted)
                        }
                    }
                }
            }

            // ── Severity heat bar — compact, tappable ──
            item {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    severityOrder.forEach { sev ->
                        val count = counts[sev] ?: 0
                        val barColor = when (sev) {
                            Severity.CRITICAL -> SevCritical; Severity.HIGH -> SevHigh
                            Severity.MEDIUM -> SevMedium; Severity.LOW -> SevLow; else -> SevSafe
                        }
                        val isActive = severityFilter == sev
                        val animatedBg by animateColorAsState(
                            targetValue = if (isActive) barColor else barColor.copy(alpha = 0.08f),
                            animationSpec = tween(120), label = "sevBg")
                        Surface(
                            onClick = { severityFilter = if (isActive) null else sev },
                            shape = RoundedCornerShape(6.dp),
                            color = animatedBg,
                            modifier = Modifier.weight(1f)
                                .semantics { contentDescription = "${sev.name}: $count findings${if (isActive) ", selected" else ""}" }
                        ) {
                            Column(modifier = Modifier.padding(vertical = 7.dp),
                                horizontalAlignment = Alignment.CenterHorizontally) {
                                Text("$count", style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isActive) Bg0 else barColor,
                                    fontFamily = FontFamily.Monospace)
                                Text(sev.name.take(4),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (isActive) Bg0.copy(alpha = 0.8f) else barColor)
                            }
                        }
                    }
                }
            }

            // ── PDF export — copper CTA, inline ──
            item {
                Button(
                    onClick = {
                        pdfGenerating = true
                        scope.launch {
                            try {
                                val pdfResult = withContext(Dispatchers.IO) { PdfGenerator(context).generate(result) }
                                if (pdfResult.success) {
                                    Toast.makeText(context, "Saved: ${pdfResult.filePath}", Toast.LENGTH_LONG).show()
                                } else {
                                    Toast.makeText(context, "Failed: ${pdfResult.error}", Toast.LENGTH_LONG).show()
                                }
                            } catch (e: Exception) {
                                Toast.makeText(context, "Failed: ${e.message}", Toast.LENGTH_SHORT).show()
                            } finally { pdfGenerating = false }
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(8.dp),
                    enabled = !pdfGenerating,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Accent, contentColor = Bg0,
                        disabledContainerColor = AccentBg, disabledContentColor = Accent.copy(alpha = 0.4f))
                ) {
                    if (pdfGenerating) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp, color = Accent.copy(alpha = 0.5f))
                        Spacer(modifier = Modifier.width(10.dp))
                        Text("Rendering report...", style = MaterialTheme.typography.labelMedium)
                    } else {
                        Text("Export PDF Report", style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            // ── Threat Classification — compact callout ──
            val classification = result.classification
            if (classification != null) {
                item(key = "classification") {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = if (result.threatScore >= 66) Danger05 else Copper05,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                            Box(modifier = Modifier.size(5.dp)
                                .offset(y = 5.dp)
                                .background(if (result.threatScore >= 66) Danger else Warning,
                                    RoundedCornerShape(2.dp)))
                            Spacer(Modifier.width(8.dp))
                            Column {
                                Text("Classification",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = if (result.threatScore >= 66) Danger else Warning)
                                Spacer(Modifier.height(4.dp))
                                Text(classification, style = MaterialTheme.typography.bodySmall,
                                    color = TextPrimary)
                            }
                        }
                    }
                }
            }

            // ── Remediation — danger callout ──
            val remediations = result.remediations
            if (remediations.isNotEmpty()) {
                item(key = "remediations") {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = Danger05,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(modifier = Modifier.size(5.dp)
                                    .background(Danger, RoundedCornerShape(2.dp)))
                                Spacer(Modifier.width(8.dp))
                                Text("Remediation",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.SemiBold, color = Danger)
                            }
                            Spacer(Modifier.height(8.dp))
                            remediations.forEachIndexed { idx, step ->
                                Text("${idx + 1}. $step",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TextPrimary,
                                    modifier = Modifier.padding(bottom = 4.dp))
                            }
                        }
                    }
                }
            }

            // ── Findings — typographic, severity-colored, copper expanded ──
            if (filteredFindings.isEmpty()) {
                item(key = "empty_state") {
                    Surface(shape = RoundedCornerShape(8.dp), color = Bg2,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                        Column(modifier = Modifier.padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally) {
                            if (result.findings.isEmpty()) {
                                Image(painter = painterResource(R.drawable.ic_launcher_foreground),
                                    contentDescription = "Clean",
                                    modifier = Modifier.size(36.dp),
                                    colorFilter = ColorFilter.tint(Safe))
                                Spacer(modifier = Modifier.height(10.dp))
                                Text("No threats detected", style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold, color = Safe)
                            } else {
                                Spacer(modifier = Modifier.height(10.dp))
                                Text("No matches in current filter",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold, color = TextMuted)
                            }
                        }
                    }
                }
            }

            items(displayItems.size, key = { index -> displayKey[index] }) { idx ->
                val item = displayItems[idx]
                when (item) {
                    is DisplayHeader -> {
                        val color = when (item.severity) {
                            Severity.CRITICAL -> SevCritical; Severity.HIGH -> SevHigh
                            Severity.MEDIUM -> SevMedium; Severity.LOW -> SevLow; else -> SevSafe
                        }
                        Row(verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(start = 4.dp, top = 4.dp)) {
                            Box(modifier = Modifier.size(5.dp).background(color, RoundedCornerShape(2.dp)))
                            Spacer(Modifier.width(8.dp))
                            Text("${item.severity.name} ${item.count}",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Medium, color = color)
                        }
                    }
                    is DisplayFinding -> ExpandableFindingCard(item.finding)
                }
            }

            // ── File info — mono + compact ──
            item {
                Surface(shape = RoundedCornerShape(8.dp), color = Bg2,
                    modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        InfoRow("Size", formatSize(result.fileSize))
                        InfoRow("Time", "${result.scanTime}ms")
                        InfoRow("SHA256", (result.sha256 ?: "N/A").take(24) + "...")
                    }
                }
            }

            item { Spacer(modifier = Modifier.height(32.dp)) }
        }
    }
}

@Composable
private fun ExpandableFindingCard(f: Finding) {
    var expanded by remember { mutableStateOf(false) }
    val severityColor = when (f.severity) {
        Severity.CRITICAL -> SevCritical; Severity.HIGH -> SevHigh
        Severity.MEDIUM -> SevMedium; Severity.LOW -> SevLow; Severity.INFO -> SevSafe
    }
    val bgColor = if (expanded) Copper05 else Bg2

    Surface(
        shape = RoundedCornerShape(6.dp),
        color = bgColor,
        modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded }
            .semantics { contentDescription = "${f.severity.name} finding: ${f.title}${if (expanded) ", expanded" else ", collapsed"}" }
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(modifier = Modifier
                    .background(severityColor.copy(alpha = 0.12f), RoundedCornerShape(4.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)) {
                    Text(f.severity.name,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold, color = severityColor,
                        fontFamily = FontFamily.Monospace)
                }
                Spacer(modifier = Modifier.width(8.dp))
                Text(f.title,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium, color = TextPrimary,
                    modifier = Modifier.weight(1f),
                    maxLines = if (expanded) Int.MAX_VALUE else 1,
                    overflow = TextOverflow.Ellipsis)
            }
            androidx.compose.animation.AnimatedVisibility(
                visible = expanded,
                enter = fadeIn(animationSpec = tween(200)) + expandVertically(animationSpec = tween(200)),
                exit = fadeOut(animationSpec = tween(150)) + shrinkVertically(animationSpec = tween(150))
            ) {
                Column {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(f.description,
                        style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Medium,
            color = TextMuted,
            modifier = Modifier.width(56.dp))
        Text(value,
            style = MonoLabel,
            color = TextSecondary)
    }
}

internal fun formatSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${bytes / 1024} KB"
    else -> String.format(Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0))
}

private class DisplayHeader(val severity: Severity, val count: Int)
private class DisplayFinding(val finding: Finding)
