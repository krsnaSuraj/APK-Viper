package com.apkviper.engine.report

import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import com.apkviper.R
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.ScanResult
import com.apkviper.model.Severity
import com.apkviper.model.ThreatLevel
import java.io.File
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

data class PdfResult(
    val success: Boolean,
    val filePath: String?,
    val uri: Uri? = null,
    val error: String? = null
)

data class MitreTechnique(
    val id: String,
    val name: String,
    val description: String,
    val findingCount: Int
)

class PdfGenerator(private val context: Context) {
    private val lock = Any()
    private var headerLogo: Bitmap? = null

    fun generate(result: ScanResult): PdfResult {
        val safeName = result.apkName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val fileName = "APKViper_${safeName}_${System.currentTimeMillis()}.pdf"
        var error: String? = null
        try { val r = saveViaMediaStore(fileName, result); if (r.success) return r
        } catch (e: Exception) { error = e.message }
        try { val r = saveViaFileDownload(fileName, result); if (r.success) return r
        } catch (e: Exception) { error = e.message }
        try { val r = saveToCache(fileName, result); if (r.success) return r
        } catch (e: Exception) { error = e.message }
        return PdfResult(false, null, error = error ?: "PDF generation failed")
    }

    private fun saveViaMediaStore(fileName: String, result: ScanResult): PdfResult {
        val uri: Uri
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, fileName)
                put(MediaStore.Downloads.MIME_TYPE, "application/pdf")
                put(MediaStore.Downloads.RELATIVE_PATH, "Download")
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw Exception("Failed to create MediaStore entry")
            context.contentResolver.openOutputStream(uri)?.use { out ->
                synchronized(lock) {
                    val doc = PdfDocument()
                    try { writePdfContent(doc, result); doc.writeTo(out) } finally { doc.close() }
                }
            } ?: throw Exception("Failed to open output stream")
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            context.contentResolver.update(uri, values, null, null)
        } else {
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val file = File(downloadsDir, fileName)
            file.outputStream().use { out ->
                synchronized(lock) {
                    val doc = PdfDocument()
                    try { writePdfContent(doc, result); doc.writeTo(out) } finally { doc.close() }
                }
            }
            uri = Uri.fromFile(file)
        }
        return PdfResult(true, "Downloads/$fileName", uri)
    }

    private fun saveViaFileDownload(fileName: String, result: ScanResult): PdfResult {
        val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val file = File(downloadsDir, fileName)
        file.outputStream().use { out ->
            synchronized(lock) {
                val doc = PdfDocument()
                try { writePdfContent(doc, result); doc.writeTo(out) } finally { doc.close() }
            }
        }
        return PdfResult(true, file.absolutePath)
    }

    private fun saveToCache(fileName: String, result: ScanResult): PdfResult {
        val cacheDir = File(context.cacheDir, "reports")
        cacheDir.mkdirs()
        val file = File(cacheDir, fileName)
        file.outputStream().use { out ->
            synchronized(lock) {
                val doc = PdfDocument()
                try { writePdfContent(doc, result); doc.writeTo(out) } finally { doc.close() }
            }
        }
        return PdfResult(true, file.absolutePath)
    }

    private fun displayScanMode(mode: String): String = when (mode.lowercase()) {
        "brutal" -> "Full Scan"
        "deep" -> "Deep Scan"
        "quick" -> "Quick Analysis"
        else -> mode
    }

    // ── Constants ─────────────────────────────────────────────────
    private val PW = 595f
    private val PH = 842f
    private val PI_W = 595; private val PI_H = 842
    private val M = 36f
    private val CW = PW - M * 2
    private val TOP_BAR = 48f
    private val TOP_Y = TOP_BAR + 14f
    private val BOT_Y = 812f
    private val MAX_BASELINE = 790f

    // Brand Navy
    private val NAVY = 0xFF0F172A.toInt()
    private val SLATE_800 = 0xFF1E293B.toInt()
    private val SLATE_700 = 0xFF334155.toInt()
    private val SLATE_200 = 0xFFE2E8F0.toInt()
    private val SLATE_100 = 0xFFF1F5F9.toInt()
    private val RED = 0xFFEF4444.toInt()
    private val ORANGE = 0xFFF97316.toInt()
    private val AMBER = 0xFFEAB308.toInt()
    private val BLUE = 0xFF3B82F6.toInt()
    private val GREEN = 0xFF22C55E.toInt()
    private val WHITE = 0xFFFFFFFF.toInt()
    private val TEAL = 0xFF14B8A6.toInt()
    private val DARK = 0xFF0F172A.toInt()
    private val MED = 0xFF475569.toInt()
    private val LIGHT = 0xFF94A3B8.toInt()
    private val ROW_ALT = 0xFFF8FAFC.toInt()

    private fun getOrCreateHeaderLogo(): Bitmap {
        if (headerLogo == null) {
            val bg = androidx.appcompat.content.res.AppCompatResources.getDrawable(context, R.drawable.ic_launcher_background)
            val fg = androidx.appcompat.content.res.AppCompatResources.getDrawable(context, R.drawable.ic_launcher_foreground)
            if (bg == null || fg == null) throw IllegalStateException("App icon resources not found")
            // Render at 1024x1024 for sharp scaling on all display sizes
            val s = 1024
            val bmp = Bitmap.createBitmap(s, s, Bitmap.Config.ARGB_8888)
            val c = android.graphics.Canvas(bmp)
            bg.setBounds(0, 0, s, s)
            bg.draw(c)
            fg.setBounds(0, 0, s, s)
            fg.draw(c)
            headerLogo = bmp
        }
        return headerLogo!!
    }

    // ── Document context ──────────────────────────────────────────

    private inner class DocCtx(
        val doc: PdfDocument,
        var page: PdfDocument.Page,
        var c: android.graphics.Canvas,
        var p: Paint,
        var y: Float,
        var num: Int
    )

    // ── Helpers ───────────────────────────────────────────────────

    private fun lineHeight(sz: Float): Float = sz * 1.45f

    private fun brk(ctx: DocCtx, need: Float) {
        if (ctx.y + need > MAX_BASELINE) {
            drawFooter(ctx)
            ctx.doc.finishPage(ctx.page)
            val info = PdfDocument.PageInfo.Builder(PI_W, PI_H, 1).create()
            ctx.page = ctx.doc.startPage(info)
            ctx.c = ctx.page.canvas
            ctx.y = TOP_Y
            ctx.num++
            drawHeader(ctx, null)
        }
    }

    private fun wrap(ctx: DocCtx, text: String, x: Float, maxW: Float, sz: Float, color: Int, gap: Float = 0f) {
        val lines = wrapText(text, maxW, sz, ctx.p)
        val lh = lineHeight(sz)
        for (line in lines) {
            brk(ctx, lh + gap)
            ctx.p.apply { this.color = color; textSize = sz; typeface = Typeface.DEFAULT }
            ctx.c.drawText(line, x, ctx.y, ctx.p)
            ctx.y += lh + gap
        }
    }

    // ── Document structure ────────────────────────────────────────

    private fun writePdfContent(document: PdfDocument, result: ScanResult) {
        val paint = Paint(Paint.ANTI_ALIAS_FLAG)

        // ── Page 1: Cover ──
        val coverInfo = PdfDocument.PageInfo.Builder(PI_W, PI_H, 1).create()
        val coverPage = document.startPage(coverInfo)
        drawCover(coverPage.canvas, paint, result)
        document.finishPage(coverPage)

        // ── Page 2+: Report body ──
        val info = PdfDocument.PageInfo.Builder(PI_W, PI_H, 1).create()
        val page = document.startPage(info)
        val ctx = DocCtx(document, page, page.canvas, paint, TOP_Y, 2)
        drawHeader(ctx, "Executive Summary")

        val grp = result.findings.groupBy { it.severity }
        drawExecutiveSummary(ctx, result)
        drawSeverityBreakdown(ctx, grp)

        brk(ctx, 30f)
        drawSectionDivider(ctx)
        drawMitre(ctx, result)

        brk(ctx, 30f)
        drawSectionDivider(ctx)
        drawRemediation(ctx, result)

        brk(ctx, 30f)
        drawSectionDivider(ctx)
        drawFileAnalysis(ctx, result)

        drawFooter(ctx)
        document.finishPage(ctx.page)

        // ── Findings detail pages — group identical titles, cap at 100 per severity ──
        val order = listOf(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        for (s in order) {
            val rawFindings = grp[s] ?: continue
            // Group identical titles — show count instead of 5000 individual pages
            val grouped = rawFindings.groupBy { it.title }
                .map { (_, items) ->
                    if (items.size == 1) items.first()
                    else items.first().copy(
                        description = "${items.size} occurrences — ${items.first().description}",
                        details = if (items.size > 1) items.joinToString("\n") { f ->
                            "  ${f.file ?: ""} ${if (f.line != null) "line ${f.line}" else ""} | ${f.description}"
                        }.take(500) else items.first().details
                    )
                }
            val capped = if (grouped.size > 100) {
                grouped.take(100) + Finding(
                    category = FindingCategory.CODE, severity = s,
                    title = "${grouped.size - 100} more findings (summary)",
                    description = "${rawFindings.size} total findings in ${grouped.size} unique titles — showing first 100. Full results available in-app."
                )
            } else grouped
            drawFindingsPage(ctx, result, capped, s)
        }

        // ── Back page ──
        drawBackPage(ctx)
    }

    // ── COVER PAGE ────────────────────────────────────────────────

    private fun drawCover(canvas: android.graphics.Canvas, p: Paint, r: ScanResult) {
        // Full navy background
        p.apply { color = NAVY; style = Paint.Style.FILL }
        canvas.drawRect(0f, 0f, PW, PH, p)

        // Top decorative accent bar
        p.color = AMBER
        canvas.drawRect(0f, 0f, PW, 4f, p)

        // Bottom decorative accent bar
        canvas.drawRect(0f, PH - 3f, PW, PH, p)

        // Logo — always the real app icon, no fallbacks
        val logo = getOrCreateHeaderLogo()
        val logoSize = 110f
        val scaled = Bitmap.createScaledBitmap(logo, logoSize.toInt(), logoSize.toInt(), true)
        canvas.drawBitmap(scaled, PW / 2f - logoSize / 2f, 140f, null)

        // Title
        p.apply { color = WHITE; textSize = 36f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER }
        canvas.drawText("APK Viper", PW / 2f, 300f, p)

        p.apply { color = LIGHT; textSize = 13f; typeface = Typeface.DEFAULT }
        canvas.drawText("Security Analysis Report", PW / 2f, 326f, p)

        // Divider
        p.apply { color = AMBER; style = Paint.Style.FILL }
        canvas.drawRect(PW / 2f - 80f, 340f, PW / 2f + 80f, 342f, p)

        // App identity
        val displayName = r.appLabel ?: r.packageName ?: r.apkName
        p.apply { color = WHITE; textSize = 16f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER }
        canvas.drawText(displayName, PW / 2f, 378f, p)

        if (r.packageName != null) {
            p.apply { color = LIGHT; textSize = 10f; typeface = Typeface.DEFAULT; textAlign = Paint.Align.CENTER }
            canvas.drawText(r.packageName, PW / 2f, 398f, p)
        }

        // File info line
        p.apply { color = 0xFF64748B.toInt(); textSize = 9f; typeface = Typeface.DEFAULT; textAlign = Paint.Align.CENTER }
        val sizeStr = if (r.fileSize > 0) "  ·  ${formatSize(r.fileSize)}" else ""
        canvas.drawText("${displayScanMode(r.scanMode)}$sizeStr", PW / 2f, 418f, p)

        // Threat score circle
        val sc = threatColor(r.threatLevel)
        val cx = PW / 2f
        val cy = 510f
        val radius = 46f

        // Outer glow
        p.apply { color = (sc and 0x00FFFFFF) or 0x20000000.toInt(); style = Paint.Style.FILL }
        canvas.drawCircle(cx, cy, radius + 6f, p)

        // Score circle
        p.apply { color = sc; style = Paint.Style.FILL }
        canvas.drawCircle(cx, cy, radius, p)

        // Score text
        p.apply { color = WHITE; textSize = 32f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER }
        canvas.drawText("${r.threatScore}", cx, cy + 11f, p)

        // Threat level label
        val levelText = when (r.threatLevel) {
            ThreatLevel.CRITICAL -> "CRITICAL"
            ThreatLevel.HIGH -> "HIGH"
            ThreatLevel.MEDIUM -> "MEDIUM"
            ThreatLevel.LOW -> "LOW"
            ThreatLevel.SAFE -> "SAFE"
            ThreatLevel.MALICIOUS -> "MALICIOUS"
        }
        p.apply { color = sc; textSize = 14f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER }
        canvas.drawText(levelText, cx, cy + radius + 30f, p)

        // Findings count
        p.apply { color = LIGHT; textSize = 10f; typeface = Typeface.DEFAULT; textAlign = Paint.Align.CENTER }
        val findingWord = if (r.findings.size == 1) "finding" else "findings"
        canvas.drawText("${r.findings.size} $findingWord", cx, cy + radius + 52f, p)

        // Classification badge
        if (r.classification != null) {
            val cls = r.classification.uppercase()
            p.apply { color = sc; textSize = 9f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER; style = Paint.Style.STROKE; strokeWidth = 1.5f }
            val cw = p.measureText(cls) + 24f
            canvas.drawRoundRect(cx - cw / 2f, cy + radius + 60f, cx + cw / 2f, cy + radius + 78f, 6f, 6f, p)
            p.style = Paint.Style.FILL
            canvas.drawText(cls, cx, cy + radius + 74f, p)
        }

        // Footer info
        p.apply { color = 0xFF475569.toInt(); textSize = 8f; typeface = Typeface.DEFAULT; textAlign = Paint.Align.CENTER }
        val dtStr = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.US)
            .withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(r.timestamp))
        canvas.drawText("Scanned: $dtStr", cx, 770f, p)
        canvas.drawText("Generated by APK Viper  ·  On-device analysis  ·  No data leaves your device", cx, 786f, p)

        p.textAlign = Paint.Align.LEFT
    }

    // ── HEADER & FOOTER ───────────────────────────────────────────

    private fun drawHeader(ctx: DocCtx, sectionTitle: String?) {
        ctx.p.apply { color = NAVY; style = Paint.Style.FILL }
        ctx.c.drawRect(0f, 0f, PW, TOP_BAR, ctx.p)

        // Accent line
        ctx.p.apply { color = AMBER; style = Paint.Style.FILL }
        ctx.c.drawRect(0f, TOP_BAR, PW, TOP_BAR + 2f, ctx.p)

        // Logo — always the real app icon
        val logo = getOrCreateHeaderLogo()
        val headerLogoSize = 20f
        val scaled = Bitmap.createScaledBitmap(logo, headerLogoSize.toInt(), headerLogoSize.toInt(), true)
        ctx.c.drawBitmap(scaled, M, TOP_BAR / 2f - headerLogoSize / 2f, null)

        // Brand name
        ctx.p.apply { color = WHITE; textSize = 13f; typeface = Typeface.DEFAULT_BOLD }
        ctx.c.drawText("APK Viper", M + headerLogoSize + 8f, TOP_BAR / 2f + 5f, ctx.p)

        // Section title
        if (sectionTitle != null) {
            ctx.p.apply { color = LIGHT; textSize = 9f; typeface = Typeface.DEFAULT; textAlign = Paint.Align.RIGHT }
            ctx.c.drawText(sectionTitle, PW - M, TOP_BAR / 2f + 5f, ctx.p)
            ctx.p.textAlign = Paint.Align.LEFT
        }
    }

    private fun drawFooter(ctx: DocCtx) {
        ctx.p.apply { color = LIGHT; textSize = 8f; typeface = Typeface.DEFAULT; textAlign = Paint.Align.RIGHT }
        ctx.c.drawText("APK Viper Security Report  ·  Page ${ctx.num}", PW - M, BOT_Y, ctx.p)
        ctx.p.textAlign = Paint.Align.LEFT
    }

    // ── Section divider ───────────────────────────────────────────

    private fun drawSectionDivider(ctx: DocCtx) {
        ctx.p.apply { color = SLATE_200; style = Paint.Style.FILL }
        ctx.c.drawRect(M, ctx.y + 4f, PW - M, ctx.y + 5f, ctx.p)
        ctx.y += 12f
    }

    // ── EXECUTIVE SUMMARY ─────────────────────────────────────────

    private fun drawExecutiveSummary(ctx: DocCtx, r: ScanResult) {
        sectionHeader(ctx, "Executive Summary", DARK)
        ctx.y += 8f

        // Info cards 2x2
        val cardW = (CW - 10f) / 2f
        val displayName = r.appLabel ?: r.packageName ?: r.apkName

        drawInfoCard(ctx, M, cardW, "App Name", displayName)
        drawInfoCard(ctx, M + cardW + 10f, cardW, "Package", r.packageName ?: r.apkName.substringBeforeLast("."))
        ctx.y += 42f

        val verStr = buildString {
            r.versionName?.let { append(it) }
            r.versionCode?.let { if (isNotEmpty()) append(" ("); append("build $it"); if (contains('(')) append(")") }
            if (isEmpty()) append("—")
        }
        drawInfoCard(ctx, M, cardW, "Version", verStr)
        val sdkStr = buildString {
            r.minSdk?.let { append("API $it") }
            r.targetSdk?.let { append(" → $it") }
            if (isEmpty()) append("—")
        }
        drawInfoCard(ctx, M + cardW + 10f, cardW, "SDK Range", sdkStr)
        ctx.y += 42f

        drawInfoCard(ctx, M, cardW, "File Size", formatSize(r.fileSize))
        drawInfoCard(ctx, M + cardW + 10f, cardW, "Scan Type", displayScanMode(r.scanMode))
        ctx.y += 46f

        // Threat score card
        brk(ctx, 120f)
        val sc = threatColor(r.threatLevel)

        // Card background
        ctx.p.apply { color = SLATE_700; style = Paint.Style.FILL }
        ctx.c.drawRoundRect(M, ctx.y, PW - M, ctx.y + 90f, 8f, 8f, ctx.p)

        // Score circle
        ctx.p.apply { color = sc; style = Paint.Style.FILL }
        ctx.c.drawCircle(M + 48f, ctx.y + 45f, 32f, ctx.p)

        // Score text
        ctx.p.apply { color = WHITE; textSize = 24f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER }
        ctx.c.drawText("${r.threatScore}", M + 48f, ctx.y + 52f, ctx.p)
        ctx.p.textAlign = Paint.Align.LEFT

        // Threat level
        ctx.p.apply { color = WHITE; textSize = 16f; typeface = Typeface.DEFAULT_BOLD }
        ctx.c.drawText(r.threatLevel.name.replace("_", " "), M + 92f, ctx.y + 34f, ctx.p)

        // Findings count
        val findingWord = if (r.findings.size == 1) "finding" else "findings"
        ctx.p.apply { color = LIGHT; textSize = 9f }
        ctx.c.drawText("${r.findings.size} $findingWord  ·  ${formatDuration(r.scanTime)}", M + 92f, ctx.y + 52f, ctx.p)

        // Timestamp
        val dtStr = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.US)
            .withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(r.timestamp))
        ctx.p.apply { color = LIGHT; textSize = 7f }
        ctx.c.drawText("Scanned: $dtStr", M + 92f, ctx.y + 66f, ctx.p)

        // Classification badge
        if (r.classification != null) {
            val cls = r.classification.uppercase().take(48)
            ctx.p.apply { color = sc; textSize = 7f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER; style = Paint.Style.STROKE; strokeWidth = 1f }
            val cw = ctx.p.measureText(cls) + 20f
            ctx.c.drawRoundRect(PW - M - cw - 4f, ctx.y + 6f, PW - M - 4f, ctx.y + 22f, 4f, 4f, ctx.p)
            ctx.p.style = Paint.Style.FILL
            ctx.c.drawText(cls, PW - M - cw / 2 - 4f, ctx.y + 18f, ctx.p)
            ctx.p.textAlign = Paint.Align.LEFT
        }

        ctx.y += 104f

        // SHA256
        brk(ctx, 18f)
        ctx.p.apply { color = LIGHT; textSize = 7f }
        ctx.c.drawText("SHA256: ${r.sha256 ?: "N/A"}", M, ctx.y, ctx.p)
        ctx.y += 14f
    }

    private fun drawInfoCard(ctx: DocCtx, x: Float, w: Float, label: String, value: String) {
        ctx.p.apply { color = SLATE_100; style = Paint.Style.FILL }
        ctx.c.drawRoundRect(x, ctx.y - 4f, x + w, ctx.y + 28f, 6f, 6f, ctx.p)
        ctx.p.apply { color = LIGHT; textSize = 7f }
        ctx.c.drawText(label, x + 10f, ctx.y + 6f, ctx.p)
        ctx.p.apply { color = DARK; textSize = 10f; typeface = Typeface.DEFAULT_BOLD }
        val displayVal = if (ctx.p.measureText(value) > w - 20f) {
            var s = value.take(40)
            while (ctx.p.measureText("$s...") > w - 20f && s.length > 3) s = s.dropLast(1)
            "$s..."
        } else value
        ctx.c.drawText(displayVal, x + 10f, ctx.y + 22f, ctx.p)
    }

    private fun sectionHeader(ctx: DocCtx, title: String, color: Int) {
        brk(ctx, 30f)
        ctx.p.apply { this.color = color; textSize = 16f; typeface = Typeface.DEFAULT_BOLD }
        ctx.c.drawText(title, M, ctx.y, ctx.p)
        ctx.y += 24f
    }

    // ── SEVERITY BREAKDOWN ────────────────────────────────────────

    private fun drawSeverityBreakdown(ctx: DocCtx, grp: Map<Severity, List<Finding>>) {
        val total = grp.values.sumOf { it.size }
        if (total == 0) return
        brk(ctx, 80f)
        ctx.p.apply { color = DARK; textSize = 14f; typeface = Typeface.DEFAULT_BOLD }
        ctx.c.drawText("Severity Breakdown", M, ctx.y, ctx.p)
        ctx.y += 20f

        val order = listOf(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        val tot = total.coerceAtLeast(1).toFloat()

        // Stacked bar
        var bx = M
        ctx.p.apply { style = Paint.Style.FILL }
        for (s in order) {
            val cnt = grp[s]?.size ?: 0
            if (cnt == 0) continue
            val bc = severityColor(s)
            val bw = (cnt / tot) * CW
            ctx.p.color = bc
            ctx.c.drawRoundRect(bx, ctx.y, bx + bw, ctx.y + 18f, if (bw > 4f) 3f else 0f, 3f, ctx.p)
            bx += bw
        }
        ctx.y += 28f

        // Legend
        bx = M
        for (s in order) {
            val cnt = grp[s]?.size ?: 0
            if (cnt == 0) continue
            val bc = severityColor(s)
            ctx.p.apply { color = bc; style = Paint.Style.FILL }
            ctx.c.drawRoundRect(bx, ctx.y, bx + 10f, ctx.y + 10f, 3f, 3f, ctx.p)
            ctx.p.apply { color = MED; textSize = 8f; typeface = Typeface.DEFAULT }
            val lb = " ${s.name} ($cnt)"
            ctx.c.drawText(lb, bx + 14f, ctx.y + 9f, ctx.p)
            bx += ctx.p.measureText(lb) + 28f
        }
        ctx.y += 22f
    }

    // ── MITRE ATT&CK ──────────────────────────────────────────────

    private fun drawMitre(ctx: DocCtx, r: ScanResult) {
        val mitre = guessMitreTechniques(r.findings, r.appLabel ?: r.packageName ?: r.apkName)
        if (mitre.isEmpty()) return

        sectionHeader(ctx, "MITRE ATT&CK Mapping", DARK)

        val cw3 = floatArrayOf(58f, 148f, CW - 206f)

        // Table header
        ctx.p.apply { color = SLATE_800; style = Paint.Style.FILL }
        ctx.c.drawRoundRect(M, ctx.y - 4f, PW - M, ctx.y + 16f, 4f, 4f, ctx.p)
        ctx.p.apply { color = WHITE; textSize = 8f; typeface = Typeface.DEFAULT_BOLD }
        ctx.c.drawText("ID", M + 6f, ctx.y + 9f, ctx.p)
        ctx.c.drawText("Technique", M + cw3[0] + 6f, ctx.y + 9f, ctx.p)
        ctx.c.drawText("Description", M + cw3[0] + cw3[1] + 6f, ctx.y + 9f, ctx.p)
        ctx.y += 22f

        for ((i, t) in mitre.withIndex()) {
            val descLines = wrapText(t.description, cw3[2] - 8f, 7f, ctx.p)
            val descH = descLines.size * 10f

            // Row has two logical lines:
            // Line 1: ID + count pill + Technique name
            // Line 2+: Description (indented to description column)
            val line1H = 16f
            val rowH = maxOf(line1H + 2f, line1H + descH + 2f)
            brk(ctx, rowH + 2f)

            // Row background
            if (i % 2 == 1) {
                ctx.p.apply { color = ROW_ALT; style = Paint.Style.FILL }
                ctx.c.drawRect(M + 2f, ctx.y - 2f, PW - M - 2f, ctx.y + rowH, ctx.p)
            }

            // ── Line 1: ID + count pill + Technique name ──
            // ID
            ctx.p.apply { color = AMBER; textSize = 8f; typeface = Typeface.DEFAULT_BOLD }
            val idW = ctx.p.measureText(t.id)
            ctx.c.drawText(t.id, M + 6f, ctx.y + 4f, ctx.p)

            // Count pill (small inline pill right after ID, within ID column)
            ctx.p.apply { textSize = 6.5f; typeface = Typeface.DEFAULT_BOLD }
            val countLabel = "${t.findingCount}"
            val pillW = ctx.p.measureText(countLabel) + 10f
            val pillX = M + 6f + idW + 3f
            val maxPillX = M + cw3[0] - 2f
            if (pillX + pillW <= maxPillX) {
                ctx.p.apply { color = (AMBER and 0x00FFFFFF) or 0x18000000.toInt(); style = Paint.Style.FILL }
                ctx.c.drawRoundRect(pillX, ctx.y + 1f, pillX + pillW, ctx.y + 10f, 3f, 3f, ctx.p)
                ctx.p.apply { color = AMBER; style = Paint.Style.FILL; textAlign = Paint.Align.CENTER }
                ctx.c.drawText(countLabel, pillX + pillW / 2f, ctx.y + 9f, ctx.p)
                ctx.p.textAlign = Paint.Align.LEFT
            } else {
                // Fallback: just draw count after ID column
                ctx.p.apply { color = AMBER; textSize = 6.5f; textAlign = Paint.Align.LEFT }
                ctx.c.drawText("x$countLabel", M + 6f, ctx.y + 14f, ctx.p)
            }

            // Technique name (on same line as ID)
            ctx.p.apply { color = DARK; textSize = 8f; typeface = Typeface.DEFAULT_BOLD }
            ctx.c.drawText(truncateText(t.name, cw3[1] - 6f, ctx.p), M + cw3[0] + 6f, ctx.y + 4f, ctx.p)

            // ── Line 2+: Description ──
            ctx.p.apply { color = MED; textSize = 7f }
            for ((di, dline) in descLines.withIndex()) {
                ctx.c.drawText(dline, M + cw3[0] + cw3[1] + 6f, ctx.y + 16f + di * 10f, ctx.p)
            }
            ctx.y += rowH + 2f
        }
        ctx.y += 6f
    }

    // ── REMEDIATION ───────────────────────────────────────────────

    private fun drawRemediation(ctx: DocCtx, r: ScanResult) {
        if (r.remediations.isEmpty()) return
        sectionHeader(ctx, "Remediation Checklist", RED)

        for ((i, step) in r.remediations.withIndex()) {
            brk(ctx, 22f)
            // Step number badge
            ctx.p.apply { color = RED; style = Paint.Style.FILL }
            ctx.c.drawCircle(M + 7f, ctx.y - 4f, 8f, ctx.p)
            ctx.p.apply { color = WHITE; textSize = 8f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER }
            ctx.c.drawText("${i + 1}", M + 7f, ctx.y, ctx.p)
            ctx.p.textAlign = Paint.Align.LEFT

            // Step text
            ctx.p.apply { color = MED; textSize = 9f }
            wrap(ctx, step, M + 22f, CW - 22f, 9f, MED, 2f)
        }
        ctx.y += 6f
    }

    // ── FILE ANALYSIS ─────────────────────────────────────────────

    private fun drawFileAnalysis(ctx: DocCtx, r: ScanResult) {
        sectionHeader(ctx, "File Analysis", DARK)

        val fields = listOfNotNull(
            "Package" to (r.packageName ?: r.apkName.substringBeforeLast(".")),
            "Version" to (r.versionName ?: "—"),
            "SDK Min" to (r.minSdk?.let { "API $it" } ?: "—"),
            "SDK Target" to (r.targetSdk?.let { "API $it" } ?: "—"),
            "File Size" to formatSize(r.fileSize),
            "SHA256" to (r.sha256 ?: "N/A"),
            "Threat Score" to "${r.threatScore}/100",
            "Scan Mode" to displayScanMode(r.scanMode),
            "Duration" to formatDuration(r.scanTime)
        )

        // Two-column layout
        val col1 = fields.take((fields.size + 1) / 2)
        val col2 = fields.drop((fields.size + 1) / 2)
        val colW = CW / 2f - 6f

        var maxRows = maxOf(col1.size, col2.size)
        val rowH = 16f
        brk(ctx, maxRows * rowH + 6f)

        for (i in 0 until maxRows) {
            if (i % 2 == 1) {
                ctx.p.apply { color = ROW_ALT; style = Paint.Style.FILL }
                ctx.c.drawRect(M, ctx.y - 4f, PW - M, ctx.y + rowH - 4f, ctx.p)
            }
            if (i < col1.size) {
                val (l, v) = col1[i]
                ctx.p.apply { color = LIGHT; textSize = 8f }
                ctx.c.drawText(l, M + 6f, ctx.y + 3f, ctx.p)
                ctx.p.apply { color = DARK; textSize = 8f; typeface = Typeface.DEFAULT_BOLD }
                val vw = colW - 70f
                ctx.c.drawText(truncateText(v, vw, ctx.p), M + 70f, ctx.y + 3f, ctx.p)
            }
            if (i < col2.size) {
                val (l, v) = col2[i]
                ctx.p.apply { color = LIGHT; textSize = 8f }
                ctx.c.drawText(l, M + colW + 12f, ctx.y + 3f, ctx.p)
                ctx.p.apply { color = DARK; textSize = 8f; typeface = Typeface.DEFAULT_BOLD }
                val vw = colW - 76f
                ctx.c.drawText(truncateText(v, vw, ctx.p), M + colW + 76f, ctx.y + 3f, ctx.p)
            }
            ctx.y += rowH
        }
        ctx.y += 8f
    }

    // ── FINDINGS DETAIL PAGES ─────────────────────────────────────

    private fun drawFindingsPage(
        ctx: DocCtx, r: ScanResult,
        fgs: List<Finding>,
        s: Severity
    ) {
        val sc = severityColor(s)
        ctx.num++
        val info = PdfDocument.PageInfo.Builder(PI_W, PI_H, 1).create()
        ctx.page = ctx.doc.startPage(info)
        ctx.c = ctx.page.canvas
        ctx.y = 0f

        // Severity banner
        ctx.p.apply { color = sc; style = Paint.Style.FILL }
        ctx.c.drawRect(0f, 0f, PW, 50f, ctx.p)

        // Dark overlay strip
        ctx.p.apply { color = (sc and 0x00FFFFFF) or 0x33000000.toInt(); style = Paint.Style.FILL }
        ctx.c.drawRect(0f, 0f, PW, 4f, ctx.p)

        // Title
        ctx.p.apply { color = WHITE; textSize = 18f; typeface = Typeface.DEFAULT_BOLD }
        ctx.c.drawText("${s.name} Findings", M, 32f, ctx.p)

        // App name and count
        ctx.p.apply { color = WHITE; textSize = 9f; typeface = Typeface.DEFAULT }
        val appLabel = r.appLabel ?: r.packageName ?: r.apkName
        ctx.c.drawText(truncateText(appLabel, 110f, ctx.p), M, 46f, ctx.p)
        ctx.p.apply { color = WHITE; textSize = 11f }
        ctx.c.drawText("${fgs.size} item${if (fgs.size != 1) "s" else ""} found", M + 120f, 46f, ctx.p)

        // Header logo — always the real app icon
        val logo = getOrCreateHeaderLogo()
        val ls = 18f
        val scaled = Bitmap.createScaledBitmap(logo, ls.toInt(), ls.toInt(), true)
        ctx.c.drawBitmap(scaled, PW - M - ls, 6f, null)

        ctx.y = 66f

        for ((fi, f) in fgs.withIndex()) {
            val descLines = wrapText(f.description, CW - 16f, 9f, ctx.p).size
            val detLines = f.details?.let { wrapText(it, CW - 24f, 7.5f, ctx.p).size } ?: 0
            val lhDesc = lineHeight(9f)
            val lhDet = lineHeight(7.5f)
            val headerH = 24f
            val descH = descLines * lhDesc
            val detH = detLines * lhDet
            val extraH = if (f.file != null) 14f else 0f
            val gapAfter = 8f
            val sepH = if (fi < fgs.size - 1) 4f else 0f
            val needed = headerH + descH + detH + extraH + gapAfter + sepH
            brk(ctx, needed)

            // Severity left strip
            ctx.p.apply { color = sc; style = Paint.Style.FILL }
            ctx.c.drawRect(M, ctx.y - 4f, M + 3f, ctx.y + needed - sepH - gapAfter + 4f, ctx.p)

            // Finding number badge
            ctx.p.apply { color = sc; style = Paint.Style.FILL }
            ctx.c.drawRoundRect(M + 10f, ctx.y - 4f, M + 34f, ctx.y + 14f, 6f, 6f, ctx.p)
            ctx.p.apply { color = WHITE; textSize = 9f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER }
            ctx.c.drawText("${fi + 1}", M + 22f, ctx.y + 10f, ctx.p)
            ctx.p.textAlign = Paint.Align.LEFT

            // Category tag
            val tagBg = (sc and 0x00FFFFFF) or 0x1E000000.toInt()
            val catLabel = f.category.name
            ctx.p.apply { color = tagBg; style = Paint.Style.FILL }
            val catW = minOf(ctx.p.measureText(catLabel) + 14f, 90f)
            ctx.c.drawRoundRect(M + 40f, ctx.y - 3f, M + 40f + catW, ctx.y + 13f, 4f, 4f, ctx.p)
            ctx.p.apply { color = sc; textSize = 7f; typeface = Typeface.DEFAULT_BOLD }
            ctx.c.drawText(catLabel, M + 46f, ctx.y + 10f, ctx.p)

            // Title
            val titleX = M + 44f + catW
            val maxTitleW = PW - titleX - 8f
            val displayTitle = if (ctx.p.measureText(f.title) > maxTitleW) {
                var t = f.title; while (ctx.p.measureText("$t...") > maxTitleW && t.length > 3) t = t.dropLast(1); "$t..."
            } else f.title
            ctx.p.apply { color = DARK; textSize = 10f; typeface = Typeface.DEFAULT_BOLD }
            ctx.c.drawText(displayTitle, titleX, ctx.y + 10f, ctx.p)
            ctx.y += headerH

            // Description
            wrap(ctx, f.description, M + 14f, CW - 16f, 9f, MED, 2f)

            // Details
            if (f.details != null) {
                brk(ctx, lhDet)
                ctx.p.apply { color = LIGHT; textSize = 7.5f }
                // Detail label
                ctx.p.typeface = Typeface.DEFAULT_BOLD
                ctx.c.drawText("Details:", M + 14f, ctx.y, ctx.p)
                ctx.y += lhDet * 0.8f
                wrap(ctx, f.details, M + 14f, CW - 24f, 7.5f, LIGHT, 1f)
            }

            // File reference
            if (f.file != null) {
                brk(ctx, 14f)
                ctx.p.apply { color = 0xFF6366F1.toInt(); textSize = 7f; typeface = Typeface.DEFAULT }
                ctx.c.drawText("File: ${f.file}${if (f.line != null) " (line ${f.line})" else ""}", M + 14f, ctx.y, ctx.p)
                ctx.y += 14f
            }

            ctx.y += gapAfter

            // Separator
            if (fi < fgs.size - 1) {
                ctx.p.apply { color = SLATE_200 }
                ctx.c.drawRect(M + 14f, ctx.y, PW - M - 14f, ctx.y + 0.5f, ctx.p)
                ctx.y += sepH
            }
        }
        drawFooter(ctx)
        ctx.doc.finishPage(ctx.page)
    }

    // ── BACK PAGE ─────────────────────────────────────────────────

    private fun drawBackPage(ctx: DocCtx) {
        ctx.num++
        val info = PdfDocument.PageInfo.Builder(PI_W, PI_H, 1).create()
        ctx.page = ctx.doc.startPage(info)
        ctx.c = ctx.page.canvas
        ctx.p.apply { color = NAVY; style = Paint.Style.FILL }
        ctx.c.drawRect(0f, 0f, PW, PH, ctx.p)

        // Top accent
        ctx.p.apply { color = AMBER; style = Paint.Style.FILL }
        ctx.c.drawRect(0f, 0f, PW, 3f, ctx.p)
        ctx.c.drawRect(0f, PH - 3f, PW, PH, ctx.p)

        // Logo — always the real app icon
        val bpLogo = getOrCreateHeaderLogo()
        val ls = 56f
        val scaled = Bitmap.createScaledBitmap(bpLogo, ls.toInt(), ls.toInt(), true)
        ctx.c.drawBitmap(scaled, PW / 2f - ls / 2f, 280f, null)

        // Title
        ctx.p.apply { color = AMBER; textSize = 32f; typeface = Typeface.DEFAULT_BOLD; textAlign = Paint.Align.CENTER }
        ctx.c.drawText("APK Viper", PW / 2f, 370f, ctx.p)

        ctx.p.apply { color = LIGHT; textSize = 13f; typeface = Typeface.DEFAULT; textAlign = Paint.Align.CENTER }
        ctx.c.drawText("APK Security Analyzer", PW / 2f, 394f, ctx.p)

        // Divider
        ctx.p.apply { color = AMBER; style = Paint.Style.FILL }
        ctx.c.drawRect(PW / 2f - 60f, 408f, PW / 2f + 60f, 410f, ctx.p)

        // Info
        val dtStr = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US)
            .withZone(ZoneId.systemDefault()).format(Instant.now())
        ctx.p.apply { color = 0xFF64748B.toInt(); textSize = 9f; typeface = Typeface.DEFAULT; textAlign = Paint.Align.CENTER }
        ctx.c.drawText("Generated: $dtStr", PW / 2f, 442f, ctx.p)

        ctx.p.apply { color = 0xFF475569.toInt(); textSize = 8f }
        ctx.c.drawText("Multi-engine detection: YARA rules, heuristic analysis, taint tracing, and MITRE ATT&CK mapping.", PW / 2f, 470f, ctx.p)
        ctx.c.drawText("All analysis performed on-device. No data leaves your device.", PW / 2f, 486f, ctx.p)
        ctx.c.drawText("APK Viper v1.0  ·  Open-source security tool", PW / 2f, 502f, ctx.p)

        ctx.p.apply { color = LIGHT; textSize = 8f; typeface = Typeface.DEFAULT; textAlign = Paint.Align.RIGHT }
        ctx.c.drawText("APK Viper Security Report  ·  Page ${ctx.num}", PW - M, BOT_Y, ctx.p)

        ctx.p.textAlign = Paint.Align.LEFT
        ctx.doc.finishPage(ctx.page)
    }

    // ── Color helpers ─────────────────────────────────────────────

    private fun threatColor(tl: ThreatLevel): Int = when (tl) {
        ThreatLevel.SAFE, ThreatLevel.LOW -> GREEN
        ThreatLevel.MEDIUM -> AMBER
        ThreatLevel.HIGH -> ORANGE
        ThreatLevel.CRITICAL, ThreatLevel.MALICIOUS -> RED
    }

    private fun severityColor(s: Severity): Int = when (s) {
        Severity.CRITICAL -> RED; Severity.HIGH -> ORANGE
        Severity.MEDIUM -> AMBER; Severity.LOW -> BLUE; Severity.INFO -> LIGHT
    }

    // ── Text wrapping ─────────────────────────────────────────────

    private fun truncateText(text: String, maxW: Float, p: Paint): String {
        p.typeface = Typeface.DEFAULT
        if (p.measureText(text) <= maxW) return text
        var s = text
        while (p.measureText("$s...") > maxW && s.length > 3) s = s.dropLast(1)
        return "$s..."
    }

    private fun wrapText(text: String, maxW: Float, sz: Float, p: Paint): List<String> {
        if (text.isEmpty()) return listOf("")
        p.textSize = sz
        p.typeface = Typeface.DEFAULT
        val lines = mutableListOf<String>()
        // Split on whitespace, collapse multiple spaces, ignore zero-length words
        val words = text.split("\\s+".toRegex()).filter { it.isNotEmpty() }
        if (words.isEmpty()) return listOf(text)
        var line = StringBuilder()
        for (word in words) {
            if (line.isEmpty() && p.measureText(word) > maxW) {
                // Single word doesn't fit — force-break by characters
                var r = word
                while (r.isNotEmpty()) {
                    var bi = r.length
                    for (i in r.indices) {
                        if (p.measureText(r.substring(0, i + 1)) > maxW) { bi = i; break }
                    }
                    if (bi == 0) bi = 1
                    lines.add(r.substring(0, bi))
                    r = r.substring(bi)
                }
                continue
            }
            val test = if (line.isEmpty()) word else "$line $word"
            if (p.measureText(test) <= maxW) {
                line.append(if (line.isEmpty()) word else " $word")
            } else {
                if (line.isNotEmpty()) lines.add(line.toString())
                line = StringBuilder(word)
            }
        }
        if (line.isNotEmpty()) lines.add(line.toString())
        return lines.ifEmpty { listOf(text) }
    }

    private fun formatSize(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${"%.1f".format(bytes / 1024.0)} KB"
        else -> "${"%.1f".format(bytes / (1024.0 * 1024))} MB"
    }

    private fun formatDuration(ms: Long): String {
        val s = ms / 1000
        return when {
            s < 60 -> "${s}s"
            s < 3600 -> "${s / 60}m ${s % 60}s"
            else -> "${s / 3600}h ${(s % 3600) / 60}m"
        }
    }

    internal fun guessMitreTechniques(findings: List<Finding>, apkName: String): List<MitreTechnique> {
        val patterns = listOf(
            "T1071" to "Application Layer Protocol" to listOf("network", "c2", "command.*control", "beacon"),
            "T1565" to "Data Manipulation" to listOf("sms", "message", "telephony"),
            "T1516" to "System Information Discovery" to listOf("record", "audio", "microphone", "camera"),
            "T1430" to "Location Tracking" to listOf("location", "gps", "geofenc"),
            "T1636" to "Contact Data" to listOf("contact", "phonebook", "address.*book"),
            "T1414" to "Clipboard Data" to listOf("clipboard", "paste"),
            "T1417" to "Input Capture" to listOf("keylog", "keystroke", "input.*capture"),
            "T1027" to "Obfuscated Files" to listOf("obfuscat", "encrypt", "packer", "packed", "protect"),
            "T1068" to "Exploitation for Privilege Escalation" to listOf("root", "privilege", "escalation", "su"),
            "T1547" to "Boot or Logon Autostart Execution" to listOf("persistence", "boot", "autostart", "receiver"),
            "T1486" to "Data Encrypted for Impact" to listOf("ransom", "encrypt.*file", "decrypt"),
            "T1622" to "Debugger Evasion" to listOf("debug", "anti.*debug", "emulator", "virtual"),
            "T1553" to "Subvert Trust Controls" to listOf("certif", "signature", "repackag"),
            "T1574" to "Hijack Execution Flow" to listOf("hijack", "dll", "load", "inject"),
            "T1106" to "Native API" to listOf("native", "jni", "ndk", "system.*call"),
            "T1055" to "Process Injection" to listOf("inject", "process.*hollow", "hook"),
        )
        val matched = mutableMapOf<String, MitreTechnique>()
        for (f in findings) {
            val txt = "${f.title} ${f.description}".lowercase()
            for ((pair, kw) in patterns) {
                val (id, name) = pair
                if (kw.any { txt.contains(it) }) {
                    val ex = matched[id]
                    matched[id] = if (ex != null) ex.copy(findingCount = ex.findingCount + 1)
                    else MitreTechnique(id, name, "Detected in $apkName", 1)
                }
            }
        }
        return matched.values.toList().sortedBy { it.id }
    }
}
