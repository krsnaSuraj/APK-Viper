package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class PhishingOverlayAnalyzer {

    companion object {
        private const val MAX_SOURCE_SIZE = 50 * 1024 * 1024
    }

    data class BrandRep(val name: String, val keywords: List<String>)

    private val targets = listOf(
        BrandRep("Google", listOf("google", "gmail", "accounts.google", "signin")),
        BrandRep("Facebook", listOf("facebook", "fb.com", "messenger")),
        BrandRep("PayPal", listOf("paypal", "pay-pal", "pay pal")),
        BrandRep("Banking", listOf("bank", "login", "password", "credit card", "card number")),
        BrandRep("Instagram", listOf("instagram", "insta-login")),
        BrandRep("WhatsApp", listOf("whatsapp", "whats-app")),
        BrandRep("Netflix", listOf("netflix", "net-flix")),
        BrandRep("Amazon", listOf("amazon", "amzn", "amazonprime")),
        BrandRep("Coinbase", listOf("coinbase", "coin-base")),
        BrandRep("Binance", listOf("binance", "bi-nance")),
        BrandRep("Telegram", listOf("telegram", "tele-gram")),
        BrandRep("Snapchat", listOf("snapchat", "snap-chat")),
        BrandRep("Microsoft", listOf("microsoft", "outlook", "office365")),
        BrandRep("TikTok", listOf("tiktok", "tik-tok")),
        BrandRep("Twitter/X", listOf("twitter", "x.com", "tweet")),
        BrandRep("Spotify", listOf("spotify", "spot-ify")),
        BrandRep("Steam", listOf("steam", "steampowered")),
        BrandRep("Discord", listOf("discord", "dis-cord")),
        BrandRep("Apple ID", listOf("apple.id", "icloud", "appleid")),
        BrandRep("Dropbox", listOf("dropbox", "drop-box")),
        BrandRep("GitHub", listOf("github", "git-hub")),
        BrandRep("LinkedIn", listOf("linkedin", "linked-in")),
        BrandRep("Crypto Wallet", listOf("metamask", "trust wallet", "wallet connect", "phantom")),
        BrandRep("Alipay", listOf("alipay", "ali-pay")),
        BrandRep("Taobao", listOf("taobao", "tao-bao"))
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()

        val manifest = decompiled.manifest.lowercase()
        val hasOverlay = manifest.contains("system_alert_window") ||
            manifest.contains("TYPE_APPLICATION_OVERLAY") ||
            manifest.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasAccessibility = manifest.contains("BIND_ACCESSIBILITY_SERVICE") ||
            manifest.contains("bind_accessibility_service")
        if (!hasOverlay && !hasAccessibility) return findings

        val (allResources, allSmali) = if (decompiled.allSourceText != null) {
            decompiled.allSourceText.lowercase() to ""
        } else {
            val javaSize = decompiled.javaSource.values.sumOf { it.length }
            val smaliSize = decompiled.smaliSource.values.sumOf { it.length }
            if (javaSize + smaliSize > MAX_SOURCE_SIZE) {
                decompiled.javaSource.values.take(100).joinToString(" ").lowercase() to
                    decompiled.smaliSource.values.take(100).joinToString(" ").lowercase()
            } else {
                decompiled.javaSource.values.joinToString(" ").lowercase() to
                    decompiled.smaliSource.values.joinToString(" ").lowercase()
            }
        }

        val matchedBrands = mutableSetOf<BrandRep>()
        for (brand in targets) {
            for (kw in brand.keywords) {
                if (allResources.contains(kw) || allSmali.contains(kw)) {
                    matchedBrands.add(brand)
                    break
                }
            }
        }

        if (matchedBrands.isEmpty()) return findings

        var severity = Severity.LOW
        if (hasOverlay && hasAccessibility) severity = Severity.CRITICAL
        else if (hasOverlay) severity = Severity.HIGH
        else if (hasAccessibility) severity = Severity.MEDIUM

        findings.add(Finding(
            category = FindingCategory.BEHAVIORAL,
            severity = severity,
            title = "Potential Phishing Overlay Attack",
            description = "References brands (${matchedBrands.take(3).joinToString(", ") { it.name }}) " +
                "combined with ${if (hasOverlay) "SYSTEM_ALERT_WINDOW" else ""}${if (hasOverlay && hasAccessibility) " + " else ""}" +
                "${if (hasAccessibility) "Accessibility Service" else ""}"
        ))

        return findings
    }
}
