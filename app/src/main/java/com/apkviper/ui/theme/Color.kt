package com.apkviper.ui.theme

import androidx.compose.ui.graphics.Color

// APK Viper — Operational Command
// A field terminal for threat analysis. Warm, deliberate, instrumental.
// Surfaces tint near-black with a 2° warmth. Accent is raw copper — hot,
// electrical, hostile. Severity runs green → amber → crimson.

// Canvas — warm-cast void, the terminal glass behind everything
val Bg0 = Color(0xFF0C0D0F)

// Surfaces — stepped with 1° warm lift, not pure gray
val Bg1 = Color(0xFF121316)   // primary surfaces (bars, drawers)
val Bg2 = Color(0xFF18191D)   // cards, panels

// Borders — etched, structural
val Border1 = Color(0xFF24252B)
val Border2 = Color(0xFF2E2F35)

// Text — warm-white hierarchy
val TextPrimary = Color(0xFFEDEDF0)
val TextSecondary = Color(0xFF9595A0)
val TextMuted = Color(0xFF787880)

// Copper accent — hot, raw, electrical. CTA, progress, active state.
val Accent = Color(0xFFD97A38)
val AccentLight = Color(0xFFE89655)
val AccentBg = Color(0xFF2A1C10)

// Danger — deep crimson, reserved for CRITICAL and destructive actions
val Danger = Color(0xFFE04347)
val DangerBg = Color(0xFF291112)

// Warning — warm amber
val Warning = Color(0xFFE0A030)

// Safe — cool green, deliberate contrast to the warm surface
val Safe = Color(0xFF34B56C)

// Severity — threat heat gradient, green → amber → orange → crimson
val SevSafe = Color(0xFF34B56C)
val SevLow = Color(0xFF6DBF52)
val SevMedium = Color(0xFFE0A030)
val SevHigh = Color(0xFFE06B3A)
val SevCritical = Color(0xFFE04347)

// Utility tints — subtle colored surfaces for badges, highlights, overlays
val Copper05 = Color(0x0DD97A38)
val Danger05 = Color(0x0DE04347)
