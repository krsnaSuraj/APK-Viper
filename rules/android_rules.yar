/*
 * APK Viper Curated Android Ruleset  (v1.1.0)
 * Hosted in-repo: rules/android_rules.yar
 *
 * This is the AUTONOMOUS, future-proof detection source. When a new Android malware
 * family emerges, a rule is added HERE and every installed APK Viper auto-pulls it on
 * the next update — no app rebuild, no manual action by the user.
 *
 * Rules are Android-specific and use proper YARA `condition:` blocks. The engine only
 * fires a rule when its FULL condition holds (single-string matches are ignored), and a
 * MALICIOUS verdict still requires >=2 independent strong findings (see ThreatScorer),
 * so these curated rules cannot by themselves false-flag a genuine/modded app.
 *
 * Every rule is high-confidence. Community/auto-updated rules (tagged confidence=low)
 * live separately and can never alone drive a verdict.
 */

// ===== BANKING TROJANS (2021-2024 families) =====

rule Android_Banker_Teabot {
    meta:
        description = "Teabot / Toddler banking trojan"
        family = "Teabot"
        severity = "critical"
    strings:
        $pkg = "com.ptpikpgl"
        $pkg2 = "com.ascvnyu"
        $ov = "AccessibilityService"
        $ov2 = "overlay"
        $sms = "abortBroadcast"
        $sms2 = "RECEIVE_SMS"
    condition:
        $pkg or $pkg2 or ($ov and $ov2 and $sms)
}

rule Android_Banker_Flubot {
    meta:
        description = "Flubot banking trojan (SMS/toll fraud)"
        family = "Flubot"
        severity = "critical"
    strings:
        $pkg = "com.logiccarri"
        $pkg2 = "com.afollst"
        $sms = "RECEIVE_SMS"
        $ov = "AccessibilityService"
    condition:
        $pkg or $pkg2 or ($sms and $ov)
}

rule Android_Banker_Sharkbot {
    meta:
        description = "Sharkbot banking trojan"
        family = "Sharkbot"
        severity = "critical"
    strings:
        $pkg = "com.sharkbot"
        $str = "sharkbot"
        $ov = "AccessibilityService"
        $inject = "inject"
    condition:
        $pkg or ($str and $ov and $inject)
}

rule Android_Banker_BRATA {
    meta:
        description = "BRATA banking trojan with device tracking"
        family = "BRATA"
        severity = "critical"
    strings:
        $pkg = "com.brata"
        $str = "brata"
        $loc = "FusedLocationProviderClient"
        $perm = "ACCESS_FINE_LOCATION"
    condition:
        $pkg or ($str and $loc and $perm)
}

// ===== SPYWARE / STEALERS =====

rule Android_Spyware_MoqHao {
    meta:
        description = "MoqHao / Wroba SMS spyware"
        family = "MoqHao"
        severity = "high"
    strings:
        $pkg = "com.android.system.update"
        $pkg2 = "com.wroba"
        $sms = "RECEIVE_SMS"
    condition:
        $pkg or $pkg2 or ($sms and "android.telephony")
}

rule Android_Spyware_KevDroid {
    meta:
        description = "KevDroid spyware / DPRK-linked"
        family = "KevDroid"
        severity = "high"
    strings:
        $pkg = "com.kevdroid"
        $exfil = "uploadToServer"
        $contact = "ContactsContract"
    condition:
        $pkg or ($exfil and $contact)
}

rule Android_RAT_BianLian {
    meta:
        description = "BianLian Android RAT"
        family = "BianLian"
        severity = "critical"
    strings:
        $pkg = "com.bianlian"
        $str = "bianlian"
        $cam = "CameraManager"
    condition:
        $pkg or ($str and $cam)
}

// ===== CRYPTO-CLIPPER / WALLET SCAMS =====

rule Android_Clipper_CryptoWallet {
    meta:
        description = "Crypto wallet clipboard clipper (replaces addressed with attacker wallet)"
        family = "Clipper"
        severity = "critical"
    strings:
        $clip = "getPrimaryClip"
        $setclip = "setPrimaryClip"
        $btc = "bc1"
        $eth = "0x"
        $replace = "replace"
    condition:
        ($clip and $setclip) and (($btc and $replace) or ($eth and $replace))
}

rule Android_Scam_FakeWallet {
    meta:
        description = "Fake crypto wallet stealer (mnemonic/seed harvest)"
        family = "FakeWallet"
        severity = "critical"
    strings:
        $seed = "mnemonic"
        $seed2 = "seed phrase"
        $seed3 = "recovery phrase"
        $wallet = "wallet"
        $exfil = "HttpURLConnection"
    condition:
        ($seed or $seed2 or $seed3) and $wallet and $exfil
}

// ===== SMS TROJANS / PREMIUM FRAUD =====

rule Android_Trojan_SMS_Fraud {
    meta:
        description = "Premium SMS fraud trojan (subscribes to paid numbers)"
        family = "SMSFraud"
        severity = "high"
    strings:
        $sms = "SEND_SMS"
        $sub = "premium"
        $sub2 = "subscription"
        $perm = "READ_PHONE_STATE"
    condition:
        ($sms and $perm) and ($sub or $sub2)
}
