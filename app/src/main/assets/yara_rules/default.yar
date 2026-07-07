/*
 * APK Viper Default YARA Ruleset
 * Covers: RATs, Banking Trojans, Spyware, Crypto Miners,
 * Ransomware, Packers, Anti-Analysis, Adware
 * Community contributions welcome!
 */

// ===== ANDROID RATS =====

rule Android_RAT_DroidJack {
    meta:
        description = "DroidJack Android RAT - Remote Access Trojan"
        family = "DroidJack"
        severity = "critical"
    strings:
        $sdk1 = "net.droidjack.server"
        $sdk2 = "droidjack"
        $perm1 = "BIND_DEVICE_ADMIN"
        $perm2 = "SYSTEM_ALERT_WINDOW"
        $func1 = "getInstalledPackages"
        $func2 = "getRunningTasks"
    condition:
        any of ($sdk*, $func1, $func2)
}

rule Android_RAT_SpyNote {
    meta:
        description = "SpyNote Android RAT - Banking spyware"
        family = "SpyNote"
        severity = "critical"
    strings:
        $pkg = "com.spynote"
        $func1 = "recordAudio"
        $func2 = "sendTextMessage"
        $perm1 = "RECORD_AUDIO"
        $perm2 = "CAMERA"
        $perm3 = "READ_SMS"
        $perm4 = "SEND_SMS"
    condition:
        $pkg or (any of ($perm1, $perm3) and any of ($func1, $func2))
}

rule Android_RAT_AhMyth {
    meta:
        description = "AhMyth Android RAT - Open-source RAT"
        family = "AhMyth"
        severity = "critical"
    strings:
        $pkg = "ahmyth"
        $func1 = "AhMyth"
        $func2 = "CameraManager"
        $func3 = "SmsManager"
        $perm1 = "CAMERA"
        $perm2 = "RECORD_AUDIO"
    condition:
        any of ($pkg, $func1) and any of ($perm1, $perm2)
}

rule Android_RAT_AndroRAT {
    meta:
        description = "AndroRAT - Remote Administration Tool"
        family = "AndroRAT"
        severity = "critical"
    strings:
        $pkg = "com.androrat"
        $func1 = "AndroRAT"
        $str1 = "getSimSerialNumber"
        $str2 = "getDeviceId"
        $str3 = "getSubscriberId"
    condition:
        any of ($pkg, $func1) or all of ($str1, $str2, $str3)
}

rule Android_RAT_L3MON {
    meta:
        description = "L3MON Android RAT"
        family = "L3MON"
        severity = "critical"
    strings:
        $str1 = "l3mon"
        $str2 = "com.etechd.l3mon"
        $func1 = "MediaProjection"
        $func2 = "AccessibilityService"
    condition:
        any of ($str1, $str2)
}

// ===== BANKING TROJANS =====

rule Android_Banker_Cerberus {
    meta:
        description = "Cerberus Banking Trojan"
        family = "Cerberus"
        severity = "critical"
    strings:
        $str1 = "cerberus"
        $str2 = "com.cerberus"
        $func1 = "overlay_attack"
        $func2 = "accessibility_event"
        $func3 = "getRunningTasks"
        $perm1 = "SYSTEM_ALERT_WINDOW"
        $perm2 = "BIND_ACCESSIBILITY_SERVICE"
    condition:
        any of ($str1, $str2) or ($perm1 and $perm2)
}

rule Android_Banker_Anubis {
    meta:
        description = "Anubis Banking Trojan"
        family = "Anubis"
        severity = "critical"
    strings:
        $str1 = "anubis"
        $str2 = "com.wolf.anubis"
        $func = "accessibilityEvent"
        $perm1 = "BIND_ACCESSIBILITY_SERVICE"
        $perm2 = "REQUEST_INSTALL_PACKAGES"
    condition:
        any of ($str1, $str2) or ($perm1 and $perm2)
}

rule Android_Banker_BlackRock {
    meta:
        description = "BlackRock Banking Trojan (Cerberus fork)"
        family = "BlackRock"
        severity = "critical"
    strings:
        $str = "blackrock"
        $func1 = "overlay_inject"
        $func2 = "keylogger"
        $func3 = "accessibility_service_config"
    condition:
        any of ($str, $func2) and any of ($func1, $func3)
}

// ===== SPYWARE =====

rule Android_Spyware_Pegasus {
    meta:
        description = "Pegasus spyware indicators (NSO Group)"
        family = "Pegasus"
        severity = "critical"
    strings:
        $cve1 = "CVE-2019-2215"
        $cve2 = "CVE-2020-0041"
        $cve3 = "CVE-2021-0399"
        $exploit = "FORCEDENTRY"
        $func = "CVE-2017-13286"
        $perm1 = "READ_LOGS"
        $perm2 = "DUMP"
    condition:
        any of ($cve1, $cve2, $cve3, $exploit) or (any of ($func, $perm1) and $perm2)
}

rule Android_Spyware_mSpy {
    meta:
        description = "mSpy commercial spyware"
        family = "mSpy"
        severity = "high"
    strings:
        $str1 = "mspy"
        $str2 = "com.mspy"
        $func1 = "recordCall"
        $func2 = "monitorMessages"
        $perm1 = "RECORD_AUDIO"
        $perm2 = "READ_SMS"
        $perm3 = "READ_CALL_LOG"
        $perm4 = "ACCESS_FINE_LOCATION"
    condition:
        any of ($str1, $str2) or all of ($perm1, $perm2, $perm3, $perm4)
}

// ===== CRYPTO MINERS =====

rule Android_Miner_XMRig {
    meta:
        description = "XMRig Cryptominer embedded in Android app"
        family = "XMRig"
        severity = "critical"
    strings:
        $str1 = "xmrig"
        $str2 = "cryptonight"
        $str3 = "stratum+tcp"
        $str4 = "mining.subscribe"
        $str5 = "randomx"
        $str6 = "rx/0"
        $pool1 = "pool.minexmr.com"
        $pool2 = "xmrpool.eu"
    condition:
        any of ($str1, $str2, $str3) or any of ($pool1, $pool2)
}

rule Android_Miner_CoinHive {
    meta:
        description = "CoinHive/Web-based cryptominer"
        family = "CoinHive"
        severity = "critical"
    strings:
        $str1 = "coinhive"
        $str2 = "coin-hive"
        $str3 = "cryptoloot"
        $str4 = "webminer"
        $str5 = "authedmine"
        $str6 = "WebAssembly"
        $func = "setJavaScriptEnabled"
    condition:
        any of ($str1, $str2, $str3, $str4, $str5) and $func
}

// ===== RANSOMWARE =====

rule Android_Ransomware_FileCoder {
    meta:
        description = "Android Filecoder ransomware"
        family = "FileCoder"
        severity = "critical"
    strings:
        $func1 = "encrypt"
        $func2 = "decrypt"
        $func3 = "Cipher"
        $ext1 = ".enc"
        $ext2 = ".locked"
        $ext3 = ".crypted"
    condition:
        any of ($func1, $func3) and any of ($ext1, $ext2, $ext3)
}

rule Android_Ransomware_Locker {
    meta:
        description = "Android screen locker ransomware"
        family = "Locker"
        severity = "critical"
    strings:
        $perm1 = "SYSTEM_ALERT_WINDOW"
        $func1 = "lockNow"
        $func2 = "resetPassword"
        $func3 = "DevicePolicyManager"
        $str1 = "ransom"
        $str2 = "bitcoin"
    condition:
        ($perm1 and any of ($func1, $func2, $func3)) or ($str1 and $str2)
}

// ===== PACKERS / PROTECTORS =====

rule Android_Packer_Jiagu {
    meta:
        description = "360 Jiagu Packer detection"
        family = "Jiagu"
        severity = "high"
    strings:
        $pkg = "com.stub.StubApp"
        $pkg2 = "com.qihoo.util"
        $lib = "libjiagu"
        $str1 = "jiagu"
        $str2 = "AppService"
    condition:
        any of ($pkg, $pkg2, $lib, $str1)
}

rule Android_Packer_Bangcle {
    meta:
        description = "Bangcle/SecShell Packer detection"
        family = "Bangcle"
        severity = "high"
    strings:
        $pkg = "com.secneo.apkwrapper"
        $pkg2 = "com.bangcle"
        $lib = "libDexHelper"
        $class = "SecShell"
    condition:
        any of ($pkg, $pkg2, $lib)
}

rule Android_Packer_DexProtector {
    meta:
        description = "DexProtector detection"
        family = "DexProtector"
        severity = "high"
    strings:
        $pkg = "com.dexprotector"
        $lib = "libdexprotector"
        $class = "DexProtector"
    condition:
        any of ($pkg, $lib, $class)
}

// ===== ANTI-ANALYSIS =====

rule Android_AntiAnalysis_DebuggerDetection {
    meta:
        description = "Debugger detection techniques"
        family = "Anti-Analysis"
        severity = "high"
    strings:
        $str1 = "isDebuggerConnected"
        $str2 = "android.os.Debug"
        $str3 = "waitForDebugger"
        $str4 = "ptrace"
        $str5 = "TracerPid"
        $str6 = "/proc/self/status"
    condition:
        any of ($str1, $str2, $str3) or ($str4 and any of ($str5, $str6))
}

rule Android_AntiAnalysis_EmulatorDetection {
    meta:
        description = "Emulator/VM detection"
        family = "Anti-Analysis"
        severity = "high"
    strings:
        $str1 = "Build.FINGERPRINT"
        $str2 = "Build.MANUFACTURER"
        $str3 = "Build.MODEL"
        $str4 = "Build.PRODUCT"
        $str5 = "generic"
        $str6 = "qemu"
        $str7 = "vbox"
        $str8 = "goldfish"
    condition:
        any of ($str1, $str2, $str3, $str4) and any of ($str5, $str6, $str7, $str8)
}

rule Android_AntiAnalysis_RootDetection {
    meta:
        description = "Root/jailbreak detection"
        family = "Anti-Analysis"
        severity = "high"
    strings:
        $str1 = "superuser"
        $str2 = "SuperSU"
        $str3 = "Magisk"
        $str4 = "su binary"
        $str5 = "which su"
        $str6 = "test-keys"
        $str7 = "ro.build.tags"
        $str8 = "/system/app/Superuser.apk"
    condition:
        3 of ($str*)
}

rule Android_AntiAnalysis_FridaDetection {
    meta:
        description = "Frida/Xposed detection"
        family = "Anti-Analysis"
        severity = "high"
    strings:
        $str1 = "frida"
        $str2 = "frida-server"
        $str3 = "xposed"
        $str4 = "XposedBridge"
        $str5 = "de.robv.android.xposed"
        $str6 = "XposedHelpers"
    condition:
        any of ($str*)
}

// ===== DATA EXFILTRATION =====

rule Android_DataExfil_SMS_Exfiltration {
    meta:
        description = "SMS data exfiltration"
        family = "SMS Stealer"
        severity = "critical"
    strings:
        $func1 = "READ_SMS"
        $func2 = "SEND_SMS"
        $func3 = "getMessageBody"
        $func4 = "getOriginatingAddress"
        $send = "sendTextMessage"
        $http = "HttpURLConnection"
        $http2 = "OkHttpClient"
    condition:
        ($func1 and any of ($func3, $func4)) and any of ($http, $http2)
}

rule Android_DataExfil_Contacts_Exfil {
    meta:
        description = "Contact list exfiltration"
        family = "Contact Stealer"
        severity = "critical"
    strings:
        $func1 = "READ_CONTACTS"
        $func2 = "getContentResolver"
        $func3 = "ContactsContract"
        $func4 = "query"
        $http = "HttpURLConnection"
        $http2 = "OkHttpClient"
    condition:
        ($func1 and any of ($func2, $func3, $func4)) and any of ($http, $http2)
}

// ===== ADWARE =====

rule Android_Adware_HiddenAds {
    meta:
        description = "HiddenAds/Fraud adware"
        family = "HiddenAds"
        severity = "medium"
    strings:
        $str1 = "webView"
        $str2 = "loadUrl"
        $str3 = "setJavaScriptEnabled"
        $str4 = "shouldOverrideUrlLoading"
        $perm1 = "SYSTEM_ALERT_WINDOW"
        $perm2 = "REQUEST_INSTALL_PACKAGES"
    condition:
        all of ($str1, $str3) and ($perm1 or $perm2)
}

// ===== COMMAND EXECUTION =====

rule Android_Shell_RuntimeExec {
    meta:
        description = "Runtime command execution capability"
        family = "Shell Exec"
        severity = "high"
    strings:
        $exec1 = "Runtime.getRuntime().exec"
        $exec2 = "ProcessBuilder"
        $exec3 = "start("
        $cmd1 = "/system/bin/sh"
        $cmd2 = "su -c"
        $cmd3 = "chmod"
    condition:
        (any of ($exec1, $exec2) and any of ($cmd1, $cmd2)) or ($exec3 and any of ($cmd1, $cmd2, $cmd3))
}

// ===== UNPACKING / DEX LOADING =====

rule Android_Unpack_DynamicDex {
    meta:
        description = "Dynamic DEX loading - potential packed malware"
        family = "DEX Loader"
        severity = "high"
    strings:
        $func1 = "DexClassLoader"
        $func2 = "PathClassLoader"
        $func3 = "InMemoryDexClassLoader"
        $func4 = "loadClass"
        $func5 = "Class.forName"
        $ref1 = "Method.invoke"
    condition:
        any of ($func1, $func2, $func3) and any of ($func4, $func5, $ref1)
}
