package com.apkviper.engine.taint

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class TaintAnalyzerTest {
    private val analyzer = TaintAnalyzer()

    private fun decompileResult(
        javaSource: Map<String, String> = mapOf("A.java" to ""),
        smaliSource: Map<String, String> = mapOf()
    ): DecompileResult =
        DecompileResult(javaSource, smaliSource, "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun cleanCode_noFindings() {
        val result = decompileResult(mapOf("A.java" to "package com.example; class A {}"))
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun sourceOnly_noFindings() {
        val code = "getDeviceId()"
        val result = decompileResult(mapOf("A.java" to code))
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun sinkOnly_noFindings() {
        val code = "HttpURLConnection conn = null"
        val result = decompileResult(mapOf("A.java" to code))
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun sourcePlusSinkPlusObfuscation_criticalExfiltration() {
        val code = """
            String imei = getDeviceId();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            String encrypted = Base64.encode(imei.getBytes());
        """.trimIndent()
        val result = decompileResult(mapOf("Main.java" to code))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.severity == Severity.CRITICAL && it.title.contains("Confirmed Data Exfiltration") })
    }

    @Test
    fun sourcePlusSinkNoObfuscation_mediumConfidence() {
        val code = """
            String imei = getDeviceId();
            String subscriber = getSubscriberId();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        """.trimIndent()
        val result = decompileResult(mapOf("Main.java" to code))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.severity == Severity.MEDIUM && it.title.contains("Data Collection + Network") })
    }

    @Test
    fun singleSourcePlusSinkNoObfuscation_noFinding() {
        val code = """
            String imei = getDeviceId();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        """.trimIndent()
        val result = decompileResult(mapOf("Main.java" to code))
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title.contains("Data Collection + Network") })
    }

    @Test
    fun multipleClassesCrossClass_detected() {
        val source = mapOf(
            "DeviceReader.java" to "getDeviceId()",
            "LocationReader.java" to "getLastKnownLocation(provider)",
            "NetworkWriter.java" to "HttpURLConnection conn = null",
            "SocketWriter.java" to "Socket sock = null",
            "Obfuscator.java" to "Base64.encode(data)",
            "Encryptor.java" to "Cipher.getInstance(\"AES\")"
        )
        val result = decompileResult(javaSource = source)
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Multi-Class Exfiltration Architecture") })
    }

    @Test
    fun smaliDefUseChain_detected() {
        val smali = """
invoke-static {}, Landroid/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;
move-result-object v0
invoke-virtual {v0}, Ljava/net/Socket->connect()V
        """.trimIndent()
        val result = decompileResult(
            javaSource = mapOf("A.java" to "getDeviceId()"),
            smaliSource = mapOf("A.smali" to smali)
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Def-Use Chain") })
    }

    @Test
    fun smaliDefUseWithoutSink_notDetected() {
        val smali = """
            invoke-static {}, Landroid/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;
            move-result-object v0
            const-string v1, "hello"
        """.trimIndent()
        val result = decompileResult(
            javaSource = mapOf("A.java" to ""),
            smaliSource = mapOf("A.smali" to smali)
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.none { it.title.contains("Def-Use Chain") })
    }

    @Test
    fun verboseLogging_detected() {
        val logs = (1..25).joinToString("\n") { "Log.d(\"Tag\", \"msg $it\")" }
        val result = decompileResult(mapOf("A.java" to logs))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Verbose Logging") })
        assertEquals(Severity.LOW, findings.find { it.title.contains("Verbose Logging") }!!.severity)
    }

    @Test
    fun moderateLogging_notFlagged() {
        val logs = (1..10).joinToString("\n") { "Log.d(\"Tag\", \"msg $it\")" }
        val result = decompileResult(mapOf("A.java" to logs))
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title.contains("Verbose Logging") })
    }

    @Test
    fun locationSourceWithSink_detected() {
        val code = """
            getLastKnownLocation(LocationManager.GPS_PROVIDER);
            requestLocationUpdates();
            OkHttpClient client = new OkHttpClient();
            Base64.encode(data);
        """.trimIndent()
        val result = decompileResult(mapOf("Tracker.java" to code))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Confirmed Data Exfiltration") })
    }

    @Test
    fun contactsSourceWithSink_detected() {
        val code = """
            Cursor c = getContentResolver().query(ContactsContract.Contacts.CONTENT_URI, null, null, null, null);
            Socket socket = new Socket("host", 9999);
            encrypt(data);
        """.trimIndent()
        val result = decompileResult(mapOf("Leak.java" to code))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Confirmed Data Exfiltration") })
    }

    @Test
    fun noSourcesInCode_noFindings() {
        val result = decompileResult(mapOf("A.java" to "int x = 1 + 2;"))
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun emptyJavaSource_noFindings() {
        val result = decompileResult(mapOf())
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun caseInsensitiveMatching() {
        val code = "GETDEVICEID() HTTPURLCONNECTION BASE64.ENCODE"
        val result = decompileResult(mapOf("A.java" to code))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Confirmed Data Exfiltration") })
    }

    @Test
    fun obfuscationIndicators_allRecognized() {
        val obfuscationPatterns = listOf(
            "Cipher.getInstance", "MessageDigest", "SecretKeySpec",
            "GZIPOutputStream", "Inflater", "StringBuilder.append", "encrypt", "decrypt"
        )
        for (pattern in obfuscationPatterns) {
            val code = """
                getDeviceId();
                HttpURLConnection conn;
                $pattern
            """.trimIndent()
            val result = decompileResult(mapOf("Test.java" to code))
            val findings = analyzer.analyze(result)
            assertTrue("Pattern '$pattern' should trigger obfuscation detection", findings.any { it.title.contains("Exfiltration") })
        }
    }

    @Test
    fun sinkPatterns_allRecognized() {
        val sinkPatterns = listOf(
            "OkHttpClient", "okhttp3.Call.execute", "Retrofit",
            "Socket", "sendTextMessage", "OutputStream",
            "BluetoothSocket", "BluetoothGatt", "sendBroadcast", "startService"
        )
        for (pattern in sinkPatterns) {
            val code = """
                getDeviceId();
                $pattern
                Cipher.getInstance("AES");
            """.trimIndent()
            val result = decompileResult(mapOf("Test.java" to code))
            val findings = analyzer.analyze(result)
            assertTrue("Sink '$pattern' should trigger detection", findings.any { it.title.contains("Exfiltration") })
        }
    }

    @Test
    fun findingsHaveCorrectCategory() {
        val code = """
            getDeviceId();
            HttpURLConnection conn;
            Base64.encode(data);
        """.trimIndent()
        val result = decompileResult(mapOf("A.java" to code))
        val findings = analyzer.analyze(result)
        findings.forEach { assertEquals(FindingCategory.CODE, it.category) }
    }
}
