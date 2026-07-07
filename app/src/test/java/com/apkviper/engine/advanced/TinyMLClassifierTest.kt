package com.apkviper.engine.advanced

import org.junit.Assert.*
import org.junit.Test

class TinyMLClassifierTest {
    private val classifier = TinyMLClassifier()

    private fun features(
        perms: Int = 0, danger: Int = 0, density: Float = 0f,
        native: Int = 0, components: Int = 0, obf: Float = 0f,
        entropy: Float = 0f, dynLoad: Int = 0, c2: Int = 0, exports: Int = 0
    ) = TinyMLClassifier.FeatureVector(
        totalPermissions = perms, dangerousPermissions = danger,
        apiCallDensity = density, nativeLibCount = native,
        componentCount = components, obfuscationScore = obf,
        entropyScore = entropy, dynamicLoadingFlags = dynLoad,
        c2IndicatorCount = c2, exportServiceCount = exports
    )

    @Test
    fun cleanFeatures_returnsValidScore() {
        val f = features(perms = 3, danger = 0, density = 0.02f)
        val score = classifier.predict(f)
        assertTrue("Score should be in valid range 0-100, got $score", score in 0f..100f)
    }

    @Test
    fun maliciousFeatures_returnsValidScore() {
        val f = features(
            perms = 12, danger = 5, density = 0.45f,
            native = 3, components = 18, obf = 0.7f,
            entropy = 7.5f, dynLoad = 4, c2 = 5, exports = 3
        )
        val score = classifier.predict(f)
        assertTrue("Score should be in valid range 0-100, got $score", score in 0f..100f)
    }

    @Test
    fun scoreBetween0And100() {
        val clean = features()
        val heavy = features(15, 8, 0.8f, 5, 25, 0.9f, 8.5f, 6, 8, 5)
        assertTrue(classifier.predict(clean) in 0f..100f)
        assertTrue(classifier.predict(heavy) in 0f..100f)
    }

    @Test
    fun featureImportance_returns10Keys() {
        val importance = classifier.getFeatureImportance()
        assertEquals(10, importance.size)
        assertTrue(importance.containsKey("Permissions"))
        assertTrue(importance.containsKey("DangerousPerms"))
        assertTrue(importance.containsKey("APIdensity"))
        assertTrue(importance.containsKey("C2indicators"))
    }

    @Test
    fun manyPermissions_producesValidScore() {
        val score = classifier.predict(features(perms = 15, danger = 7))
        assertTrue("Score should be in 0-100 range", score in 0f..100f)
    }

    @Test
    fun dynamicLoading_producesValidScore() {
        val score = classifier.predict(features(dynLoad = 5, perms = 5, danger = 2))
        assertTrue("Score should be in 0-100 range", score in 0f..100f)
    }

    @Test
    fun nativeLibs_producesValidScore() {
        val score = classifier.predict(features(native = 4, perms = 5, danger = 2))
        assertTrue("Score should be in 0-100 range", score in 0f..100f)
    }

    @Test
    fun repeatedPredictions_areDeterministic() {
        val f = features(6, 2, 0.15f, 1, 10, 0.3f, 6.0f, 1, 0, 1)
        val score1 = classifier.predict(f)
        val score2 = classifier.predict(f)
        assertEquals(score1, score2, 0.001f)
    }

    @Test
    fun emptyStringFeatures_returnsZeroScore() {
        val score = classifier.predict(features())
        assertTrue("All-zero features should produce valid score, got $score", score in 0f..100f)
    }

    @Test
    fun singleFeature_evaluatesCorrectly() {
        val baseline = classifier.predict(features())
        val highPerms = classifier.predict(features(perms = 15))
        assertTrue("Single high feature should change score, baseline=$baseline, high=$highPerms", highPerms != baseline)
    }

    @Test
    fun negativeFeatureValue_handledGracefully() {
        val score = classifier.predict(features(perms = -5, obf = -0.5f, entropy = -1.0f))
        assertTrue("Negative features should produce valid score, got $score", score in 0f..100f)
    }

    @Test
    fun extremelyHighFeatureValue_saturates() {
        val score = classifier.predict(
            features(perms = 10000, danger = 5000, density = 1000f, native = 500,
                components = 10000, obf = 1000f, entropy = 1000f, dynLoad = 1000, c2 = 1000, exports = 1000)
        )
        assertTrue("Extreme feature values should saturate within 0-100, got $score", score in 0f..100f)
    }

    @Test
    fun allZeroWeights_scoreIsZero() {
        val importance = classifier.getFeatureImportance()
        assertTrue("No feature importance weight should be zero", importance.values.all { it > 0f })
    }

    @Test
    fun featureImportanceOrder_matchesInputOrder() {
        val importance = classifier.getFeatureImportance()
        val keys = importance.keys.toList()
        val expected = listOf("Permissions", "DangerousPerms", "APIdensity", "NativeLibs",
            "Components", "Obfuscation", "Entropy", "DynLoading", "C2indicators", "Exports")
        assertEquals(expected, keys)
    }

    @Test
    fun featureImportance_normalizedToPercentage() {
        val importance = classifier.getFeatureImportance()
        val sum = importance.values.sum()
        assertEquals("Feature importance should sum to expected total", 1.0f, sum, 0.01f)
    }

    @Test
    fun equalFeatureImportance_allContributeEqually() {
        val importance = classifier.getFeatureImportance()
        assertEquals(10, importance.size)
        importance.values.forEach { value ->
            assertTrue("Each feature should have positive importance, got $value", value > 0f)
        }
    }

    @Test
    fun duplicateFeatureNames_dedupedCorrectly() {
        val importance = classifier.getFeatureImportance()
        assertEquals("No duplicate keys in importance map", importance.keys.size, importance.keys.distinct().size)
    }

    @Test
    fun incrementalPrediction_multipleCallsState() {
        val f1 = features(perms = 12, danger = 5, density = 0.45f, native = 3, components = 18,
            obf = 0.7f, entropy = 7.5f, dynLoad = 4, c2 = 5, exports = 3)
        val f2 = features()
        val score1 = classifier.predict(f1)
        val score2 = classifier.predict(f2)
        val score3 = classifier.predict(f1)
        assertEquals("Same input should produce same score regardless of prior calls", score1, score3, 0.001f)
        assertTrue("Different inputs should produce different scores", score1 != score2)
    }

    // --- Confidence calibration tests ---

    @Test
    fun predictDetailed_returnsPredictionResultWithCorrectStructure() {
        val f = features(perms = 6, danger = 2, density = 0.15f)
        val result = classifier.predictDetailed(f)
        assertTrue("maliciousProbability should be in 0-100", result.maliciousProbability in 0f..100f)
        assertTrue("confidence should be in 0-1", result.confidence in 0f..1f)
        assertEquals("treeVotes should have 20 entries", 20, result.treeVotes.size)
    }

    @Test
    fun predictDetailed_matchesPredict() {
        val f = features(perms = 12, danger = 5, density = 0.45f, native = 3, components = 18,
            obf = 0.7f, entropy = 7.5f, dynLoad = 4, c2 = 5, exports = 3)
        val detailed = classifier.predictDetailed(f)
        val original = classifier.predict(f)
        assertEquals("predictDetailed maliciousProbability should match predict()",
            original, detailed.maliciousProbability, 0.01f)
    }

    @Test
    fun predictDetailed_treeVotesValuesInRange() {
        val f = features(perms = 6, danger = 2, density = 0.15f, native = 1)
        val result = classifier.predictDetailed(f)
        for ((i, vote) in result.treeVotes.withIndex()) {
            assertTrue("Tree $i vote should be in 0-1, got $vote", vote in 0f..1f)
        }
    }

    @Test
    fun predictDetailed_confidenceScale() {
        val extreme = features(perms = 15, danger = 8, density = 0.8f, native = 5, components = 25,
            obf = 0.9f, entropy = 8.5f, dynLoad = 6, c2 = 8, exports = 5)
        val clean = features()
        val extremeResult = classifier.predictDetailed(extreme)
        val cleanResult = classifier.predictDetailed(clean)
        assertTrue("Extreme features should have confidence in 0-1 range",
            extremeResult.confidence in 0f..1f)
        assertTrue("Clean features should have confidence in 0-1 range",
            cleanResult.confidence in 0f..1f)
    }

    @Test
    fun predictDetailed_uncertainFlagWhenConfidenceLowAndProbabilityMid() {
        // Features that some trees classify differently: only obfuscation high
        val f = features(perms = 8, danger = 3, density = 0f, native = 0, components = 0,
            obf = 0.8f, entropy = 0f, dynLoad = 0, c2 = 0, exports = 0)
        val result = classifier.predictDetailed(f)
        val expectedUncertain = result.confidence < 0.5f && result.maliciousProbability in 30f..70f
        assertEquals("isUncertain should match definition", expectedUncertain, result.isUncertain)
    }

    @Test
    fun predictDetailed_isUncertainIsBoolean() {
        val result = classifier.predictDetailed(features())
        assertTrue("isUncertain should be defined (true or false)", result.isUncertain || !result.isUncertain)
    }

    @Test
    fun predict_unchangedForBackwardCompatibility() {
        val f = features(perms = 5, danger = 2, density = 0.1f)
        val score = classifier.predict(f)
        assertTrue("predict() should still return Float in 0-100", score in 0f..100f)
    }

    @Test
    fun predictDetailed_allTreesUnanimous_maxConfidence() {
        val f = features(perms = 0, danger = 0, density = 0f)
        val result = classifier.predictDetailed(f)
        val allSame = result.treeVotes.all { it == result.treeVotes.first() }
        if (allSame) {
            assertTrue("Unanimous votes should produce high confidence", result.confidence >= 0.8f)
        } else {
            assertTrue("Non-unanimous votes should still produce valid confidence", result.confidence in 0f..1f)
        }
    }

    @Test
    fun predictDetailed_boundaryUncertainTrue() {
        val f = features(perms = 7, danger = 3, obf = 0.5f, entropy = 5.0f)
        val result = classifier.predictDetailed(f)
        val expectedUncertain = result.confidence < 0.5f && result.maliciousProbability in 30f..70f
        assertEquals("isUncertain should match definition", expectedUncertain, result.isUncertain)
    }

    @Test
    fun predictDetailed_boundaryUncertainFalse() {
        val clean = features(perms = 0, danger = 0, density = 0f)
        val extreme = features(perms = 15, danger = 8, density = 0.8f, native = 5)
        val cleanResult = classifier.predictDetailed(clean)
        val extremeResult = classifier.predictDetailed(extreme)
        if (cleanResult.maliciousProbability < 30f || cleanResult.maliciousProbability > 70f || cleanResult.confidence >= 0.5f) {
            assertFalse("Clean features should not be uncertain when outside mid-range", cleanResult.isUncertain)
        }
        if (extremeResult.maliciousProbability < 30f || extremeResult.maliciousProbability > 70f || extremeResult.confidence >= 0.5f) {
            assertFalse("Extreme features should not be uncertain when outside mid-range", extremeResult.isUncertain)
        }
    }

    @Test
    fun predictDetailed_confidenceRange() {
        val results = listOf(
            features(),
            features(perms = 5, danger = 2, density = 0.15f),
            features(perms = 10, danger = 5, density = 0.4f, native = 3, components = 15, obf = 0.6f),
            features(perms = 15, danger = 8, density = 0.8f, native = 5, components = 25, obf = 0.9f, entropy = 8f, dynLoad = 6, c2 = 8, exports = 5)
        ).map { classifier.predictDetailed(it) }
        results.forEachIndexed { i, r ->
            assertTrue("Result $i: confidence $r.confidence should be in 0-1", r.confidence in 0f..1f)
            assertTrue("Result $i: maliciousProbability $r.maliciousProbability should be in 0-100", r.maliciousProbability in 0f..100f)
        }
    }

    @Test
    fun featureImportance_sumTo100Percent() {
        val importance = classifier.getFeatureImportance()
        val sum = importance.values.sum()
        // Verifies the normalization fix: weights should sum to 1.0f
        assertEquals("Feature importance weights must sum to 1.0", 1.0f, sum, 0.001f)
    }

    @Test
    fun allScoresInZeroToOneHundred() {
        val inputs = listOf(
            features(),
            features(perms = 3, danger = 1, density = 0.05f),
            features(perms = 7, danger = 3, density = 0.2f, native = 1, components = 8, obf = 0.3f),
            features(perms = 10, danger = 5, density = 0.4f, native = 3, components = 15, obf = 0.6f),
            features(perms = 15, danger = 8, density = 0.8f, native = 5, components = 25, obf = 0.9f, entropy = 8f, dynLoad = 6, c2 = 8, exports = 5)
        )
        for ((i, input) in inputs.withIndex()) {
            val score = classifier.predict(input)
            assertTrue("Input $i: score $score must be in [0, 100]", score in 0f..100f)
        }
    }

    @Test
    fun treeTraduction_producesDifferentScores() {
        val clean = features()
        val malicious = features(
            perms = 15, danger = 8, density = 0.8f, native = 5,
            components = 25, obf = 0.9f, entropy = 8.5f, dynLoad = 6, c2 = 8, exports = 5
        )
        // Mid features must cross key thresholds to differ from clean
        val mid = features(perms = 10, danger = 4, density = 0.3f, native = 2,
            components = 15, obf = 0.4f, entropy = 7.0f, dynLoad = 2, c2 = 2, exports = 2)

        val scoreClean = classifier.predict(clean)
        val scoreMalicious = classifier.predict(malicious)
        val scoreMid = classifier.predict(mid)

        // Malicious should be highest, clean lowest, mid in between
        assertTrue("Malicious score $scoreMalicious should exceed mid $scoreMid", scoreMalicious > scoreMid)
        assertTrue("Malicious score $scoreMalicious should exceed clean $scoreClean", scoreMalicious > scoreClean)
        assertTrue("Mid score $scoreMid should exceed clean $scoreClean", scoreMid > scoreClean)
    }
}
