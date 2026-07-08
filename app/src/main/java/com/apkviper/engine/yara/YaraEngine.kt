package com.apkviper.engine.yara

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import java.util.concurrent.ConcurrentHashMap

/**
 * On-device YARA-like rule engine using Aho-Corasick
 * multi-pattern string matching algorithm.
 *
 * Parses YARA-compatible rule format and matches against
 * APK smali, Java source, and manifest content.
 *
 * IMPORTANT (false-positive fix): a rule only fires when its `condition:` is
 * actually satisfied. Previously the engine fired on ANY single string match,
 * which caused rules such as `Android_Ransomware_FileCoder` (condition requires
 * an encryption verb AND a `.locked`/`.enc` extension) to trigger on ordinary
 * apps that merely contain the word "encrypt". The condition evaluator below
 * implements `any of` / `all of` / `N of` quantifiers plus `and` / `or` / `not`
 * and parentheses, so a rule fires only when its full logic holds.
 *
 * Community / auto-updated rules carry `confidence = "low"` in their meta block;
 * those matches are surfaced but (see ThreatScorer) can never alone produce a
 * MALICIOUS verdict.
 */
class YaraEngine {

    companion object {
        private const val MAX_SOURCE_SIZE = 50 * 1024 * 1024
    }

    data class YaraRule(
        val name: String,
        val meta: Map<String, String>,
        val strings: List<RuleString>,
        val condition: String
    )

    data class RuleString(
        val identifier: String,
        val value: String,
        val type: String = "text" // text, hex, regex
    )

    private val rules = mutableListOf<YaraRule>()
    private var acAutomaton: AhoCorasick? = null
    private val regexCache = ConcurrentHashMap<String, Regex>()

    @Synchronized
    fun loadRules(rulesText: String) {
        val parsed = parseRules(rulesText)
        rules.clear()
        rules.addAll(parsed)

        val patterns = parsed.flatMap { rule ->
            rule.strings.map { it.value.lowercase() }
        }
        acAutomaton = AhoCorasick(patterns)
    }

    fun scan(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val combinedSource = decompiled.allSourceText ?: run {
            val combined = (decompiled.javaSource.values + decompiled.smaliSource.values)
            if (combined.sumOf { it.length } > MAX_SOURCE_SIZE) {
                (decompiled.javaSource.values.take(200) + decompiled.smaliSource.values.take(100)).joinToString("\n")
            } else {
                combined.joinToString("\n")
            }
        }
        val allContent = combinedSource + "\n" + decompiled.manifest
        val contentLower = allContent.lowercase()

        val ac = acAutomaton
        if (ac == null) {
            android.util.Log.w("YaraEngine", "scan() called before loadRules()")
            return findings
        }
        // Use Aho-Corasick for fast multi-pattern matching
        val acMatches = ac.search(contentLower)

        // Build flat string -> index lookup (same order as Aho-Corasick patterns)
        val allPatterns = rules.flatMap { it.strings.map { s -> s.value } }
        val patternToIdx = allPatterns.withIndex().associate { (i, v) -> v to i }

        rules.forEach { rule ->
            val matchedIds = mutableListOf<String>()

            rule.strings.forEach { rs ->
                val rsIdx = patternToIdx[rs.value] ?: -1

                val found = when {
                    rs.value.startsWith("{") && rs.value.endsWith("}") -> {
                        false
                    }
                    rs.value.startsWith("/") && rs.value.endsWith("/") -> {
                        try {
                            regexCache.getOrPut(rs.value) {
                                Regex(rs.value.substring(1, rs.value.length - 1), RegexOption.IGNORE_CASE)
                            }.containsMatchIn(allContent)
                        } catch (_: Exception) { false }
                    }
                    else -> rsIdx in acMatches // Use Aho-Corasick results
                }

                if (found) matchedIds.add(rs.identifier)
            }

            // CONDITION EVALUATION -- the rule fires only if its full condition holds.
            val conditionMet = try {
                ConditionEvaluator.evaluate(rule.condition, matchedIds.toSet())
            } catch (e: Exception) {
                android.util.Log.w("YaraEngine", "Failed to evaluate condition for ${rule.name}: ${e.message}")
                false
            }

            if (conditionMet && matchedIds.isNotEmpty()) {
                val severity = when {
                    rule.name.contains("RAT", ignoreCase = true) -> Severity.CRITICAL
                    rule.name.contains("banker", ignoreCase = true) || rule.name.contains("trojan", ignoreCase = true) -> Severity.CRITICAL
                    rule.name.contains("spyware", ignoreCase = true) || rule.name.contains("spy", ignoreCase = true) -> Severity.HIGH
                    rule.name.contains("miner", ignoreCase = true) || rule.name.contains("crypto", ignoreCase = true) -> Severity.CRITICAL
                    rule.name.contains("ransom", ignoreCase = true) -> Severity.CRITICAL
                    rule.name.contains("packer", ignoreCase = true) || rule.name.contains("packed", ignoreCase = true) -> Severity.HIGH
                    rule.name.contains("stealer", ignoreCase = true) -> Severity.HIGH
                    rule.name.contains("adware", ignoreCase = true) -> Severity.MEDIUM
                    rule.name.contains("anti_analysis", ignoreCase = true) || rule.name.contains("evasion", ignoreCase = true) -> Severity.HIGH
                    else -> Severity.MEDIUM
                }

                val confidence = when (rule.meta["confidence"]?.lowercase()) {
                    "low" -> FindingConfidence.LOW
                    "medium" -> FindingConfidence.MEDIUM
                    else -> FindingConfidence.HIGH
                }

                findings.add(Finding(
                    category = FindingCategory.MALWARE,
                    severity = severity,
                    title = "YARA Match: ${rule.name}",
                    description = rule.meta["description"] ?: "Matched known malware signature",
                    details = "Matched strings: ${matchedIds.joinToString(", ")}\n" +
                              "Rule: ${rule.name}\n" +
                              "Family: ${rule.meta["family"] ?: "unknown"}\n" +
                              "Author: ${rule.meta["author"] ?: "community"}",
                    confidence = confidence,
                    ruleSource = if (confidence == FindingConfidence.LOW) "community" else "curated"
                ))
            }
        }

        return findings
    }

    private fun parseRules(rulesText: String): List<YaraRule> {
        val parsedRules = mutableListOf<YaraRule>()
        val lines = rulesText.lines()

        var currentRuleName = ""
        val currentMeta = mutableMapOf<String, String>()
        val currentStrings = mutableListOf<RuleString>()
        var currentCondition = ""
        var inStrings = false
        var inCondition = false

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("//")) continue

            when {
                trimmed.startsWith("rule ") -> {
                    if (currentRuleName.isNotEmpty()) {
                        parsedRules.add(YaraRule(currentRuleName, currentMeta.toMap(), currentStrings.toList(), currentCondition))
                        currentMeta.clear()
                        currentStrings.clear()
                        currentCondition = ""
                        inStrings = false
                        inCondition = false
                    }
                    var name = trimmed.removePrefix("rule ").removeSuffix("{").trim()
                    if (name.isEmpty()) name = "unnamed_rule_${parsedRules.size + 1}"
                    currentRuleName = name
                }
                trimmed.startsWith("strings") -> {
                    inStrings = true
                    inCondition = false
                }
                trimmed.startsWith("condition") -> {
                    inStrings = false
                    inCondition = true
                    currentCondition = trimmed.substringAfter("condition").trim().removeSuffix(":")
                }
                inStrings && trimmed.startsWith("\$") -> {
                    val parts = trimmed.split("=", limit = 2)
                    if (parts.size == 2) {
                        val id = parts[0].trim()
                        val raw = parts[1].trim()
                        val value = if (raw.startsWith("\"") && raw.indexOf("\"", 1) > 0) {
                            raw.substring(1, raw.indexOf("\"", 1))
                        } else {
                            raw.removeSurrounding("\"")
                        }
                        currentStrings.add(RuleString(id, value))
                    }
                }
                inCondition -> {
                    currentCondition += " $trimmed"
                }
                trimmed.startsWith("meta") -> {
                    // Start of meta section
                }
                trimmed.contains("=") && !trimmed.startsWith("\$") && !inStrings && !inCondition -> {
                    val parts = trimmed.split("=", limit = 2)
                    if (parts.size == 2) {
                        currentMeta[parts[0].trim()] = parts[1].trim().removeSurrounding("\"")
                    }
                }
            }
        }

        // Add last rule
        if (currentRuleName.isNotEmpty()) {
            parsedRules.add(YaraRule(currentRuleName, currentMeta.toMap(), currentStrings.toList(), currentCondition))
        }

        return parsedRules
    }

    /**
     * Recursive-descent evaluator for the subset of YARA condition syntax used by our
     * ruleset: string identifiers (`$id`, `$id*` wildcard), `any of` / `all of` / `N of`
     * quantifiers over identifier lists, plus `not`, parentheses, `and`, `or`.
     *
     * `matched` is the set of string identifiers that actually matched in the sample.
     */
    object ConditionEvaluator {

        fun evaluate(condition: String, matched: Set<String>): Boolean {
            if (condition.isBlank()) return false
            val tokens = tokenize(condition)
            if (tokens.isEmpty()) return false
            val parser = Parser(tokens, matched)
            return try {
                parser.parseOr()
            } catch (e: Exception) {
                false
            }
        }

        private fun tokenize(cond: String): List<String> {
            val tokens = mutableListOf<String>()
            var i = 0
            while (i < cond.length) {
                val c = cond[i]
                when {
                    c.isWhitespace() -> i++
                    c == '(' || c == ')' || c == ',' -> { tokens.add(c.toString()); i++ }
                    c == '$' -> {
                        var j = i + 1
                        while (j < cond.length && (cond[j].isLetterOrDigit() || cond[j] == '_' || cond[j] == '*')) j++
                        tokens.add(cond.substring(i, j)); i = j
                    }
                    c.isLetterOrDigit() || c == '_' -> {
                        var j = i
                        while (j < cond.length && (cond[j].isLetterOrDigit() || cond[j] == '_' || cond[j] == '.')) j++
                        tokens.add(cond.substring(i, j)); i = j
                    }
                    else -> i++ // skip unknown chars
                }
            }
            return tokens
        }

        private class Parser(private val tokens: List<String>, private val matched: Set<String>) {
            private var pos = 0

            fun parseOr(): Boolean {
                var value = parseAnd()
                while (peek() == "or") {
                    next()
                    value = value || parseAnd()
                }
                return value
            }

            private fun parseAnd(): Boolean {
                var value = parseFactor()
                while (peek() == "and") {
                    next()
                    value = value && parseFactor()
                }
                return value
            }

            private fun parseFactor(): Boolean {
                return when (peek()) {
                    "not" -> { next(); !parseFactor() }
                    "(" -> {
                        next()
                        val v = parseOr()
                        if (peek() == ")") next()
                        v
                    }
                    "any", "all" -> parseQuantifier(peek()!!)
                    else -> {
                        val tok = peek()
                        if (tok != null && tok.matches(Regex("^\\d+$"))) parseQuantifier(tok)
                        else parseAtom()
                    }
                }
            }

            private fun parseQuantifier(kind: String): Boolean {
                when (kind) {
                    "any" -> { next(); expect("of") }
                    "all" -> { next(); expect("of") }
                    else -> { next(); expect("of") }
                }
                expect("(")
                val list = mutableListOf<String>()
                while (peek() != ")") {
                    val t = peek()
                    if (t == null) break
                    if (t != ",") list.add(t)
                    next()
                }
                expect(")")
                val results = list.map { resolveIdentifier(it) }
                return when (kind) {
                    "any" -> results.any { it }
                    "all" -> results.all { it } && results.isNotEmpty()
                    else -> {
                        val n = kind.toIntOrNull() ?: 1
                        results.count { it } >= n
                    }
                }
            }

            private fun parseAtom(): Boolean {
                val tok = peek()
                return if (tok != null) { next(); resolveIdentifier(tok) } else false
            }

            private fun resolveIdentifier(id: String): Boolean {
                if (id.startsWith("$")) {
                    return if (id.endsWith("*")) {
                        val prefix = id.removeSuffix("*")
                        matched.any { it.startsWith(prefix) }
                    } else {
                        matched.contains(id)
                    }
                }
                return false
            }

            private fun peek(): String? = tokens.getOrNull(pos)
            private fun next() { pos++ }
            private fun expect(t: String) { if (peek() == t) pos++ }
        }
    }

    /**
     * Aho-Corasick automaton for efficient multi-pattern string matching.
     * Time: O(n + m + z) where n = text length, m = total pattern length, z = matches
     */
    class AhoCorasick(patterns: List<String>) {
        private val root = Node()
        val patternToIndex: Map<String, Int> = patterns.withIndex().associate { (i, p) -> p to i }

        init {
            buildTrie(patterns)
            buildFailureLinks()
        }

        private class Node {
            val children = mutableMapOf<Char, Node>()
            var fail: Node = this
            val outputs = mutableListOf<Int>() // pattern indices that end here
            var depth = 0
        }

        private fun buildTrie(patterns: List<String>) {
            patterns.forEachIndexed { index, pattern ->
                var node = root
                pattern.forEach { char ->
                    node = node.children.getOrPut(char) { Node().also { it.depth = node.depth + 1 } }
                }
                node.outputs.add(index)
            }
        }

        private fun buildFailureLinks() {
            val queue = ArrayDeque<Node>()
            root.children.values.forEach { child ->
                child.fail = root
                queue.add(child)
            }

            while (queue.isNotEmpty()) {
                val current = queue.removeFirst()
                current.children.forEach { (char, child) ->
                    queue.add(child)
                    var fallback = current.fail
                    while (fallback != root && char !in fallback.children) {
                        fallback = fallback.fail
                    }
                    child.fail = fallback.children[char] ?: root
                    child.outputs.addAll(child.fail.outputs)
                }
            }
        }

        fun search(text: String): Map<Int, List<Int>> {
            val matches = mutableMapOf<Int, MutableList<Int>>()
            var node = root

            text.forEachIndexed { index, char ->
                while (node != root && char !in node.children) {
                    node = node.fail
                }
                node = node.children[char] ?: root

                node.outputs.forEach { patternIndex ->
                    matches.getOrPut(patternIndex) { mutableListOf() }.add(index)
                }
            }

            return matches
        }
    }
}
