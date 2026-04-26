package com.adblocker.filter.parser

import com.adblocker.filter.rules.FilterRule
import com.adblocker.filter.rules.RuleOption
import com.adblocker.utils.Logger
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader

/**
 * filter.parser — EasyListParser
 *
 * Parses Adblock Plus / EasyList / uBlock Origin compatible filter list syntax.
 *
 * Handles:
 *   ! comments
 *   ## cosmetic rules (element hiding)
 *   #@# cosmetic exceptions
 *   ||domain^ domain-anchored network rules
 *   @@exception whitelist rules
 *   /regex/ raw regex rules (skipped — too slow on Android)
 *   plain URL substring rules
 *   $option,option network rule options
 *
 * NOTE: Returns a List (not a Sequence) to avoid premature stream closure.
 */
object EasyListParser {

    private const val TAG = "EasyListParser"

    /**
     * Parse the entire stream and return all valid rules as a list.
     * The stream is read fully before returning so callers can close it safely.
     */
    fun parse(stream: InputStream): Sequence<FilterRule> {
        val rules = mutableListOf<FilterRule>()
        val reader = BufferedReader(InputStreamReader(stream, Charsets.UTF_8))
        var lineNumber = 0
        reader.use { r ->
            r.forEachLine { line ->
                lineNumber++
                val trimmed = line.trim()
                if (trimmed.isNotEmpty()) {
                    try {
                        val rule = parseLine(trimmed)
                        if (rule != null && rule !is FilterRule.Comment) {
                            rules.add(rule)
                        }
                    } catch (e: Exception) {
                        Logger.d(TAG, "Parse error on line $lineNumber: ${e.message}")
                    }
                }
            }
        }
        return rules.asSequence()
    }

    // -------------------------------------------------------------------------
    //  Line parsing
    // -------------------------------------------------------------------------

    private fun parseLine(line: String): FilterRule? {
        return when {
            line.startsWith("!")        -> FilterRule.Comment
            line.startsWith("[")        -> FilterRule.Comment
            line.startsWith("##")       -> parseCosmeticRule(line, emptyList(), isException = false)
            line.startsWith("#@#")      -> parseCosmeticRule(line, emptyList(), isException = true)
            line.contains("##")        -> parseDomainCosmeticRule(line, isException = false)
            line.contains("#@#")       -> parseDomainCosmeticRule(line, isException = true)
            line.startsWith("@@")       -> parseNetworkRule(line.substring(2), isException = true)
            line.startsWith("/") && line.endsWith("/") -> null  // skip regex — too expensive
            else                        -> parseNetworkRule(line, isException = false)
        }
    }

    // -------------------------------------------------------------------------
    //  Network rules
    // -------------------------------------------------------------------------

    private fun parseNetworkRule(raw: String, isException: Boolean): FilterRule? {
        if (raw.isBlank()) return null

        val dollarIdx = raw.lastIndexOf('$')
        val (pattern, optionsStr) = if (dollarIdx > 0 && dollarIdx < raw.length - 1) {
            raw.substring(0, dollarIdx) to raw.substring(dollarIdx + 1)
        } else {
            raw to ""
        }

        val options = parseOptions(optionsStr)

        if (pattern.startsWith("||")) {
            val domain = pattern.substring(2).trimEnd('^', '/', '*')
            if (domain.isNotBlank()) {
                return FilterRule.NetworkRule(
                    pattern = domain,
                    isException = isException,
                    domainAnchored = true,
                    options = options
                )
            }
        }

        val cleaned = pattern.trimStart('|').trimEnd('^')
        if (cleaned.isNotBlank()) {
            return FilterRule.NetworkRule(
                pattern = cleaned,
                isException = isException,
                domainAnchored = false,
                options = options
            )
        }

        return null
    }

    private fun parseOptions(optionsStr: String): Set<RuleOption> {
        if (optionsStr.isBlank()) return emptySet()
        // Fix #6: trimStart('~') убирал '~' но возвращал то же значение — инвертированные
        // опции (~script, ~image и т.д.) интерпретировались как прямые. Тысячи правил
        // EasyList типа @@...~script становились противоположными по смыслу.
        // Теперь негативные опции (~ prefix) пропускаются — они означают «всё кроме этого
        // типа», т.е. правило применяется к большинству типов. Это корректнее, чем
        // ложно добавлять позитивную опцию, которая ограничивала бы правило одним типом.
        return optionsStr.split(',').mapNotNull { opt ->
            val trimmed = opt.trim()
            if (trimmed.startsWith('~')) return@mapNotNull null  // негативная опция — пропускаем
            when (trimmed.lowercase()) {
                "third-party"    -> RuleOption.THIRD_PARTY
                "first-party"    -> RuleOption.FIRST_PARTY
                "script"         -> RuleOption.SCRIPT
                "stylesheet"     -> RuleOption.STYLESHEET
                "image"          -> RuleOption.IMAGE
                "xmlhttprequest" -> RuleOption.XMLHTTPREQUEST
                "document"       -> RuleOption.DOCUMENT
                "subdocument"    -> RuleOption.SUBDOCUMENT
                "popup"          -> RuleOption.POPUP
                "ping"           -> RuleOption.PING
                "font"           -> RuleOption.FONT
                "media"          -> RuleOption.MEDIA
                "websocket"      -> RuleOption.WEBSOCKET
                else             -> null
            }
        }.toSet()
    }

    // -------------------------------------------------------------------------
    //  Cosmetic rules
    // -------------------------------------------------------------------------

    private fun parseCosmeticRule(
        line: String,
        domains: List<String>,
        isException: Boolean
    ): FilterRule {
        val sep = if (isException) "#@#" else "##"
        val cssSelector = line.substringAfter(sep)
        return FilterRule.CosmeticRule(
            domains = domains,
            cssSelector = cssSelector,
            isException = isException
        )
    }

    private fun parseDomainCosmeticRule(line: String, isException: Boolean): FilterRule? {
        val sep = if (isException) "#@#" else "##"
        val sepIdx = line.indexOf(sep)
        if (sepIdx < 0) return null
        val domainPart = line.substring(0, sepIdx)
        val domains = domainPart.split(',').map { it.trim() }.filter { it.isNotBlank() }
        val cssSelector = line.substring(sepIdx + sep.length)
        return FilterRule.CosmeticRule(
            domains = domains,
            cssSelector = cssSelector,
            isException = isException
        )
    }
}
