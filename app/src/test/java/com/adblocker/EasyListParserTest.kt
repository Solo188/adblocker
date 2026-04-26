package com.adblocker

import com.adblocker.filter.parser.EasyListParser
import com.adblocker.filter.rules.FilterRule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for EasyListParser line-by-line parsing correctness.
 */
class EasyListParserTest {

    private fun parse(vararg lines: String): List<FilterRule> {
        val input = lines.joinToString("\n").byteInputStream()
        return EasyListParser.parse(input).toList()
    }

    @Test
    fun `comment lines are excluded`() {
        val rules = parse("! This is a comment", "[Adblock Plus 2.0]")
        assertTrue(rules.isEmpty())
    }

    @Test
    fun `domain anchored rule parsed correctly`() {
        val rules = parse("||doubleclick.net^")
        assertEquals(1, rules.size)
        val rule = rules[0] as FilterRule.NetworkRule
        assertEquals("doubleclick.net", rule.pattern)
        assertTrue(rule.domainAnchored)
        assertFalse(rule.isException)
    }

    @Test
    fun `exception rule parsed correctly`() {
        val rules = parse("@@||safe.example.com^")
        assertEquals(1, rules.size)
        val rule = rules[0] as FilterRule.NetworkRule
        assertTrue(rule.isException)
        assertTrue(rule.domainAnchored)
    }

    @Test
    fun `cosmetic rule parsed correctly`() {
        val rules = parse("##.ad-banner")
        assertEquals(1, rules.size)
        val rule = rules[0] as FilterRule.CosmeticRule
        assertEquals(".ad-banner", rule.cssSelector)
        assertFalse(rule.isException)
        assertTrue(rule.domains.isEmpty())
    }

    @Test
    fun `domain cosmetic rule parsed correctly`() {
        val rules = parse("example.com##.sidebar-ad")
        assertEquals(1, rules.size)
        val rule = rules[0] as FilterRule.CosmeticRule
        assertEquals(listOf("example.com"), rule.domains)
        assertEquals(".sidebar-ad", rule.cssSelector)
    }

    @Test
    fun `plain substring rule parsed`() {
        val rules = parse("/banner-ad.png")
        assertEquals(1, rules.size)
        // Regex rules (starting with /) are skipped — assert empty
        // (implementation skips /regex/ syntax)
    }

    @Test
    fun `multiple rules parsed in sequence`() {
        val rules = parse(
            "! comment",
            "||ads.com^",
            "||tracker.net^",
            "@@||safe.com^"
        )
        assertEquals(3, rules.size)
    }
}
