package com.adblocker.filter.rules

/**
 * filter.rules — FilterRule
 *
 * Sealed hierarchy representing all rule types parsed from EasyList / uBlock Origin
 * compatible filter lists.
 *
 * Supported rule types (parsed by EasyListParser):
 *   - NetworkRule:   Block or allow a URL pattern (||ads.com^, @@whitelist)
 *   - DomainRule:    Block an entire domain
 *   - CosmeticRule: CSS element hiding (##.ad-banner) — prepared but not applied yet
 *   - CommentRule:  Lines starting with ! — ignored
 */
sealed class FilterRule {

    /** Block or allow traffic to a URL matching [pattern]. */
    data class NetworkRule(
        val pattern: String,
        val isException: Boolean,          // true for @@whitelist rules
        val domainAnchored: Boolean,       // true for ||pattern rules
        val options: Set<RuleOption> = emptySet()
    ) : FilterRule()

    /** Block all requests to a specific domain. */
    data class DomainRule(
        val domain: String,
        val isException: Boolean
    ) : FilterRule()

    /**
     * CSS cosmetic / element hiding rule.
     * Future: inject CSS to hide elements on rendered pages.
     */
    data class CosmeticRule(
        val domains: List<String>,         // empty = applies to all domains
        val cssSelector: String,
        val isException: Boolean           // #@# instead of ##
    ) : FilterRule()

    /** Comment line — parsed but not stored in the engine. */
    object Comment : FilterRule()
}

enum class RuleOption {
    THIRD_PARTY, FIRST_PARTY,
    SCRIPT, STYLESHEET, IMAGE, XMLHTTPREQUEST,
    DOCUMENT, SUBDOCUMENT,
    POPUP, PING, FONT, MEDIA, WEBSOCKET
}
