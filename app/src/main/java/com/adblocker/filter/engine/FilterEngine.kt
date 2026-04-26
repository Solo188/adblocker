package com.adblocker.filter.engine

import android.content.Context
import com.adblocker.filter.parser.EasyListParser
import com.adblocker.filter.rules.FilterRule
import com.adblocker.filter.rules.RuleOption
import com.adblocker.utils.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.CountDownLatch

class FilterEngine(private val context: Context) {

    companion object {
        private const val TAG = "FilterEngine"
        private const val EASYLIST_ASSET    = "filters/easylist.txt"
        private const val EASYPRIVACY_ASSET = "filters/easyprivacy.txt"
    }

    private val blockTrie     = DomainTrie()
    private val exceptionTrie = DomainTrie()
    private val blockAho      = AhoCorasick()
    private val exceptionAho  = AhoCorasick()
    // CopyOnWriteArrayList: initialize() пишет один раз, shouldBlock() читает часто из разных потоков
    private val typedRules    = java.util.concurrent.CopyOnWriteArrayList<TypedRule>()

    // Косметические правила — аналогично, пишем один раз при initialize()
    private val globalCssSelectors = java.util.concurrent.CopyOnWriteArrayList<String>()
    private val perDomainCss       = java.util.concurrent.ConcurrentHashMap<String, MutableList<String>>()
    private val cosmeticExceptions = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    @Volatile var ruleCount: Int = 0
        private set

    // Fix #5: CountDownLatch позволяет LocalProxyService дождаться полной загрузки
    // правил перед стартом LittleProxy. Без этого первые запросы после старта VPN
    // проходят без фильтрации — filterEngine ещё пуст.
    private val readyLatch = CountDownLatch(1)

    /** Блокирует вызывающий поток до завершения initialize(). */
    fun awaitReady() { readyLatch.await() }

    /** true если initialize() уже завершился. */
    val isReady: Boolean get() = readyLatch.count == 0L

    // ── init ──────────────────────────────────────────────────────────────────

    suspend fun initialize() = withContext(Dispatchers.IO) {
        loadBuiltinRules()
        loadAssetSafe(EASYLIST_ASSET)
        loadAssetSafe(EASYPRIVACY_ASSET)
        blockAho.build()
        exceptionAho.build()
        ruleCount = blockTrie.size + blockAho.patternCount + typedRules.size
        Logger.i(TAG,
            "FilterEngine: ${blockTrie.size} domain, ${blockAho.patternCount} substring, " +
            "${typedRules.size} typed, ${globalCssSelectors.size} global CSS, " +
            "${perDomainCss.size} per-domain CSS"
        )
        readyLatch.countDown()  // Fix #5: сигнализируем что движок готов
    }

    private fun loadBuiltinRules() {
        listOf(
            "doubleclick.net","googlesyndication.com","googleadservices.com",
            "googletagservices.com","googletagmanager.com","google-analytics.com",
            "adnxs.com","advertising.com","adform.net","adroll.com",
            "criteo.com","criteo.net","rubiconproject.com","openx.net",
            "pubmatic.com","casalemedia.com","smartadserver.com",
            "contextweb.com","yieldmanager.com","buysellads.com",
            "scorecardresearch.com","quantserve.com","demdex.net",
            "amazon-adsystem.com","adtechus.com","outbrain.com","taboola.com",
            "revcontent.com","mgid.com","hotjar.com","mixpanel.com",
            "moatads.com","33across.com","lijit.com","smaato.com",
            "adsafeprotected.com","omtrdc.net","mktoresp.com","chartbeat.com",
            "addthis.com","sharethis.com","zergnet.com",
            "pagead2.googlesyndication.com","tpc.googlesyndication.com",
            "adservice.google.com","stats.g.doubleclick.net",
            "ads.twitter.com","ads.linkedin.com","advertising.amazon.com",
            "mc.yandex.ru","an.yandex.ru","yandex.com"
        ).forEach { blockTrie.insert(it) }

        listOf(
            "/ads/","/ad/","/advert/","/advertising/","/adsystem/",
            "/adserver/","/adservice/","/adtech/","/adtrack/",
            "/pagead/","/doubleclick/","/googlesyndication/",
            "/banner/","/banners/","/sponsor/","/sponsored/",
            "/tracking/","/tracker/","/pixel/","/beacon/",
            "/analytics/","/telemetry/","/metrics/"
        ).forEach { blockAho.addPattern(it) }

        globalCssSelectors.addAll(listOf(
            ".ad",".ads",".adv",".advert",".advertisement",".advertising",
            ".ad-container",".ad-wrapper",".ad-slot",".ad-unit",".ad-banner",
            ".ad-block",".ad-box",".ad-placeholder",".ad-frame",".ad-area",
            "[class*='advert']","[class*='-ad-']","[class*='_ad_']",
            "[id*='advert']","[id*='-ad-']","[id*='_ad_']",
            "[id^='ad-']","[id^='ads-']","[class^='ad-']","[class^='ads-']",
            ".adsbygoogle","ins.adsbygoogle","[data-ad-client]","[data-ad-slot]",
            "#google_ads_iframe_0",".yandex-ad",".ya-ad","[class*='yandex-adv']",".Y-ads",
            ".banner-ad",".banner_ad",".top-banner",".sticky-ad",
            ".floating-ad",".overlay-ad",".interstitial",
            ".popup-ad",".modal-ad",".ad-overlay",".ad-modal",
            ".sponsored",".sponsored-content",".sponsor-box",
            "[data-sponsored]","[aria-label='Sponsored']",
            "#taboola-below-article",".trc_related_container",
            "#outbrain_widget",".OUTBRAIN","#mgid-container",
            ".adblock-notice",".adblock-warning",".anti-adblock",
            "#adblock-overlay",".no-adblock-message"
        ))
    }

    private fun loadAssetSafe(path: String) {
        try {
            context.assets.open(path).use { stream ->
                EasyListParser.parse(stream).forEach { addRule(it) }
            }
        } catch (e: Exception) {
            Logger.d(TAG, "Asset not loaded ($path): ${e.message}")
        }
    }

    private fun addRule(rule: FilterRule) {
        when (rule) {
            is FilterRule.NetworkRule -> {
                val hasTypeOption = rule.options.any { it.isResourceType() }
                if (rule.isException) {
                    if (rule.domainAnchored) exceptionTrie.insert(rule.pattern)
                    else exceptionAho.addPattern(rule.pattern)
                } else {
                    if (hasTypeOption) {
                        typedRules.add(TypedRule(rule.pattern, rule.domainAnchored, rule.options))
                    } else {
                        if (rule.domainAnchored) blockTrie.insert(rule.pattern)
                        else blockAho.addPattern(rule.pattern)
                    }
                }
            }
            is FilterRule.DomainRule -> {
                if (rule.isException) exceptionTrie.insert(rule.domain)
                else blockTrie.insert(rule.domain)
            }
            is FilterRule.CosmeticRule -> {
                if (rule.isException) {
                    cosmeticExceptions.add(rule.cssSelector)
                    return
                }
                if (rule.domains.isEmpty()) {
                    globalCssSelectors.add(rule.cssSelector)
                } else {
                    rule.domains.forEach { domain ->
                        perDomainCss
                            .getOrPut(domain.lowercase().removePrefix("www.")) {
                                java.util.concurrent.CopyOnWriteArrayList()
                            }
                            .add(rule.cssSelector)
                    }
                }
            }
            is FilterRule.Comment -> {}
        }
    }

    // ── Network blocking ──────────────────────────────────────────────────────

    fun shouldBlock(
        url: String,
        host: String,
        resType: ResourceType = ResourceType.OTHER,
        thirdParty: Boolean = true
    ): Boolean {
        val normHost = host.lowercase().removePrefix("www.")
        val urlLow   = url.lowercase()

        if (exceptionTrie.matches(normHost)) return false
        if (exceptionAho.matches(urlLow))    return false
        if (blockTrie.matches(normHost))     return true
        if (blockAho.matches(urlLow))        return true

        for (r in typedRules) {
            val patternMatch = if (r.domainAnchored)
                normHost == r.pattern || normHost.endsWith(".${r.pattern}")
            else
                urlLow.contains(r.pattern)
            if (!patternMatch) continue

            val typeOptions = r.options.filter { it.isResourceType() }
            if (typeOptions.isNotEmpty() && typeOptions.none { it.matchesResourceType(resType) }) continue
            if (RuleOption.THIRD_PARTY in r.options && !thirdParty) continue
            if (RuleOption.FIRST_PARTY in r.options && thirdParty)  continue

            return true
        }
        return false
    }

    // ── Cosmetic CSS ──────────────────────────────────────────────────────────

    fun getCssForHost(host: String): String {
        val normHost = host.lowercase().removePrefix("www.")
        val selectors = LinkedHashSet<String>()
        selectors.addAll(globalCssSelectors)
        perDomainCss[normHost]?.let { selectors.addAll(it) }
        val parent = normHost.substringAfter('.')
        if (parent != normHost) perDomainCss[parent]?.let { selectors.addAll(it) }
        val filtered = selectors.filter { it !in cosmeticExceptions }
        if (filtered.isEmpty()) return ""
        return filtered.joinToString(",\n") +
               " { display: none !important; visibility: hidden !important; }"
    }

    fun hasCssRules(): Boolean = globalCssSelectors.isNotEmpty()

    data class TypedRule(
        val pattern: String,
        val domainAnchored: Boolean,
        val options: Set<RuleOption>
    )
}

// ── ResourceType ──────────────────────────────────────────────────────────────

enum class ResourceType {
    SCRIPT, STYLESHEET, IMAGE, XMLHTTPREQUEST,
    DOCUMENT, SUBDOCUMENT, FONT, MEDIA, WEBSOCKET,
    PING, POPUP, OTHER;

    companion object {
        fun fromAccept(accept: String?): ResourceType {
            val a = accept?.lowercase() ?: return OTHER
            return when {
                "javascript" in a || "ecmascript" in a -> SCRIPT
                "text/css"   in a                      -> STYLESHEET
                "image/"     in a                      -> IMAGE
                "text/html"  in a                      -> DOCUMENT
                else                                   -> OTHER
            }
        }
        fun fromContentType(ct: String?): ResourceType {
            val c = ct?.lowercase() ?: return OTHER
            return when {
                "javascript" in c -> SCRIPT
                "css"        in c -> STYLESHEET
                "image/"     in c -> IMAGE
                "font"       in c -> FONT
                "audio/"     in c || "video/" in c -> MEDIA
                "html"       in c -> DOCUMENT
                else              -> OTHER
            }
        }
    }
}

fun RuleOption.isResourceType(): Boolean = this in setOf(
    RuleOption.SCRIPT, RuleOption.STYLESHEET, RuleOption.IMAGE,
    RuleOption.XMLHTTPREQUEST, RuleOption.DOCUMENT, RuleOption.SUBDOCUMENT,
    RuleOption.FONT, RuleOption.MEDIA, RuleOption.WEBSOCKET,
    RuleOption.PING, RuleOption.POPUP
)

fun RuleOption.matchesResourceType(t: ResourceType): Boolean = when (this) {
    RuleOption.SCRIPT         -> t == ResourceType.SCRIPT
    RuleOption.STYLESHEET     -> t == ResourceType.STYLESHEET
    RuleOption.IMAGE          -> t == ResourceType.IMAGE
    RuleOption.XMLHTTPREQUEST -> t == ResourceType.XMLHTTPREQUEST
    RuleOption.DOCUMENT       -> t == ResourceType.DOCUMENT
    RuleOption.SUBDOCUMENT    -> t == ResourceType.SUBDOCUMENT
    RuleOption.FONT           -> t == ResourceType.FONT
    RuleOption.MEDIA          -> t == ResourceType.MEDIA
    RuleOption.WEBSOCKET      -> t == ResourceType.WEBSOCKET
    RuleOption.PING           -> t == ResourceType.PING
    RuleOption.POPUP          -> t == ResourceType.POPUP
    else                      -> false
}
