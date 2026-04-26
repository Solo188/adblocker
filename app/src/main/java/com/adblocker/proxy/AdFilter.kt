package com.adblocker.proxy

import android.util.Log
import com.adblocker.filter.engine.FilterEngine
import com.adblocker.filter.engine.ResourceType
import com.google.gson.Gson
import com.google.gson.JsonParser
import java.nio.charset.Charset

class AdFilter(private val filterEngine: FilterEngine) {

    companion object {
        private const val TAG = "AdFilter"

        // Callback для UI лога — устанавливается из MainViewModel
        var onRequest: ((host: String, url: String, blocked: Boolean, code: Int) -> Unit)? = null

        private val ANTI_ADBLOCK_JS = """
<script>(function(){
  try{
    Object.defineProperty(window,'adblock',{get:function(){return false;},configurable:true});
    Object.defineProperty(window,'__adblockDetected',{get:function(){return false;},configurable:true});
    if(window.blockAdBlock)window.blockAdBlock={onDetected:function(){},onNotDetected:function(cb){if(cb)cb();}};
  }catch(e){}
})();</script>""".trimIndent()

        private val YOUTUBE_AD_KEYS = setOf(
            "adPlacements", "playerAds", "adSlots",
            "adBreakHeartbeatParams", "auxiliaryUi"
        )
        private val YOUTUBE_API_PATHS = setOf(
            "youtubei/v1/player", "youtubei/v1/next",
            "youtubei/v1/browse", "youtubei/v1/search"
        )
        private val gson = Gson()
    }

    data class RequestInfo(
        val host: String,
        val url: String,
        val method: String,
        val referer: String?,
        val accept: String?,
        val contentType: String?
    ) {
        val resourceType: ResourceType get() = ResourceType.fromAccept(accept)
        val isThirdParty: Boolean get() {
            if (referer.isNullOrBlank()) return false
            return try {
                val rh = java.net.URI(referer).host?.lowercase()?.removePrefix("www.") ?: return false
                val h  = host.lowercase().removePrefix("www.")
                !h.endsWith(rh) && !rh.endsWith(h)
            } catch (_: Exception) { false }
        }
        val isYouTubeApi: Boolean get() = YOUTUBE_API_PATHS.any { url.contains(it) }
    }

    fun shouldBlock(info: RequestInfo): Boolean =
        filterEngine.shouldBlock(info.url, info.host, info.resourceType, info.isThirdParty)

    fun processResponseBody(
        body: ByteArray,
        contentType: String,
        host: String,
        url: String,
        isYouTubeApi: Boolean
    ): ByteArray? = when {
        isYouTubeApi && "json" in contentType -> processYouTubeJson(body)
        "text/html" in contentType            -> processHtml(body, contentType, host)
        else                                  -> null
    }

    private fun processHtml(body: ByteArray, contentType: String, host: String): ByteArray? {
        val charset = extractCharset(contentType)
        val html    = String(body, charset)
        val css     = filterEngine.getCssForHost(host)

        val injection = buildString {
            if (css.isNotEmpty()) {
                append("\n<style id='__adblock_css'>\n$css\n</style>\n")
            }
            append(ANTI_ADBLOCK_JS).append("\n")
        }

        val headEnd = html.indexOf("</head>", ignoreCase = true)
        val bodyTag = if (headEnd < 0) html.indexOf("<body", ignoreCase = true) else -1

        return when {
            headEnd >= 0 -> {
                (html.substring(0, headEnd) + injection + html.substring(headEnd))
                    .toByteArray(charset)
            }
            bodyTag >= 0 -> {
                val end = html.indexOf('>', bodyTag) + 1
                (html.substring(0, end) + injection + html.substring(end))
                    .toByteArray(charset)
            }
            else -> null
        }
    }

    private fun processYouTubeJson(body: ByteArray): ByteArray? {
        return try {
            val json = String(body, Charsets.UTF_8)
            if (json.isBlank()) return null
            val root    = JsonParser.parseString(json)
            val changed = stripAdKeys(root)
            if (!changed) null else gson.toJson(root).toByteArray(Charsets.UTF_8)
        } catch (_: Exception) { null }
    }

    private fun stripAdKeys(el: com.google.gson.JsonElement): Boolean {
        var changed = false
        when {
            el.isJsonObject -> {
                val obj = el.asJsonObject
                YOUTUBE_AD_KEYS.forEach { key ->
                    if (obj.has(key)) { obj.remove(key); changed = true }
                }
                obj.entrySet().forEach { if (stripAdKeys(it.value)) changed = true }
            }
            el.isJsonArray -> el.asJsonArray.forEach { if (stripAdKeys(it)) changed = true }
        }
        return changed
    }

    fun patchCsp(headers: MutableMap<String, String>) {
        val csp = headers["content-security-policy"] ?: return
        if ("script-src" in csp && "'unsafe-inline'" !in csp) {
            headers.remove("content-security-policy")
            headers.remove("content-security-policy-report-only")
        }
    }

    fun logRequest(host: String, url: String, blocked: Boolean, code: Int) {
        try { onRequest?.invoke(host, url, blocked, code) } catch (_: Exception) {}
    }

    private fun extractCharset(contentType: String): Charset = try {
        Regex("charset=([\\w-]+)", RegexOption.IGNORE_CASE)
            .find(contentType)?.groupValues?.get(1)
            ?.let { Charset.forName(it) } ?: Charsets.UTF_8
    } catch (_: Exception) { Charsets.UTF_8 }
}
