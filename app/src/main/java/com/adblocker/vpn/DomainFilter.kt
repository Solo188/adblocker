package com.adblocker.vpn

import android.content.Context
import java.io.File

class DomainFilter {

    @Volatile private var blacklist: Set<String> = emptySet()

    @Suppress("UNCHECKED_CAST")
    private val cache: LinkedHashMap<String, Boolean> = object :
        LinkedHashMap<String, Boolean>(1024, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Boolean>) = size > 10_000
    }

    fun getBlacklistSize(): Int = blacklist.size

    fun loadFromFile(context: Context) {
        try {
            val file = File(context.filesDir, "domains.txt")
            if (!file.exists()) return
            val newSet = HashSet<String>(8192)
            file.forEachLine { line ->
                val domain = line.trim()
                if (domain.isNotEmpty() && !domain.startsWith("#")) newSet.add(domain)
            }
            blacklist = newSet
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun loadFromAssets(context: Context) {
        val newSet = HashSet<String>(2048)
        try {
            context.assets.open("ad_domains.txt").bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val domain = line.trim()
                    if (domain.isNotEmpty() && !domain.startsWith("#")) {
                        newSet.add(domain)
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        blacklist = newSet
    }

    fun isBlocked(domain: String): Boolean {
        if (domain.length < 4) return false

        val lower = domain.lowercase()
        synchronized(cache) { cache[lower] }?.let { return it }

        val list   = blacklist
        val parts  = lower.split(".")
        var result = false
        for (i in parts.indices) {
            val sub = parts.drop(i).joinToString(".")
            if (list.contains(sub)) { result = true; break }
        }

        synchronized(cache) { cache[lower] = result }
        return result
    }
}
