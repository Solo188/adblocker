package com.adblocker.ui.log

import java.time.Instant

/**
 * ui.log — RequestLogEntry
 *
 * Immutable snapshot of a single intercepted HTTP request.
 * Used by the RecyclerView adapter and future Room persistence.
 */
data class RequestLogEntry(
    val id: Long = System.nanoTime(),
    val timestamp: Instant = Instant.now(),
    val method: String,
    val host: String,
    val url: String,
    val blocked: Boolean,
    val responseCode: Int = -1,
    val durationMs: Long = -1
) {
    val displayTime: String
        get() {
            val t = java.time.LocalTime.ofInstant(timestamp, java.time.ZoneId.systemDefault())
            return "%02d:%02d:%02d".format(t.hour, t.minute, t.second)
        }

    val shortUrl: String
        get() = url.let { u ->
            val afterScheme = u.substringAfter("://")
            val afterHost = afterScheme.substringAfter(host).take(60)
            if (afterHost.length == 60) "$afterHost…" else afterHost
        }
}
