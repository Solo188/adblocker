package com.adblocker.utils

import java.net.InetAddress
import java.net.ServerSocket

object NetworkUtils {

    /**
     * Find a free TCP port on localhost for the embedded proxy.
     * Falls back to a fixed default if the OS cannot provide one.
     */
    fun findFreePort(preferred: Int = 8118): Int {
        return try {
            ServerSocket(0).use { it.localPort }
        } catch (e: Exception) {
            preferred
        }
    }

    fun isLoopback(address: InetAddress): Boolean =
        address.isLoopbackAddress || address.hostAddress?.startsWith("127.") == true

    /**
     * Safely parse a host from an HTTP CONNECT target (e.g. "example.com:443").
     */
    fun parseConnectHost(target: String): Pair<String, Int>? {
        return try {
            val lastColon = target.lastIndexOf(':')
            if (lastColon < 0) return null
            val host = target.substring(0, lastColon)
            val port = target.substring(lastColon + 1).toInt()
            host to port
        } catch (e: Exception) {
            null
        }
    }
}
