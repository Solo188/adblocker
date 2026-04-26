package com.adblocker.utils

import android.util.Log

/**
 * Thin wrapper around Android's Log so every subsystem logs with a consistent
 * "[AdBlocker/<tag>]" prefix and logging can be toggled globally.
 */
object Logger {

    private const val GLOBAL_TAG = "AdBlocker"
    var enabled = true

    fun d(tag: String, msg: String) {
        if (enabled) Log.d("$GLOBAL_TAG/$tag", msg)
    }

    fun i(tag: String, msg: String) {
        if (enabled) Log.i("$GLOBAL_TAG/$tag", msg)
    }

    fun w(tag: String, msg: String, t: Throwable? = null) {
        if (enabled) {
            if (t != null) Log.w("$GLOBAL_TAG/$tag", msg, t)
            else Log.w("$GLOBAL_TAG/$tag", msg)
        }
    }

    fun e(tag: String, msg: String, t: Throwable? = null) {
        // Errors always log regardless of enabled flag.
        if (t != null) Log.e("$GLOBAL_TAG/$tag", msg, t)
        else Log.e("$GLOBAL_TAG/$tag", msg)
    }
}
