package com.adblocker.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.adblocker.utils.Logger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class VpnController(private val context: Context) {

    companion object {
        private const val TAG = "VpnController"

        const val ACTION_STATE_CHANGED = "com.adblocker.VPN_STATE_CHANGED"
        const val EXTRA_STATE = "vpn_state"
    }

    private val _state = MutableStateFlow(VpnState.STOPPED)
    val state: StateFlow<VpnState> = _state

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            if (intent?.action != ACTION_STATE_CHANGED) return
            val stateName = intent.getStringExtra(EXTRA_STATE) ?: return
            try {
                _state.value = VpnState.valueOf(stateName)
            } catch (_: IllegalArgumentException) {}
        }
    }

    init {
        val filter = IntentFilter(ACTION_STATE_CHANGED)
        ContextCompat.registerReceiver(
            context, stateReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED
        )
        if (AdBlockerVpnService.isRunning) {
            _state.value = VpnState.CONNECTED
        }
    }

    fun prepareIntent(): Intent? = VpnService.prepare(context)

    fun start() {
        Logger.i(TAG, "Requesting VPN start")
        _state.value = VpnState.CONNECTING
        ContextCompat.startForegroundService(
            context,
            Intent(context, AdBlockerVpnService::class.java).apply {
                action = AdBlockerVpnService.ACTION_START
            }
        )
    }

    fun stop() {
        Logger.i(TAG, "Requesting VPN stop")
        _state.value = VpnState.STOPPING
        context.startService(
            Intent(context, AdBlockerVpnService::class.java).apply {
                action = AdBlockerVpnService.ACTION_STOP
            }
        )
    }

    fun toggle() {
        if (_state.value == VpnState.CONNECTED) stop() else start()
    }

    fun destroy() {
        try { context.unregisterReceiver(stateReceiver) } catch (_: Exception) {}
    }
}

enum class VpnState {
    STOPPED, CONNECTING, CONNECTED, STOPPING, ERROR
}
