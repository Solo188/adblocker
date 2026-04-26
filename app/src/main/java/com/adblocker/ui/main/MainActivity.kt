package com.adblocker.ui.main

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import com.adblocker.R
import com.adblocker.vpn.VpnState
import com.adblocker.databinding.ActivityMainBinding
import com.adblocker.ui.log.RequestLogAdapter
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val viewModel: MainViewModel by viewModels()
    private lateinit var logAdapter: RequestLogAdapter

    private val vpnPermLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            viewModel.startVpn()
        } else {
            Snackbar.make(binding.root, "VPN permission denied", Snackbar.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        viewModel.initialize(this)

        setupRecyclerView()
        setupVpnToggle()
        observeViewModel()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_export_ca -> {
                viewModel.exportCaCertificate(this)
                true
            }
            R.id.action_clear_log -> {
                viewModel.clearLog()
                true
            }
            R.id.action_about -> {
                showAboutDialog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun setupRecyclerView() {
        logAdapter = RequestLogAdapter()
        binding.recyclerLog.apply {
            layoutManager = LinearLayoutManager(this@MainActivity).apply {
                reverseLayout = true
                stackFromEnd = true
            }
            adapter = logAdapter
        }
    }

    private fun setupVpnToggle() {
        binding.btnVpnToggle.setOnClickListener {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                vpnPermLauncher.launch(vpnIntent)
            } else {
                viewModel.toggleVpn()
            }
        }
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    viewModel.vpnState.collect { state ->
                        updateVpnUi(state)
                    }
                }
                launch {
                    viewModel.requestLog.collect { log ->
                        logAdapter.submitList(log)
                        if (log.isNotEmpty()) {
                            binding.recyclerLog.scrollToPosition(0)
                        }
                    }
                }
                launch {
                    viewModel.blockedCount.collect { count ->
                        binding.tvBlockedCount.text = "$count blocked"
                    }
                }
            }
        }
    }

    private fun updateVpnUi(state: VpnState) {
        when (state) {
            VpnState.STOPPED -> {
                binding.btnVpnToggle.text = "Start Protection"
                binding.tvStatus.text = "Off"
                binding.tvStatus.setBackgroundResource(R.drawable.bg_status_off)
                binding.shieldIcon.setImageResource(R.drawable.ic_shield_off)
            }
            VpnState.CONNECTING, VpnState.STOPPING -> {
                binding.btnVpnToggle.text = if (state == VpnState.CONNECTING) "Connecting…" else "Stopping…"
                binding.tvStatus.text = "Working…"
                binding.tvStatus.setBackgroundResource(R.drawable.bg_status_connecting)
            }
            VpnState.CONNECTED -> {
                binding.btnVpnToggle.text = "Stop Protection"
                binding.tvStatus.text = "Active"
                binding.tvStatus.setBackgroundResource(R.drawable.bg_status_on)
                binding.shieldIcon.setImageResource(R.drawable.ic_shield)
            }
            VpnState.ERROR -> {
                binding.tvStatus.text = "Error"
                binding.tvStatus.setBackgroundResource(R.drawable.bg_status_off)
                Snackbar.make(binding.root, "VPN error — check logs", Snackbar.LENGTH_LONG).show()
            }
        }
    }

    private fun showAboutDialog() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("AdBlocker")
            .setMessage(
                "Local VPN-based ad blocker.\n\n" +
                "Traffic never leaves your device.\n" +
                "Powered by Netty + BouncyCastle + EasyList.\n\n" +
                "To enable HTTPS blocking, install the CA certificate via the overflow menu."
            )
            .setPositiveButton("OK", null)
            .show()
    }
}
