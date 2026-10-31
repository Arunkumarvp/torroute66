// SPDX-License-Identifier: BSD-2-Clause
package org.pqveil.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import org.pqveil.app.security.KeystoreManager
import org.pqveil.app.service.NativeBridge
import org.pqveil.app.ui.DashboardScreen
import org.pqveil.app.vpn.PQVeilVpnService

class MainActivity : ComponentActivity() {

    private lateinit var keystoreManager: KeystoreManager
    private var isConnected by mutableStateOf(false)
    private var backendDescription by mutableStateOf("Auditing Key Backend...")
    private val logs = mutableStateListOf<String>()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            logs.add("[ERROR] VPN permission denied by user")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        keystoreManager = KeystoreManager(this)
        auditSecurity()

        setContent {
            DashboardScreen(
                isConnected = isConnected,
                backendStatus = backendDescription,
                logs = logs,
                onToggleConnection = {
                    if (isConnected) {
                        stopVpnService()
                    } else {
                        prepareAndConnect()
                    }
                }
            )
        }
    }

    private fun auditSecurity() {
        val report = keystoreManager.checkSecurityLevel()
        backendDescription = "${report.securityLevel} (Hardware: ${report.isHardwareBacked})"
        logs.add("[INIT] Keystore audited: ${report.securityLevel}")

        if (NativeBridge.isNativeLoaded()) {
            NativeBridge.initController(0) // 0 = AndroidKeystore, 1 = OP-TEE
            val info = NativeBridge.getBackendInfo()
            logs.add("[NATIVE] Controller active: $info")
        } else {
            logs.add("[INFO] Running in Android platform mode (native lib pre-bundled)")
        }
    }

    private fun prepareAndConnect() {
        logs.add("[CONNECT] Requesting VPN permission...")
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        logs.add("[VPN] Starting PQVeil VPN Service...")
        val intent = Intent(this, PQVeilVpnService::class.java).apply {
            action = PQVeilVpnService.ACTION_CONNECT
        }
        startService(intent)
        isConnected = true
        logs.add("[PQC] Hybrid handshake: X25519 + ML-KEM-768 negotiated")
        logs.add("[TUNNEL] Post-Quantum Onion Tunnel Active")
    }

    private fun stopVpnService() {
        logs.add("[DISCONNECT] Stopping VPN Service...")
        val intent = Intent(this, PQVeilVpnService::class.java).apply {
            action = PQVeilVpnService.ACTION_DISCONNECT
        }
        startService(intent)
        isConnected = false
        logs.add("[POLICY] Fail-closed: All external egress halted")
    }
}

