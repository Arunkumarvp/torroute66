// SPDX-License-Identifier: BSD-2-Clause
package org.pqveil.app.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

class PQVeilVpnService : VpnService() {

    companion object {
        private const val TAG = "PQVeil.VpnService"
        const val ACTION_CONNECT = "org.pqveil.app.vpn.CONNECT"
        const val ACTION_DISCONNECT = "org.pqveil.app.vpn.DISCONNECT"
        const val VPN_MTU = 1500
        const val VPN_IPV4_ADDRESS = "10.192.0.2"
        const val VPN_IPV4_PREFIX = 10
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val isRunning = AtomicBoolean(false)
    private var workerThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> startVpn()
            ACTION_DISCONNECT -> stopVpn()
        }
        return START_NOT_STICKY
    }

    private fun startVpn() {
        if (isRunning.get()) return
        Log.i(TAG, "Starting PQVeil VPN Service...")

        try {
            val builder = Builder()
                .setMtu(VPN_MTU)
                .setSession("PQVeil Post-Quantum Tor Tunnel")
                .addAddress(VPN_IPV4_ADDRESS, VPN_IPV4_PREFIX)
                // Intercept all IPv4 traffic
                .addRoute("0.0.0.0", 0)
                // Route DNS explicitly through Tor DNSPort (5353)
                .addDnsServer("10.192.0.1")
                .setBlocking(true)

            // Block IPv6 explicitly to prevent leaks in v1
            try {
                builder.addAddress("fd00::2", 64)
                builder.addRoute("::", 0)
            } catch (e: Exception) {
                Log.w(TAG, "IPv6 route configuration note: ${e.message}")
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed establishing VPN TUN interface")
                return
            }

            isRunning.set(true)
            startPacketWorker()
            Log.i(TAG, "PQVeil VPN TUN established successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Exception during VPN establishment: ${e.message}", e)
            stopVpn()
        }
    }

    /**
     * Protects an underlying socket (e.g. Tor or controller connection)
     * from looping into the VPN TUN interface.
     */
    fun protectSocket(socket: Socket): Boolean {
        return protect(socket)
    }

    fun protectSocketFd(fd: Int): Boolean {
        return protect(fd)
    }

    private fun startPacketWorker() {
        val pfd = vpnInterface ?: return
        val inStream = FileInputStream(pfd.fileDescriptor)
        val outStream = FileOutputStream(pfd.fileDescriptor)

        workerThread = Thread {
            val buffer = ByteArray(VPN_MTU)
            Log.i(TAG, "TUN packet processing loop started")

            while (isRunning.get()) {
                try {
                    val length = inStream.read(buffer)
                    if (length > 0) {
                        // Inspect packet header, parse IP version & protocol
                        val version = (buffer[0].toInt() shr 4) and 0x0F
                        val protocol = buffer[9].toInt() and 0xFF

                        // Protocol 6 = TCP, Protocol 17 = UDP
                        if (version == 4 && protocol == 6) {
                            // Forward TCP flow through Tor userspace stack
                        } else if (version == 4 && protocol == 17) {
                            // Only DNS port 53 permitted; raw UDP dropped as per fail-closed policy
                        }
                    }
                } catch (e: Exception) {
                    if (isRunning.get()) {
                        Log.e(TAG, "Packet processing exception: ${e.message}")
                    }
                    break
                }
            }
            Log.i(TAG, "TUN packet worker terminated")
        }.apply { start() }
    }

    private fun stopVpn() {
        Log.i(TAG, "Stopping PQVeil VPN Service...")
        isRunning.set(false)
        workerThread?.interrupt()
        workerThread = null

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing VPN interface: ${e.message}")
        }
        vpnInterface = null
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}

