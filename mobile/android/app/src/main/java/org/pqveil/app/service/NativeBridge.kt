// SPDX-License-Identifier: BSD-2-Clause
package org.pqveil.app.service

import android.util.Log

object NativeBridge {
    private const val TAG = "PQVeil.NativeBridge"
    private var isLoaded = false

    init {
        try {
            System.loadLibrary("pqveil_controller")
            isLoaded = true
            Log.i(TAG, "Native Rust controller library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native library pqveil_controller not yet packaged in APK: ${e.message}")
            isLoaded = false
        }
    }

    fun isNativeLoaded(): Boolean = isLoaded

    // JNI External Declarations matching Rust lib.rs
    external fun initController(backendCode: Int): Boolean
    external fun getBackendInfo(): String
    external fun startTunnel(onionTarget: String): Boolean
    external fun stopTunnel(): Boolean
    external fun getHealthReport(): String
}

