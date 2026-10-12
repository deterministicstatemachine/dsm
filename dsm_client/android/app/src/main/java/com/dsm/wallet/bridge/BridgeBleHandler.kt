// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

internal object BridgeBleHandler {

    fun requestBlePermissions() {
        try {
            val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
            if (act != null) {
                act.runOnUiThread {
                    try {
                        act.requestBlePermissionsFromUi()
                    } catch (_: Throwable) {
                        // ignore
                    }
                }
            }
        } catch (_: Throwable) {
            // ignore
        }
    }
}
