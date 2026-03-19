package com.dsm.wallet.bridge

internal object UnifiedUiBridge {

    fun dispatchBlePermissionEvent(eventName: String, detail: String) {
        try {
            val activity = com.dsm.wallet.ui.MainActivity.getActiveInstance()
            if (activity != null) {
                activity.dispatchCustomEventToWebView(eventName, detail)
            } else {
                android.util.Log.w("Unified", "Cannot dispatch BLE permission event '$eventName': no active MainActivity")
            }
        } catch (t: Throwable) {
            android.util.Log.e("Unified", "Failed to dispatch BLE permission event '$eventName': ${t.message}")
        }
    }
}
