// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.service

import android.content.Context
import android.util.Log
import com.dsm.native.DsmNative
import com.dsm.wallet.bridge.BridgeIdentityHandler
import com.dsm.wallet.bridge.SinglePathWebViewBridge
import com.dsm.wallet.bridge.Unified
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * The wallet started with no screen, in a process Android started for a push
 * from a storage node: the same Rust startup MainActivity runs, in the same
 * order, without its page. It runs once per process. MainActivity, opened later
 * in the same process, runs its startup as it always does: Rust's startup is
 * made to run again for the same identity.
 *
 * The env config is the one MainActivity materialized when the app was last
 * opened; a phone that never opened the app holds no doorbell to be rung.
 */
internal object HeadlessWallet {
    private const val TAG = "HeadlessWallet"
    private const val ENV_CONFIG = "dsm_env_config.toml"

    private const val NOT_STARTED = 0
    private const val STARTED = 1
    private val state = AtomicInteger(NOT_STARTED)

    private fun started(): Boolean = state.get() == STARTED

    /**
     * Start the wallet for a push. Answers whether it is started; on a failure the
     * reason is in the log, and the push is lost: the app reads its inbox when it
     * is next opened.
     */
    @Synchronized
    fun start(context: Context): Boolean {
        if (started()) return started()
        val config = File(context.filesDir, ENV_CONFIG)
        if (!config.canRead() || config.length() == 0L) {
            Log.w(TAG, "no env config at ${config.path}: the app was never opened, nothing to start")
            return started()
        }
        Unified.initDsmSdk(config.absolutePath)
        if (!Unified.initSdk(context.filesDir.path)) {
            Log.e(TAG, "SDK initialization failed; the session carries Rust's reason")
            return started()
        }
        val prefs = context.getSharedPreferences(SinglePathWebViewBridge.PREFS_NAME, Context.MODE_PRIVATE)
        val restored = BridgeIdentityHandler.bootstrapFromPrefs(
            prefs = prefs,
            sdkContextInitialized = AtomicBoolean(),
            logTag = TAG,
            keyDeviceId = SinglePathWebViewBridge.KEY_DEVICE_ID,
            keyGenesisHash = SinglePathWebViewBridge.KEY_GENESIS_HASH,
        )
        if (!restored) {
            Log.w(TAG, "no identity to restore: nothing to start")
            return started()
        }
        if (!DsmNative.initializeBilateralSdk()) {
            Log.w(TAG, "bilateral SDK initialization returned no SDK")
        }
        if (!Unified.ensureAppRouterInstalled()) {
            Log.e(TAG, "the wallet's router is not installed: the push is not served")
            return started()
        }
        // The token Rust puts the doorbells up with: a new process holds none yet.
        InboxPush.start(context)
        state.set(STARTED)
        Log.i(TAG, "wallet started for a push, with no screen")
        return started()
    }
}
