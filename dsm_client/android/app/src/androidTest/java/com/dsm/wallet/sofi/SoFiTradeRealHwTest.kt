// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.sofi

import android.content.Context
import android.util.Log
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import com.dsm.wallet.ui.MainActivity
import dsm.types.proto.AmmVaultSummaryV1
import dsm.types.proto.RouteCommitV1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import java.security.SecureRandom

/**
 * Real-hardware verification for the full SoFi (Sovereign Finance) trade
 * pipeline on a single connected Android device. Walks the 9-route
 * end-to-end flow through `NativeBoundaryBridge` (Kotlin → JNI → Rust):
 *
 *   1. `dlv.create` × 2          (two AMM vaults, different fee tiers)
 *   2. `route.publishRoutingAdvertisement` × 2
 *   3. `route.syncVaultsForPair`
 *   4. `route.findAndBindBestPath` (one route, anchor-bound, exact output)
 *   5. `route.signRouteCommit`
 *   6. `route.computeExternalCommitment` (query)
 *   7. `route.publishExternalCommitment`
 *   8. `dlv.unlockRouted`        (atomic settlement)
 *   9. `dlv.listOwnedAmmVaults`  (verify post-trade reserves moved)
 *
 * The wallet acts as both the vault owner (creator_public_key = wallet
 * pk on each vault) and the trader (initiator_public_key = wallet pk on
 * the RouteCommit) — the single-device dual-role pattern from
 * `route_commit_sdk::tests::demo_full_amm_trade_e2e`.
 *
 * **Phase 8 refactor**: all bridge boilerplate, per-route helpers,
 * bootstrap-readiness pollers, and encoding helpers now live in
 * [SoFiTestHelpers].  This file is a thin driver that orchestrates
 * the 9-step flow; the cross-device tests in [SoFiCrossDeviceOwnerTest]
 * and [SoFiCrossDeviceTraderTest] share the same helper file so any
 * bridge-pattern fix lands in one place.
 *
 * Prerequisites (the test self-skips via `Assume.assumeTrue` rather
 * than failing if any of these are missing):
 *  1. `dsm_env_config.toml` deployed to one of MainActivity's
 *     materialize paths (Downloads, externalFilesDir, files-dir
 *     override). Without it, MainActivity bootstrap aborts at
 *     `envMissing` and AppRouter never installs.
 *         adb push dsm_env_config.toml /sdcard/Download/
 *  2. Wallet identity bootstrapped — genesis completed at least once.
 *     If the wallet was just installed, open it once interactively
 *     and tap through the genesis flow before running this test.
 *     `Unified.ensureAppRouterInstalled()` returns false until genesis
 *     + DBRW binding-key derivation finish (~30s after first launch).
 *  3. ERA balance >= MIN_ERA_BALANCE on this device. Use the wallet's
 *     faucet screen to claim if missing.
 *
 * Run:
 *     ./gradlew :app:connectedAndroidTest \
 *         -Pandroid.testInstrumentationRunnerArguments.class=\
 *         com.dsm.wallet.sofi.SoFiTradeRealHwTest
 *
 * Watch logs in a second pane:
 *     adb logcat -s SOFI_TRADE
 *
 * What this test proves that the Rust unit tests do NOT:
 *  - The JNI / SQLite / storage / proto-codec stack carries the full
 *    trade across the bridge without truncation, schema drift, or
 *    threading deadlocks.
 *  - `route.findAndBindBestPath` returns a RouteCommit whose single hop
 *    carries a stamped anchor-state binding, and the settled output
 *    equals the quoted exact output (one route, one anchored state, one
 *    exact output, one signature — no fallback, no slippage floor).
 *  - The post-trade reserve update (chunks #7 republish-on-settled)
 *    completes within the bounded poll window after `dlv.unlockRouted`.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SoFiTradeRealHwTest {

    @Suppress("unused")
    private fun ctx(): Context = InstrumentationRegistry.getInstrumentation().targetContext

    private var activity: ActivityScenario<MainActivity>? = null
    private lateinit var sofi: SoFiTestContext

    @Before
    fun setUp() {
        // Per-run unique OUTPUT_TOKEN so storage's per-pair advertisement
        // set is empty at test start.  Lex-canonical ordering: ERA
        // (0x45..) is always lex-higher than "00_DEMO_*" (0x30...), so
        // outputToken = lexLower and ERA = lexHigher.  The wallet's
        // faucet credits ERA balance; this test never needs OUTPUT to
        // have balance because the wallet receives it (the delta
        // credits via Operation::DlvUnlock).
        val (outputToken, lexLower, lexHigher) = freshOutputTokenForRun()
        sofi = SoFiTestContext(outputToken, lexLower, lexHigher)

        // Launch MainActivity so its onCreate runs the full DSM bootstrap
        // sequence (initStorageBaseDir → initDsmSdk → initSdk →
        // bootstrapFromPrefs → ensureAppRouterInstalled). The AppRouter is
        // installed asynchronously after identity + binding key are ready;
        // poll Unified.ensureAppRouterInstalled() with a bounded retry
        // until it returns true. No wall-clock — bounded spin.
        activity = ActivityScenario.launch(MainActivity::class.java)
        val installed = waitForAppRouter(maxPollAttempts = 600, pollMs = 100L)
        Assume.assumeTrue(
            "AppRouter never installed — wallet bootstrap did not finish. " +
                "Check that the device has a valid genesis identity (open the " +
                "wallet UI once first to complete genesis).",
            installed,
        )

        // The full AppRouter installs only once the wallet is unlocked
        // (Genesis v2: signing re-derives from the cached wallet seed).
        // ensureAppRouterInstalled returning true for the bootstrap stub
        // isn't enough — poll `balance.get` until the real router answers
        // it, then read the actual balance.
        // 90s budget — covers slow first-boot resume (Minimal → Full
        // router transition + measure_trust orbit + trust snapshot publish).
        val balance = pollBalanceUntilTrustReady("ERA", maxAttempts = 900, pollMs = 100L)
        Log.i(TAG, "setUp: ERA balance = $balance (need >= $MIN_ERA_BALANCE)")
        Assume.assumeTrue(
            "Need ERA balance >= $MIN_ERA_BALANCE on this device (have $balance). " +
                "Open the wallet UI → faucet → claim ERA, then re-run.",
            balance >= MIN_ERA_BALANCE,
        )
    }

    @org.junit.After
    fun tearDown() {
        try {
            activity?.close()
        } catch (_: Throwable) {
            // best-effort
        }
        activity = null
    }

    @Test
    fun t01_trade_settles_with_exact_anchor_bound_output() {
        // Per-run unique salt → unique content_digest → unique vault_id.
        // Vaults are immutable: a prior run's vault advertisements occupy
        // their storage keys forever. Each test run creates genuinely
        // fresh vaults by salting the content with a CSPRNG nonce. The
        // 16-byte hex form keeps the label readable in logcat without
        // pulling in Base32 encode for an ephemeral test-only string.
        val runSalt = ByteArray(16).also { SecureRandom().nextBytes(it) }
            .joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }
        val label1 = "sofi-test-vault-1-$runSalt"
        val label2 = "sofi-test-vault-2-$runSalt"

        // ── STEP 1: create two AMM vaults with different fee tiers ──
        val vault1Id = sofi.createAmmVault(label1, VAULT1_FEE_BPS)
        val vault2Id = sofi.createAmmVault(label2, VAULT2_FEE_BPS)
        Log.i(TAG, "vaults created: salt=$runSalt v1=${b32(vault1Id)} v2=${b32(vault2Id)}")
        assertEquals("vault_id is 32 bytes", 32, vault1Id.size)
        assertEquals("vault_id is 32 bytes", 32, vault2Id.size)

        // ── STEP 2: publish routing advertisements for both ──
        sofi.publishRoutingAdvertisement(vault1Id, VAULT1_FEE_BPS, label1)
        sofi.publishRoutingAdvertisement(vault2Id, VAULT2_FEE_BPS, label2)

        // ── STEP 3: sync the canonical pair from storage so the path
        //            search sees the latest advertisement set ──
        sofi.syncVaultsForPair()

        // ── STEP 4: findAndBindBestPath — one route bound to one
        //            anchored vault state producing one exact output ──
        val unsignedRcBytes = sofi.findAndBindBestPath()
        val rc = RouteCommitV1.parseFrom(unsignedRcBytes)
        assertEquals("single-hop AMM route", 1, rc.hopsCount)
        val expectedOut = u128beToLong(rc.expectedFinalOutputAmountU128.toByteArray())
        assertTrue("expected output must be > 0 (got $expectedOut)", expectedOut > 0L)
        assertTrue(
            "hop must carry a stamped anchor-state binding (reserves digest)",
            rc.hopsList[0].vaultStateReservesDigest.size() == 32,
        )
        Log.i(TAG, "quote: exact expected=$expectedOut (single route, anchor-bound)")

        // ── STEP 5: wallet signs (SPHINCS+ stays in Rust) ──
        val signedRcBytes = sofi.signRouteCommit(unsignedRcBytes)

        // ── STEP 6: compute X (query, takes signed RouteCommit) ──
        val x = sofi.computeExternalCommitment(signedRcBytes)
        assertEquals("X is 32 bytes", 32, x.size)
        Log.i(TAG, "X = ${b32(x)}")

        // ── STEP 7: publish X anchor to storage ──
        sofi.publishExternalCommitment(x)

        // ── STEP 8: unlock against the primary vault ──
        val primaryVaultId = rc.hopsList[0].vaultId.toByteArray()
        val unlockResultVaultB32 = sofi.unlockVaultRouted(primaryVaultId, signedRcBytes)
        Log.i(TAG, "unlock returned vault=$unlockResultVaultB32")

        // ── STEP 9: verify reserves advanced (bounded retry — post-
        //            trade reserve update is async to chain advance) ──
        var primaryAfter: AmmVaultSummaryV1? = null
        var reservesMoved = false
        var attempts = 0
        while (attempts < RESERVE_POLL_ATTEMPTS && !reservesMoved) {
            val owned = sofi.listOwnedAmmVaults()
            primaryAfter = owned.firstOrNull { it.vaultId.toByteArray().contentEquals(primaryVaultId) }
            if (primaryAfter != null) {
                val ra = u128beToLong(primaryAfter.reserveAU128.toByteArray())
                val rb = u128beToLong(primaryAfter.reserveBU128.toByteArray())
                if (ra != INITIAL_RESERVE_A || rb != INITIAL_RESERVE_B) {
                    reservesMoved = true
                    break
                }
            }
            // Clockless spin — no Thread.sleep / wall-clock.
            var spin = 0
            while (spin < SPIN_BUDGET_PER_POLL) {
                spin++
            }
            attempts++
        }
        val updated = primaryAfter
            ?: fail("primary vault ${b32(primaryVaultId)} not found in listOwnedAmmVaults") as Nothing
        assertTrue(
            "reserves must move after a settled trade (polled $attempts times)",
            reservesMoved,
        )

        // Canonical pair: tokenA = DEMO_BBB (lex-lower), tokenB = ERA.
        // Trader spends ERA (tokenB) in, gets DEMO_BBB (tokenA) out.
        // So reserveB INCREASES (trader put ERA into the reserve) and
        // reserveA DECREASES (reserve paid out DEMO_BBB).
        val raAfter = u128beToLong(updated.reserveAU128.toByteArray())
        val rbAfter = u128beToLong(updated.reserveBU128.toByteArray())
        assertTrue(
            "reserveB (ERA) must grow ($rbAfter <= $INITIAL_RESERVE_B)",
            rbAfter > INITIAL_RESERVE_B,
        )
        assertTrue(
            "reserveA (DEMO_BBB) must shrink ($raAfter >= $INITIAL_RESERVE_A)",
            raAfter < INITIAL_RESERVE_A,
        )
        val actualOut = INITIAL_RESERVE_A - raAfter
        // Exact-output guarantee: the trade was bound to the exact vault
        // state, so the settled output equals the quoted expected output.
        assertEquals(
            "actual output must EXACTLY equal the quoted expected output",
            expectedOut,
            actualOut,
        )

        Log.i(
            TAG,
            "settled vault=${b32(primaryVaultId)} " +
                "actual=$actualOut expected=$expectedOut " +
                "post: reserveA=$raAfter reserveB=$rbAfter attempts=$attempts",
        )
    }
}
