// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.sofi

import android.content.Context
import android.util.Log
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import com.dsm.wallet.bridge.BridgeEncoding
import com.dsm.wallet.ui.MainActivity
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

/**
 * Phase 8 cross-device SoFi test — TRADER side (Wallet B).
 *
 * Pairs with [SoFiCrossDeviceOwnerTest] running on a physically
 * distinct first device.  See that file's class doc for the spec
 * rationale.
 *
 * This test runs on the **trader** device.  It:
 *   1. Reads instrumentation args (owner_salt, owner_v1_b32,
 *      owner_v2_b32, output_token_b32) populated by the
 *      orchestrator from the owner's logcat sentinel.
 *   2. Claims faucet ERA if the local balance is below
 *      [MIN_ERA_BALANCE].
 *   3. Runs `route.syncVaultsForPair` and asserts the owner's
 *      vaults are discovered via shared storage (proves the
 *      cross-device storage round trip).
 *   4. Runs the rest of the SoFi trade flow:
 *      findAndBindBestPath → signRouteCommit → computeExternalCommitment
 *      → publishExternalCommitment → dlv.unlockRouted.
 *   5. Logs a settlement sentinel the orchestrator scrapes for the
 *      pass/fail report.
 *
 * Cross-device note: this test CANNOT use `dlv.listOwnedAmmVaults`
 * for post-trade verification because that route filters by
 * `creator_public_key == local_pk` (dlv_routes.rs:84), and the
 * trader is NOT the vault owner.  Instead, the orchestrator pairs
 * this test's `trader_settled` logcat line with the owner's
 * `owner_observed_settle` line for cross-validation.
 *
 * Run standalone (will skip via Assume.assumeTrue if the orchestrator
 * args are missing):
 *
 *     ./gradlew :app:connectedAndroidTest \
 *         -Pandroid.testInstrumentationRunnerArguments.class=\
 *         com.dsm.wallet.sofi.SoFiCrossDeviceTraderTest \
 *         -Pandroid.testInstrumentationRunnerArguments.owner_salt=<salt> \
 *         -Pandroid.testInstrumentationRunnerArguments.owner_v1_b32=<v1> \
 *         -Pandroid.testInstrumentationRunnerArguments.owner_v2_b32=<v2> \
 *         -Pandroid.testInstrumentationRunnerArguments.output_token_b32=<out>
 *
 * Watch logs:
 *     adb logcat -s SOFI_TRADE SOFI_XDEV
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SoFiCrossDeviceTraderTest {

    companion object {
        const val XDEV_TAG = "SOFI_XDEV"
        const val ARG_OWNER_SALT = "owner_salt"
        const val ARG_OWNER_V1_B32 = "owner_v1_b32"
        const val ARG_OWNER_V2_B32 = "owner_v2_b32"
        const val ARG_OUTPUT_TOKEN_B32 = "output_token_b32"
    }

    @Suppress("unused")
    private fun ctx(): Context = InstrumentationRegistry.getInstrumentation().targetContext

    private var activity: ActivityScenario<MainActivity>? = null
    private lateinit var sofi: SoFiTestContext
    private lateinit var ownerVault1Id: ByteArray
    private lateinit var ownerVault2Id: ByteArray

    @Before
    fun setUp() {
        // ── Read orchestrator args ─────────────────────────────────
        val args = InstrumentationRegistry.getArguments()
        val ownerSalt = args.getString(ARG_OWNER_SALT)
        val ownerV1B32 = args.getString(ARG_OWNER_V1_B32)
        val ownerV2B32 = args.getString(ARG_OWNER_V2_B32)
        val outputTokenB32 = args.getString(ARG_OUTPUT_TOKEN_B32)
        Assume.assumeTrue(
            "Missing orchestrator args — run via " +
                "scripts/run_cross_device_sofi_test.sh, OR pass " +
                "-Pandroid.testInstrumentationRunnerArguments.{$ARG_OWNER_SALT," +
                "$ARG_OWNER_V1_B32,$ARG_OWNER_V2_B32,$ARG_OUTPUT_TOKEN_B32} " +
                "manually for standalone debugging.",
            ownerSalt != null && ownerV1B32 != null && ownerV2B32 != null && outputTokenB32 != null,
        )
        ownerVault1Id = BridgeEncoding.base32CrockfordDecode(ownerV1B32!!)
        ownerVault2Id = BridgeEncoding.base32CrockfordDecode(ownerV2B32!!)
        val outputToken = BridgeEncoding.base32CrockfordDecode(outputTokenB32!!)
        require(ownerVault1Id.size == 32) {
            "owner_v1_b32 must decode to 32 bytes (got ${ownerVault1Id.size})"
        }
        require(ownerVault2Id.size == 32) {
            "owner_v2_b32 must decode to 32 bytes (got ${ownerVault2Id.size})"
        }
        Log.i(
            TAG,
            "trader setUp: orchestrator args parsed " +
                "salt=$ownerSalt v1=$ownerV1B32 v2=$ownerV2B32 output_token=${b32(outputToken)}",
        )

        // Build the SoFi context with the owner's exact canonical pair
        // (lex-lower = owner's outputToken; lex-higher = ERA).  The
        // pair MUST match the owner's vaults verbatim or the trader's
        // route.syncVaultsForPair will look in the wrong storage prefix.
        sofi = SoFiTestContext(
            outputToken = outputToken,
            lexLower = outputToken,
            lexHigher = INPUT_TOKEN,
        )

        // ── Boot the wallet + wait for trust snapshot ──────────────
        activity = ActivityScenario.launch(MainActivity::class.java)
        val installed = waitForAppRouter(maxPollAttempts = 600, pollMs = 100L)
        Assume.assumeTrue(
            "AppRouter never installed on the trader device — wallet bootstrap " +
                "did not finish.  Open the wallet UI once to complete genesis.",
            installed,
        )

        // ── Claim faucet ERA if balance is low ─────────────────────
        var balance = pollBalanceUntilTrustReady("ERA", maxAttempts = 900, pollMs = 100L)
        Log.i(TAG, "trader setUp: initial ERA balance = $balance (need >= $MIN_ERA_BALANCE)")
        if (balance in 0 until MIN_ERA_BALANCE) {
            Log.i(TAG, "trader setUp: balance below threshold, attempting faucet claim")
            val claimed = claimFaucetEra()
            if (claimed) {
                // Re-poll for the credited balance — faucet credit
                // commits via Operation::Mint which has its own
                // commit-and-propagate latency.
                balance = pollBalanceUntilTrustReady("ERA", maxAttempts = 200, pollMs = 100L)
                Log.i(TAG, "trader setUp: post-claim ERA balance = $balance")
            } else {
                Log.w(TAG, "trader setUp: faucet.claim route failed; balance unchanged")
            }
        }
        Assume.assumeTrue(
            "Trader device needs ERA balance >= $MIN_ERA_BALANCE (have $balance). " +
                "Faucet.claim was attempted but did not credit enough.  Open the " +
                "wallet UI → faucet → claim manually, then re-run.",
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
    fun t01_trader_discovers_and_settles_against_owner_published_vaults() {
        // ── STEP 1: sync the canonical pair from shared storage ────
        // This is the load-bearing cross-device read: the owner's
        // route.publishRoutingAdvertisement on their device wrote to
        // the shared sofi/vault/... keyspace; our sync must read it
        // back.
        sofi.syncVaultsForPair()
        Log.i(TAG, "trader: syncVaultsForPair OK; proceeding to path search")

        // ── STEP 2: findAndBindBestPath against the owner's vaults ─
        val unsignedRcBytes = sofi.findAndBindBestPath()
        val rc = RouteCommitV1.parseFrom(unsignedRcBytes)
        assertEquals("single-hop AMM route", 1, rc.hopsCount)

        // CROSS-DEVICE CRITICAL ASSERT: the discovered vault_id MUST
        // be one of the owner's published vault_ids.  This proves the
        // storage round trip worked and the path search found the
        // owner's advertisement (not, say, a stale ad from a prior
        // run on this trader device).
        val pickedVaultId = rc.hopsList[0].vaultId.toByteArray()
        val isOwnerVault = pickedVaultId.contentEquals(ownerVault1Id) ||
            pickedVaultId.contentEquals(ownerVault2Id)
        assertTrue(
            "Trader's findAndBindBestPath picked vault=${b32(pickedVaultId)} " +
                "which is NEITHER owner's v1=${b32(ownerVault1Id)} NOR " +
                "owner's v2=${b32(ownerVault2Id)} — storage round trip failed " +
                "or path search picked a stale local vault.",
            isOwnerVault,
        )
        Log.i(
            TAG,
            "trader: path search picked owner's vault=${b32(pickedVaultId)} " +
                "(matches ${if (pickedVaultId.contentEquals(ownerVault1Id)) "v1" else "v2"})",
        )

        // Exact-output binding assertions: one route, one anchored state,
        // one exact output. There is no fallback and no slippage floor —
        // the hop carries a stamped anchor-state binding, and the
        // unlock-time gate re-simulates for an EXACT output match.
        val expectedOut = u128beToLong(rc.expectedFinalOutputAmountU128.toByteArray())
        assertTrue("expected output must be > 0 (got $expectedOut)", expectedOut > 0L)
        assertTrue(
            "hop must carry a stamped anchor-state binding (reserves digest)",
            rc.hopsList[0].vaultStateReservesDigest.size() == 32,
        )
        Log.i(TAG, "trader quote: exact expected=$expectedOut (single route, anchor-bound)")

        // ── STEP 3: sign the RouteCommit (SPHINCS+ stays in Rust) ──
        val signedRcBytes = sofi.signRouteCommit(unsignedRcBytes)

        // ── STEP 4: compute X (query, takes signed RouteCommit) ────
        val x = sofi.computeExternalCommitment(signedRcBytes)
        assertEquals("X is 32 bytes", 32, x.size)
        Log.i(TAG, "trader: X = ${b32(x)}")

        // ── STEP 5: publish X anchor to shared storage so the unlock
        //            gate (on this device, but also visible to the
        //            owner) sees it. ─
        sofi.publishExternalCommitment(x)

        // ── STEP 6: unlock — atomic settlement.  The handler verifies
        //            X is visible on storage, re-simulates the AMM swap
        //            against the owner's advertised reserves, and emits
        //            Operation::DlvUnlock on THIS device's self-loop
        //            chain.  Cross-device confidence: the handler does
        //            NOT gate the unlock on `creator_public_key ==
        //            local_pk` — only the post-settle anchor republish
        //            is owner-gated (Phase 6 fix). ─
        val unlockResultVaultB32 = sofi.unlockVaultRouted(pickedVaultId, signedRcBytes)
        Log.i(TAG, "trader: unlock returned vault=$unlockResultVaultB32")
        assertEquals(
            "dlv.unlockRouted echoed wrong vault_id",
            b32(pickedVaultId),
            unlockResultVaultB32,
        )

        // ── STEP 7: settlement sentinel for the orchestrator ───────
        Log.i(
            XDEV_TAG,
            "trader_settled " +
                "vault=${b32(pickedVaultId)} " +
                "expected_out=$expectedOut",
        )

        // Note: post-trade reserve verification (assert reserveA shrunk,
        // reserveB grew, actualOut >= floor) lives on the OWNER's side
        // because dlv.listOwnedAmmVaults filters by creator_pk and
        // returns nothing for us.  The orchestrator pairs our
        // `trader_settled` line with the owner's `owner_observed_settle`
        // line and runs the cross-validation on the host.
    }
}
