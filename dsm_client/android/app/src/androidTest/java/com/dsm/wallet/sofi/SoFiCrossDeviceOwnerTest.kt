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
 * Phase 8 cross-device SoFi test — OWNER side (Wallet A).
 *
 * Pairs with [SoFiCrossDeviceTraderTest] running on a physically
 * distinct second device.  Together they prove SoFi spec §4.1's
 * "once a valid σ exists on storage, the unlock is computable by
 * anyone" property on real hardware — Wallet A creates AMM vaults on
 * this device (e.g. Galaxy A54) and publishes routing advertisements;
 * Wallet B on a second device (e.g. Galaxy A16) discovers them via
 * shared storage and trades against them.
 *
 * This test runs on the **owner** device.  It:
 *   1. Creates two AMM vaults with distinct fee tiers (30 bps, 50 bps).
 *   2. Publishes routing advertisements so the trader's
 *      `route.syncVaultsForPair` can discover them via storage.
 *   3. Logs a sentinel line that the host-side orchestrator scrapes
 *      to extract (salt, vault_ids, output_token_b32) and pass to the
 *      trader's test as `-P` instrumentation args.
 *   4. Enters a bounded poll loop watching for post-trade reserve
 *      drift via `dlv.listOwnedAmmVaults` — the trader's settle
 *      propagates back through storage + local cache refresh.
 *   5. Once drift is detected, asserts the post-trade reserves match
 *      the same intent-bound math Phase 5 asserts.
 *
 * The orchestrator script
 * (`dsm_client/android/scripts/run_cross_device_sofi_test.sh`) drives
 * both tests in sequence with the appropriate args; see that file +
 * `docs/cross-device-sofi-test.md` for runbook context.
 *
 * Run standalone (for debugging this side only — the post-trade poll
 * will time out without a paired trader):
 *
 *     ./gradlew :app:connectedAndroidTest \
 *         -Pandroid.testInstrumentationRunnerArguments.class=\
 *         com.dsm.wallet.sofi.SoFiCrossDeviceOwnerTest
 *
 * Watch logs:
 *     adb logcat -s SOFI_TRADE SOFI_XDEV
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SoFiCrossDeviceOwnerTest {

    companion object {
        const val XDEV_TAG = "SOFI_XDEV"

        /** Bounded poll for the trader's settlement to propagate back to
         *  the owner's local DLVManager.  Each attempt = one
         *  `dlv.listOwnedAmmVaults` query + a CPU spin budget; total
         *  budget is much wider than the single-device test because
         *  cross-device storage round-trips dominate. */
        const val SETTLEMENT_POLL_ATTEMPTS: Int = 60
        const val SETTLEMENT_POLL_SPIN_BUDGET: Int = 1_000_000
    }

    @Suppress("unused")
    private fun ctx(): Context = InstrumentationRegistry.getInstrumentation().targetContext

    private var activity: ActivityScenario<MainActivity>? = null
    private lateinit var sofi: SoFiTestContext

    @Before
    fun setUp() {
        val (outputToken, lexLower, lexHigher) = freshOutputTokenForRun()
        sofi = SoFiTestContext(outputToken, lexLower, lexHigher)

        activity = ActivityScenario.launch(MainActivity::class.java)
        val installed = waitForAppRouter(maxPollAttempts = 600, pollMs = 100L)
        Assume.assumeTrue(
            "AppRouter never installed on the owner device — wallet bootstrap " +
                "did not finish.  Open the wallet UI once to complete genesis.",
            installed,
        )

        // Owner does not spend ERA in this test (the trader spends),
        // but we still poll balance.get to confirm the trust snapshot
        // is published — without it route handlers refuse to run.
        val balance = pollBalanceUntilTrustReady("ERA", maxAttempts = 900, pollMs = 100L)
        Log.i(TAG, "owner setUp: ERA balance = $balance (any value OK for owner role)")
        Assume.assumeTrue(
            "Owner device has no published trust snapshot (balance.get returned $balance). " +
                "Ensure genesis + C-DBRW resume completed before the test runs.",
            balance >= 0L,
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
    fun t01_owner_publishes_vaults_and_waits_for_trader_settle() {
        // Per-run unique salt so each run gets fresh vault_ids that don't
        // collide with prior runs' permanent storage entries.
        val runSalt = ByteArray(16).also { SecureRandom().nextBytes(it) }
            .joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }
        val label1 = "sofi-xdev-owner-vault-1-$runSalt"
        val label2 = "sofi-xdev-owner-vault-2-$runSalt"

        // ── STEP 1: create two AMM vaults with different fee tiers ──
        val vault1Id = sofi.createAmmVault(label1, VAULT1_FEE_BPS)
        val vault2Id = sofi.createAmmVault(label2, VAULT2_FEE_BPS)
        Log.i(TAG, "owner vaults created: salt=$runSalt v1=${b32(vault1Id)} v2=${b32(vault2Id)}")
        assertEquals("vault_id is 32 bytes", 32, vault1Id.size)
        assertEquals("vault_id is 32 bytes", 32, vault2Id.size)

        // ── STEP 2: publish routing advertisements for both ──
        sofi.publishRoutingAdvertisement(vault1Id, VAULT1_FEE_BPS, label1)
        sofi.publishRoutingAdvertisement(vault2Id, VAULT2_FEE_BPS, label2)
        Log.i(TAG, "owner ads published for pair lex_lower=${sofi.outputToken.decodeAscii()} lex_higher=ERA")

        // ── STEP 3: emit the orchestrator sentinel.  Single line,
        //            grep-friendly key=value pairs.  The host script
        //            extracts these and passes them to the trader's
        //            test as -Pandroid.testInstrumentationRunnerArguments
        //            entries. ──
        Log.i(
            XDEV_TAG,
            "owner_published " +
                "salt=$runSalt " +
                "v1=${b32(vault1Id)} " +
                "v2=${b32(vault2Id)} " +
                "output_token_b32=${b32(sofi.outputToken)}",
        )

        // ── STEP 4: bounded poll for post-trade reserve drift.  The
        //            trader's dlv.unlockRouted settles on its own
        //            self-loop chain; the owner's local DLVManager
        //            reflects the reserve advance once it refreshes
        //            from storage (route.syncVaultsForPair invocations
        //            in this poll trigger that refresh path). ──
        val canonicalLower = sofi.outputToken // DEMO_BBB-style (lex-lower)
        var primaryVaultId: ByteArray? = null
        var settled: AmmVaultSummaryV1? = null
        var attempts = 0
        while (attempts < SETTLEMENT_POLL_ATTEMPTS) {
            // Refresh from storage each iteration so the trader's
            // settled advertisement (with bumped state_number)
            // propagates into our local view.
            try {
                sofi.syncVaultsForPair()
            } catch (t: Throwable) {
                Log.w(TAG, "owner poll: syncVaultsForPair failed: ${t.message}")
            }
            val owned = sofi.listOwnedAmmVaults()
            // Locate either of our two vaults whose reserves have moved.
            settled = owned.firstOrNull { summary ->
                val vid = summary.vaultId.toByteArray()
                val matchesOurs = vid.contentEquals(vault1Id) || vid.contentEquals(vault2Id)
                if (!matchesOurs) return@firstOrNull false
                val ra = u128beToLong(summary.reserveAU128.toByteArray())
                val rb = u128beToLong(summary.reserveBU128.toByteArray())
                ra != INITIAL_RESERVE_A || rb != INITIAL_RESERVE_B
            }
            if (settled != null) {
                primaryVaultId = settled.vaultId.toByteArray()
                break
            }
            // Clockless spin budget between polls.
            var spin = 0
            while (spin < SETTLEMENT_POLL_SPIN_BUDGET) {
                spin++
            }
            attempts++
        }

        val updated = settled ?: run {
            // Surface a useful diagnostic before failing — what does the
            // owner's local view actually show after the poll budget?
            val finalSnapshot = sofi.listOwnedAmmVaults()
                .filter { s ->
                    val vid = s.vaultId.toByteArray()
                    vid.contentEquals(vault1Id) || vid.contentEquals(vault2Id)
                }
                .map { s ->
                    val ra = u128beToLong(s.reserveAU128.toByteArray())
                    val rb = u128beToLong(s.reserveBU128.toByteArray())
                    "${b32(s.vaultId.toByteArray())}: ra=$ra rb=$rb"
                }
            Log.e(TAG, "owner poll: trader settlement never reached us. snapshot=$finalSnapshot")
            fail("Trader settlement not observed on owner device within $attempts poll attempts.")
            return
        }
        val vid = primaryVaultId!!

        // ── STEP 5: assert the same intent-bound math Phase 5 asserts.
        //            Trader spent ERA (lex-higher = reserveB) and
        //            received output_token (lex-lower = reserveA), so
        //            reserveB grew and reserveA shrunk. ──
        val raAfter = u128beToLong(updated.reserveAU128.toByteArray())
        val rbAfter = u128beToLong(updated.reserveBU128.toByteArray())
        assertTrue(
            "reserveB (ERA) must grow after trader settle ($rbAfter <= $INITIAL_RESERVE_B)",
            rbAfter > INITIAL_RESERVE_B,
        )
        assertTrue(
            "reserveA (output_token) must shrink after trader settle ($raAfter >= $INITIAL_RESERVE_A)",
            raAfter < INITIAL_RESERVE_A,
        )
        val actualOut = INITIAL_RESERVE_A - raAfter
        val actualIn = rbAfter - INITIAL_RESERVE_B
        assertTrue("trader's input must be > 0 (got $actualIn)", actualIn > 0L)
        assertTrue("trader's output must be > 0 (got $actualOut)", actualOut > 0L)

        Log.i(
            XDEV_TAG,
            "owner_observed_settle " +
                "vault=${b32(vid)} " +
                "actual_in=$actualIn actual_out=$actualOut " +
                "post: reserveA=$raAfter reserveB=$rbAfter " +
                "attempts=$attempts",
        )

        // Match the canonical pair claim: lex_lower IS the output token
        // (the salted DEMO_*), lex_higher IS ERA — defensive check that
        // canonicalLower wasn't accidentally swapped.
        assertEquals(
            "owner vault's tokenA must equal the lex-lower OUTPUT_TOKEN we created with",
            canonicalLower.toList(),
            updated.tokenA.toByteArray().toList(),
        )
    }

    private fun ByteArray.decodeAscii(): String = String(this, Charsets.UTF_8)
}
