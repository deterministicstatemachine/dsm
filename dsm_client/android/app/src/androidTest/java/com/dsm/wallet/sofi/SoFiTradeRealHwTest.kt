// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.sofi

import android.content.Context
import android.util.Log
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import com.dsm.wallet.bridge.BridgeEncoding
import com.dsm.wallet.bridge.NativeBoundaryBridge
import com.dsm.wallet.bridge.Unified
import com.dsm.wallet.ui.MainActivity
import com.google.protobuf.ByteString
import dsm.types.proto.AmmConstantProduct
import dsm.types.proto.AmmVaultSummaryV1
import dsm.types.proto.ArgPack
import dsm.types.proto.AnchorEnforcement
import dsm.types.proto.BalanceGetResponse
import dsm.types.proto.Codec
import dsm.types.proto.DlvInstantiateV1
import dsm.types.proto.DlvSpecV1
import dsm.types.proto.DlvUnlockRoutedV1
import dsm.types.proto.Envelope
import dsm.types.proto.ExternalCommitmentV1
import dsm.types.proto.FindAndBindRouteRequest
import dsm.types.proto.FulfillmentMechanism
import dsm.types.proto.IngressResponse
import dsm.types.proto.PublishRoutingAdvertisementRequest
import dsm.types.proto.RouteCommitV1
import dsm.types.proto.RoutingPairRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Real-hardware verification for the full SoFi (Sovereign Finance) trade
 * pipeline on a single connected Android device. Walks the 9-route
 * end-to-end flow through `NativeBoundaryBridge` (Kotlin → JNI → Rust):
 *
 *   1. `dlv.create` × 2          (two AMM vaults, different fee tiers)
 *   2. `route.publishRoutingAdvertisement` × 2
 *   3. `route.syncVaultsForPair`
 *   4. `route.findAndBindBestPath` (Tier 2: maxPaths=3, slippageBps=50)
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
 *    Tier 2 trade across the bridge without truncation, schema drift,
 *    or threading deadlocks.
 *  - `route.findAndBindBestPath(maxPaths=3)` actually returns a
 *    RouteCommit with a non-empty `fallbacks` field when two vaults
 *    advertise on the same pair (proves the N-best enumerator wired
 *    end-to-end through the handler).
 *  - The post-trade reserve update (chunks #7 republish-on-settled)
 *    completes within the bounded poll window after `dlv.unlockRouted`.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SoFiTradeRealHwTest {

    private companion object {
        const val TAG = "SOFI_TRADE"

        // Token ids. Lex order: "DEMO_BBB" (0x44...) < "ERA" (0x45...).
        // Canonical AMM pair = (lex-lower, lex-higher) → (DEMO_BBB, ERA).
        // Trader spends ERA (tokenB on the vault) and receives
        // DEMO_BBB (tokenA on the vault).
        val INPUT_TOKEN: ByteArray = "ERA".toByteArray(Charsets.UTF_8)
        val OUTPUT_TOKEN: ByteArray = "DEMO_BBB".toByteArray(Charsets.UTF_8)
        val LEX_LOWER: ByteArray = OUTPUT_TOKEN
        val LEX_HIGHER: ByteArray = INPUT_TOKEN

        const val INITIAL_RESERVE_A: Long = 1_000_000L
        const val INITIAL_RESERVE_B: Long = 1_000_000L
        const val INPUT_AMOUNT: Long = 1_000L
        const val MIN_ERA_BALANCE: Long = 5_000L

        const val VAULT1_FEE_BPS: Int = 30
        const val VAULT2_FEE_BPS: Int = 50
        const val MAX_PATHS: Int = 3
        const val SLIPPAGE_BPS: Int = 50
        const val FLOOR_BPS: Int = 50

        // Bounded poll for the post-trade reserve update — the handler
        // commits the on-chain DlvUnlock then updates vault state in a
        // second lock acquisition. No wall-clock per the clockless rule.
        const val RESERVE_POLL_ATTEMPTS: Int = 10
        const val SPIN_BUDGET_PER_POLL: Int = 200_000
    }

    @Suppress("unused")
    private fun ctx(): Context = InstrumentationRegistry.getInstrumentation().targetContext

    private var activity: ActivityScenario<MainActivity>? = null

    @Before
    fun setUp() {
        // Launch MainActivity so its onCreate runs the full DSM bootstrap
        // sequence (initStorageBaseDir → initDsmSdk → initSdk →
        // bootstrapFromPrefs → ensureAppRouterInstalled). The AppRouter is
        // installed asynchronously after identity + binding key are ready;
        // poll Unified.ensureAppRouterInstalled() with a bounded retry
        // until it returns true. No wall-clock — bounded spin.
        activity = ActivityScenario.launch(MainActivity::class.java)
        // C-DBRW derivation + bridge install can take ~30s on first run
        // when the wallet was just installed. Use SystemClock.sleep for
        // the test-side wait loop (this is test plumbing, not a protocol
        // decision — the clockless rule applies to protocol code only).
        val installed = waitForAppRouter(maxPollAttempts = 600, pollMs = 100L)
        Assume.assumeTrue(
            "AppRouter never installed — wallet bootstrap did not finish. " +
                "Check that the device has a valid genesis identity (open the " +
                "wallet UI once first to complete genesis).",
            installed,
        )

        val balance = getBalance("ERA")
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

    private fun waitForAppRouter(maxPollAttempts: Int, pollMs: Long): Boolean {
        for (i in 0 until maxPollAttempts) {
            val ready = try {
                Unified.ensureAppRouterInstalled()
            } catch (_: Throwable) {
                false
            }
            if (ready) {
                Log.i(TAG, "waitForAppRouter: ready after $i attempts (~${i * pollMs}ms)")
                return true
            }
            android.os.SystemClock.sleep(pollMs)
        }
        Log.w(TAG, "waitForAppRouter: gave up after $maxPollAttempts attempts")
        return false
    }

    @Test
    fun t01_trade_settles_against_tier2_envelope() {
        // ── STEP 1: create two AMM vaults with different fee tiers ──
        val vault1Id = createAmmVault("sofi-test-vault-1", VAULT1_FEE_BPS)
        val vault2Id = createAmmVault("sofi-test-vault-2", VAULT2_FEE_BPS)
        Log.i(TAG, "vaults created: v1=${b32(vault1Id)} v2=${b32(vault2Id)}")
        assertEquals("vault_id is 32 bytes", 32, vault1Id.size)
        assertEquals("vault_id is 32 bytes", 32, vault2Id.size)

        // ── STEP 2: publish routing advertisements for both ──
        publishRoutingAdvertisement(vault1Id, VAULT1_FEE_BPS, "sofi-test-vault-1")
        publishRoutingAdvertisement(vault2Id, VAULT2_FEE_BPS, "sofi-test-vault-2")

        // ── STEP 3: sync the canonical pair from storage so the path
        //            search sees the latest advertisement set ──
        syncVaultsForPair()

        // ── STEP 4: findAndBindBestPath with Tier 2 envelope params ──
        val unsignedRcBytes = findAndBindBestPath()
        val rc = RouteCommitV1.parseFrom(unsignedRcBytes)
        assertEquals("single-hop AMM route", 1, rc.hopsCount)
        assertTrue(
            "Tier 2 must populate fallbacks when 2 vaults advertise on the pair (got ${rc.fallbacksCount})",
            rc.fallbacksCount >= 1,
        )
        val floorOut = u128beToLong(rc.floorFinalOutputAmountU128.toByteArray())
        val expectedOut = u128beToLong(rc.expectedFinalOutputAmountU128.toByteArray())
        assertTrue("envelope floor must be stamped (got $floorOut)", floorOut > 0L)
        assertTrue("expected output must be > 0 (got $expectedOut)", expectedOut > 0L)
        assertTrue(
            "expected output $expectedOut must be >= envelope floor $floorOut",
            expectedOut >= floorOut,
        )
        val perHopFloor = u128beToLong(rc.hopsList[0].minOutputAmountU128.toByteArray())
        assertTrue("per-hop intent-bound floor must be stamped (got $perHopFloor)", perHopFloor > 0L)
        Log.i(
            TAG,
            "quote: expected=$expectedOut floor=$floorOut perHopFloor=$perHopFloor " +
                "fallbackGroups=${rc.fallbacksCount}",
        )

        // ── STEP 5: wallet signs (SPHINCS+ stays in Rust) ──
        val signedRcBytes = signRouteCommit(unsignedRcBytes)

        // ── STEP 6: compute X (query, takes signed RouteCommit) ──
        val x = computeExternalCommitment(signedRcBytes)
        assertEquals("X is 32 bytes", 32, x.size)
        Log.i(TAG, "X = ${b32(x)}")

        // ── STEP 7: publish X anchor to storage ──
        publishExternalCommitment(x)

        // ── STEP 8: unlock against the primary vault ──
        val primaryVaultId = rc.hopsList[0].vaultId.toByteArray()
        val unlockResultVaultB32 = unlockVaultRouted(primaryVaultId, signedRcBytes)
        Log.i(TAG, "unlock returned vault=$unlockResultVaultB32")

        // ── STEP 9: verify reserves advanced (bounded retry — post-
        //            trade reserve update is async to chain advance) ──
        var primaryAfter: AmmVaultSummaryV1? = null
        var reservesMoved = false
        var attempts = 0
        while (attempts < RESERVE_POLL_ATTEMPTS && !reservesMoved) {
            val owned = listOwnedAmmVaults()
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
        // So reserveB INCREASES (trader put ERA into the pool) and
        // reserveA DECREASES (pool paid out DEMO_BBB).
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
        assertTrue(
            "actual output $actualOut must meet intent-bound floor $floorOut",
            actualOut >= floorOut,
        )

        Log.i(
            TAG,
            "settled vault=${b32(primaryVaultId)} " +
                "actual=$actualOut floor=$floorOut " +
                "post: reserveA=$raAfter reserveB=$rbAfter " +
                "fallbacks=${rc.fallbacksCount} attempts=$attempts",
        )
    }

    // ─────────────────────────────────────────────────────────────────
    // Bridge invocation helpers — wrap NativeBoundaryBridge with the
    // ArgPack envelope + IngressResponse + 0x03-framed Envelope-v3
    // decoding the AppRouter uses on every route.
    // ─────────────────────────────────────────────────────────────────

    private fun routerInvoke(method: String, body: ByteArray): Envelope {
        val packed = packArgs(body)
        val raw = NativeBoundaryBridge.routerInvoke(method, packed)
        return decodeIngressEnvelope(raw, method)
    }

    private fun routerQuery(method: String, body: ByteArray): Envelope {
        val packed = packArgs(body)
        val raw = NativeBoundaryBridge.routerQuery(method, packed)
        return decodeIngressEnvelope(raw, method)
    }

    private fun packArgs(body: ByteArray): ByteArray {
        return ArgPack.newBuilder()
            .setCodec(Codec.CODEC_PROTO)
            .setBody(ByteString.copyFrom(body))
            .build()
            .toByteArray()
    }

    private fun decodeIngressEnvelope(raw: ByteArray, methodForError: String): Envelope {
        val ir = try {
            IngressResponse.parseFrom(raw)
        } catch (e: Exception) {
            fail("$methodForError: failed to parse IngressResponse: ${e.message}")
            return Envelope.getDefaultInstance() // unreachable
        }
        when (ir.resultCase) {
            IngressResponse.ResultCase.OK_BYTES -> {
                val okBytes = ir.okBytes.toByteArray()
                if (okBytes.isEmpty()) {
                    fail("$methodForError: ok envelope was empty")
                }
                val envelopeBytes = if (okBytes[0] == 0x03.toByte() && okBytes.size > 1) {
                    okBytes.copyOfRange(1, okBytes.size)
                } else {
                    okBytes
                }
                val env = try {
                    Envelope.parseFrom(envelopeBytes)
                } catch (e: Exception) {
                    fail("$methodForError: failed to parse Envelope: ${e.message}")
                    return Envelope.getDefaultInstance()
                }
                if (env.payloadCase == Envelope.PayloadCase.ERROR) {
                    fail("$methodForError: route returned error: ${env.error.message}")
                }
                return env
            }
            IngressResponse.ResultCase.ERROR -> {
                fail("$methodForError: ingress error: ${ir.error.message}")
            }
            else -> {
                fail("$methodForError: ingress returned unexpected result ${ir.resultCase}")
            }
        }
        return Envelope.getDefaultInstance() // unreachable
    }

    private fun appStateValue(env: Envelope, methodForError: String): String {
        if (env.payloadCase != Envelope.PayloadCase.APP_STATE_RESPONSE) {
            fail("$methodForError: expected APP_STATE_RESPONSE, got ${env.payloadCase}")
        }
        return env.appStateResponse.value ?: ""
    }

    // ─────────────────────────────────────────────────────────────────
    // Per-route helpers — each builds the proto request, calls the
    // bridge, decodes the response. No business logic — pure framing.
    // ─────────────────────────────────────────────────────────────────

    private fun getBalance(tokenId: String): Long {
        // `balance.get` accepts `ArgPack { codec=PROTO, body=<UTF-8 token id> }`
        val body = tokenId.toByteArray(Charsets.UTF_8)
        val env = routerQuery("balance.get", body)
        if (env.payloadCase != Envelope.PayloadCase.BALANCE_GET_RESPONSE) {
            fail("balance.get: expected BALANCE_GET_RESPONSE, got ${env.payloadCase}")
        }
        val resp: BalanceGetResponse = env.balanceGetResponse
        return resp.available
    }

    private fun createAmmVault(label: String, feeBps: Int): ByteArray {
        // Build the AmmConstantProduct fulfillment with canonical
        // (tokenA, tokenB) = (DEMO_BBB, ERA) since DEMO_BBB is lex-lower.
        val amm = AmmConstantProduct.newBuilder()
            .setTokenA(ByteString.copyFrom(LEX_LOWER))
            .setTokenB(ByteString.copyFrom(LEX_HIGHER))
            .setReserveAU128(ByteString.copyFrom(u128be(INITIAL_RESERVE_A)))
            .setReserveBU128(ByteString.copyFrom(u128be(INITIAL_RESERVE_B)))
            .setFeeBps(feeBps)
            .build()
        val fm = FulfillmentMechanism.newBuilder()
            .setAmmConstantProduct(amm)
            .build()
        val fulfillmentBytes = fm.toByteArray()

        // Distinct content per vault → distinct vault_id (computed
        // Rust-side from device_id + policy_digest + content_digest).
        val content = "SoFiTradeRealHwTest:$label:fee=$feeBps".toByteArray(Charsets.UTF_8)
        // Synthetic but stable 32-byte policy anchor — the dlv.create
        // handler stores this verbatim without verifying it against
        // a registered CPTA policy. Sufficient for vault creation.
        val policyDigest = blake3Like32("DSM/sofi-test-policy:$label")

        val spec = DlvSpecV1.newBuilder()
            .setPolicyDigest(ByteString.copyFrom(policyDigest))
            // Leave content_digest + fulfillment_digest empty — Rust
            // computes them per the accept-or-compute path.
            .setFulfillmentBytes(ByteString.copyFrom(fulfillmentBytes))
            .setContent(ByteString.copyFrom(content))
            .setAnchorEnforcement(AnchorEnforcement.ANCHOR_ENFORCEMENT_REQUIRED)
            .build()
        val req = DlvInstantiateV1.newBuilder()
            .setSpec(spec)
            // Empty pk + signature → Rust accept-or-stamp uses the
            // wallet's pk + signs Track C.4 style.
            .setCreatorPublicKey(ByteString.EMPTY)
            .setTokenId(ByteString.EMPTY)
            .setLockedAmountU128(ByteString.copyFrom(ByteArray(16)))
            .setSignature(ByteString.EMPTY)
            .build()

        val env = routerInvoke("dlv.create", req.toByteArray())
        val vaultIdB32 = appStateValue(env, "dlv.create")
        require(vaultIdB32.isNotEmpty()) { "dlv.create returned empty vault_id" }
        return BridgeEncoding.base32CrockfordDecode(vaultIdB32)
    }

    private fun publishRoutingAdvertisement(
        vaultId: ByteArray,
        feeBps: Int,
        label: String,
    ) {
        // Rust handler computes the BLAKE3 digest from vault_proto_bytes.
        // We pass a synthetic but stable proto-bytes blob (matches the
        // pattern in demo_full_amm_trade_e2e).
        val vaultProtoBytes = ("demo-vault-proto:$label:" + b32(vaultId)).toByteArray(Charsets.UTF_8)
        val unlockSpecDigest = blake3Like32("DSM/sofi-test-unlock:$label")
        val req = PublishRoutingAdvertisementRequest.newBuilder()
            .setVaultId(ByteString.copyFrom(vaultId))
            .setTokenA(ByteString.copyFrom(LEX_LOWER))
            .setTokenB(ByteString.copyFrom(LEX_HIGHER))
            .setReserveAU128(ByteString.copyFrom(u128be(INITIAL_RESERVE_A)))
            .setReserveBU128(ByteString.copyFrom(u128be(INITIAL_RESERVE_B)))
            .setFeeBps(feeBps)
            .setUnlockSpecDigest(ByteString.copyFrom(unlockSpecDigest))
            .setUnlockSpecKey("defi/spec/sofi-test/$label")
            // Empty owner_public_key → Rust stamps wallet pk.
            .setOwnerPublicKey(ByteString.EMPTY)
            .setVaultProtoBytes(ByteString.copyFrom(vaultProtoBytes))
            .build()
        val env = routerInvoke("route.publishRoutingAdvertisement", req.toByteArray())
        val returnedVaultB32 = appStateValue(env, "route.publishRoutingAdvertisement")
        require(returnedVaultB32 == b32(vaultId)) {
            "route.publishRoutingAdvertisement returned $returnedVaultB32, expected ${b32(vaultId)}"
        }
    }

    private fun syncVaultsForPair() {
        val req = RoutingPairRequest.newBuilder()
            .setTokenA(ByteString.copyFrom(LEX_LOWER))
            .setTokenB(ByteString.copyFrom(LEX_HIGHER))
            .build()
        routerInvoke("route.syncVaultsForPair", req.toByteArray())
        // Result envelope is an ack — we don't need its body.
    }

    private fun findAndBindBestPath(): ByteArray {
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val req = FindAndBindRouteRequest.newBuilder()
            .setInputToken(ByteString.copyFrom(INPUT_TOKEN))
            .setOutputToken(ByteString.copyFrom(OUTPUT_TOKEN))
            .setInputAmountU128(ByteString.copyFrom(u128be(INPUT_AMOUNT)))
            .setMaxHops(0) // 0 → server default (4)
            .setNonce(ByteString.copyFrom(nonce))
            .setMaxPaths(MAX_PATHS)
            .setSlippageBps(SLIPPAGE_BPS)
            .setFloorBps(FLOOR_BPS)
            .build()
        val env = routerInvoke("route.findAndBindBestPath", req.toByteArray())
        val unsignedB32 = appStateValue(env, "route.findAndBindBestPath")
        require(unsignedB32.isNotEmpty()) { "findAndBindBestPath returned empty unsigned RouteCommit" }
        return BridgeEncoding.base32CrockfordDecode(unsignedB32)
    }

    private fun signRouteCommit(unsignedBytes: ByteArray): ByteArray {
        val env = routerInvoke("route.signRouteCommit", unsignedBytes)
        val signedB32 = appStateValue(env, "route.signRouteCommit")
        require(signedB32.isNotEmpty()) { "signRouteCommit returned empty signed RouteCommit" }
        return BridgeEncoding.base32CrockfordDecode(signedB32)
    }

    private fun computeExternalCommitment(signedRcBytes: ByteArray): ByteArray {
        val env = routerQuery("route.computeExternalCommitment", signedRcBytes)
        val xB32 = appStateValue(env, "route.computeExternalCommitment")
        require(xB32.isNotEmpty()) { "computeExternalCommitment returned empty X" }
        return BridgeEncoding.base32CrockfordDecode(xB32)
    }

    private fun publishExternalCommitment(x: ByteArray) {
        val req = ExternalCommitmentV1.newBuilder()
            .setVersion(1)
            .setX(ByteString.copyFrom(x))
            // Empty publisher_public_key → Rust stamps wallet pk.
            .setPublisherPublicKey(ByteString.EMPTY)
            .setLabel("sofi-test")
            .build()
        val env = routerInvoke("route.publishExternalCommitment", req.toByteArray())
        val returnedXB32 = appStateValue(env, "route.publishExternalCommitment")
        require(returnedXB32 == b32(x)) {
            "publishExternalCommitment returned $returnedXB32, expected ${b32(x)}"
        }
    }

    private fun unlockVaultRouted(vaultId: ByteArray, signedRcBytes: ByteArray): String {
        // device_id field on DlvUnlockRoutedV1 is the unlocker's
        // device id; for a same-wallet trade we let Rust derive it
        // from the wallet's current state — but the proto requires
        // 32 bytes, so pull the current device id via balance metadata
        // path. Simpler: send 32 bytes of zeros and let the handler
        // reject if it cares (it accepts non-empty bytes; the value
        // is informational, not a verification gate per dlv_routes.rs).
        // To be safe we mirror the frontend pattern and supply the
        // actual device id derived from the genesis state — but
        // without a dedicated route to fetch it from instrumentation
        // context, the safe path is to read it from an existing
        // balance query response if exposed. The current handler
        // strict-checks `device_id.len() == 32`, nothing more.
        val deviceId = ByteArray(32) // 32 zero bytes — passes the length gate
        val req = DlvUnlockRoutedV1.newBuilder()
            .setVaultId(ByteString.copyFrom(vaultId))
            .setDeviceId(ByteString.copyFrom(deviceId))
            .setRouteCommitBytes(ByteString.copyFrom(signedRcBytes))
            // Empty unlocker_public_key → handler falls back to device_id.
            .setUnlockerPublicKey(ByteString.EMPTY)
            .setSignature(ByteString.EMPTY)
            .build()
        val env = routerInvoke("dlv.unlockRouted", req.toByteArray())
        return appStateValue(env, "dlv.unlockRouted")
    }

    private fun listOwnedAmmVaults(): List<AmmVaultSummaryV1> {
        val env = routerQuery("dlv.listOwnedAmmVaults", ByteArray(0))
        val joined = appStateValue(env, "dlv.listOwnedAmmVaults")
        if (joined.isEmpty()) return emptyList()
        return joined.split("\n").mapNotNull { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty()) return@mapNotNull null
            try {
                val bytes = BridgeEncoding.base32CrockfordDecode(trimmed)
                AmmVaultSummaryV1.parseFrom(bytes)
            } catch (e: Exception) {
                Log.w(TAG, "listOwnedAmmVaults: failed to decode line: ${e.message}")
                null
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Small utility helpers
    // ─────────────────────────────────────────────────────────────────

    /** Big-endian 16-byte (u128) encoding of a non-negative long. */
    private fun u128be(n: Long): ByteArray {
        require(n >= 0) { "u128be requires non-negative input" }
        val out = ByteArray(16)
        var v = n
        for (i in 15 downTo 0) {
            out[i] = (v and 0xff).toByte()
            v = v ushr 8
        }
        return out
    }

    /** Decode a 16-byte big-endian u128 to Long. Truncates if > Long.MAX_VALUE
     *  (test inputs are bounded well below that). */
    private fun u128beToLong(bytes: ByteArray): Long {
        if (bytes.isEmpty()) return 0L
        require(bytes.size == 16) { "u128beToLong expects 16 bytes, got ${bytes.size}" }
        val bi = BigInteger(1, bytes)
        // The reserve values used in this test fit in a Long.
        return bi.toLong()
    }

    private fun b32(bytes: ByteArray): String = BridgeEncoding.base32CrockfordEncode(bytes)

    /** Deterministic 32-byte digest from a label string. Uses MessageDigest
     *  SHA-256 (BLAKE3 isn't in the AndroidX stdlib but the digest only
     *  needs to be 32 bytes + collision-resistant within the test scope —
     *  the dlv.create handler stores it verbatim without semantic check). */
    private fun blake3Like32(label: String): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        md.update(label.toByteArray(Charsets.UTF_8))
        return md.digest()
    }
}
