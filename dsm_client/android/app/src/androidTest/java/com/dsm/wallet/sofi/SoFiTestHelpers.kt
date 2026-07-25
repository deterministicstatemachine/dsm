// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.sofi

import android.util.Log
import com.dsm.wallet.bridge.BridgeEncoding
import com.dsm.wallet.bridge.NativeBoundaryBridge
import com.dsm.wallet.bridge.Unified
import com.google.protobuf.ByteString
import dsm.types.proto.AmmConstantProduct
import dsm.types.proto.AmmVaultSummaryV1
import dsm.types.proto.AnchorEnforcement
import dsm.types.proto.ArgPack
import dsm.types.proto.BalanceGetResponse
import dsm.types.proto.Codec
import dsm.types.proto.DlvInstantiateV1
import dsm.types.proto.DlvSpecV1
import dsm.types.proto.DlvUnlockRoutedV1
import dsm.types.proto.Envelope
import dsm.types.proto.ExternalCommitmentV1
import dsm.types.proto.FaucetClaimRequest
import dsm.types.proto.FindAndBindRouteRequest
import dsm.types.proto.FulfillmentMechanism
import dsm.types.proto.IngressResponse
import dsm.types.proto.PublishRoutingAdvertisementRequest
import dsm.types.proto.RoutingPairRequest
import org.junit.Assert.fail
import java.math.BigInteger
import java.security.SecureRandom

// ─────────────────────────────────────────────────────────────────────
//  Shared test helpers for the SoFi (Sovereign Finance) trade family.
//
//  Three tests depend on this file:
//    • SoFiTradeRealHwTest         — Phase 5, single-device dual-role
//    • SoFiCrossDeviceOwnerTest    — Phase 8, owner side
//    • SoFiCrossDeviceTraderTest   — Phase 8, trader side
//
//  Stateless utilities live as top-level `internal` functions.  The
//  bits that need per-run token-pair state (createAmmVault /
//  publishRoutingAdvertisement / etc.) live on [SoFiTestContext],
//  which each test instantiates in its @Before with the run's
//  OUTPUT_TOKEN salt.
//
//  Any future bridge-pattern bugfix lands in ONE place here, not
//  three separate test files.
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────
// Constants — shared across all SoFi tests
// ─────────────────────────────────────────────────────────────────

internal const val TAG = "SOFI_TRADE"

/** Trader-spent input token (faucet-claimable). */
internal val INPUT_TOKEN: ByteArray = "ERA".toByteArray(Charsets.UTF_8)

internal const val INITIAL_RESERVE_A: Long = 1_000_000L
internal const val INITIAL_RESERVE_B: Long = 1_000_000L
// Production faucet (faucet_state.rs default config) credits 100 ERA per
// claim regardless of the requested amount — the server ignores the
// FaucetClaimRequest.amount field and uses its config.claim_amount.
// Test thresholds match what one claim actually grants.
internal const val INPUT_AMOUNT: Long = 10L
internal const val MIN_ERA_BALANCE: Long = 50L
internal const val FAUCET_CLAIM_AMOUNT: Long = 100L

internal const val VAULT1_FEE_BPS: Int = 30
internal const val VAULT2_FEE_BPS: Int = 50

/** Bounded poll for post-trade reserve drift — handler commits the
 *  on-chain DlvUnlock then updates vault state in a second lock
 *  acquisition.  No wall-clock per the clockless rule. */
internal const val RESERVE_POLL_ATTEMPTS: Int = 10
internal const val SPIN_BUDGET_PER_POLL: Int = 200_000

// ─────────────────────────────────────────────────────────────────
// Bridge boilerplate — stateless framing for NativeBoundaryBridge
// ─────────────────────────────────────────────────────────────────

internal fun packArgs(body: ByteArray): ByteArray {
    return ArgPack.newBuilder()
        .setCodec(Codec.CODEC_PROTO)
        .setBody(ByteString.copyFrom(body))
        .build()
        .toByteArray()
}

internal fun decodeIngressEnvelope(raw: ByteArray, methodForError: String): Envelope {
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

internal fun routerInvoke(method: String, body: ByteArray): Envelope {
    val packed = packArgs(body)
    val raw = NativeBoundaryBridge.routerInvoke(method, packed)
    return decodeIngressEnvelope(raw, method)
}

internal fun routerQuery(method: String, body: ByteArray): Envelope {
    val packed = packArgs(body)
    val raw = NativeBoundaryBridge.routerQuery(method, packed)
    return decodeIngressEnvelope(raw, method)
}

internal fun appStateValue(env: Envelope, methodForError: String): String {
    if (env.payloadCase != Envelope.PayloadCase.APP_STATE_RESPONSE) {
        fail("$methodForError: expected APP_STATE_RESPONSE, got ${env.payloadCase}")
    }
    return env.appStateResponse.value ?: ""
}

// ─────────────────────────────────────────────────────────────────
// Bootstrap-readiness pollers
// ─────────────────────────────────────────────────────────────────

/** Poll [Unified.ensureAppRouterInstalled] until the full AppRouter is
 *  installed, returning false on timeout.  Bridge install + identity
 *  restore can take a few seconds on first run after wallet creation.
 *
 *  Test plumbing uses [android.os.SystemClock.sleep]; the clockless rule
 *  applies to protocol code only. */
internal fun waitForAppRouter(maxPollAttempts: Int = 600, pollMs: Long = 100L): Boolean {
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

/** Bounded poll for `balance.get` until the full AppRouter is up (wallet
 *  unlocked, signing re-derivable from the cached wallet seed).
 *  [Unified.ensureAppRouterInstalled] returns true for the
 *  MinimalBootstrapRouter stub too — that router rejects `balance.get`
 *  with "requires genesis" until the full router takes over.  The trust
 *  snapshot publishes later still, after measure_trust runs.  This poll
 *  retries past both transitions; -1 means neither resolved within the
 *  budget. */
internal fun pollBalanceUntilTrustReady(
    tokenId: String,
    maxAttempts: Int = 900,
    pollMs: Long = 100L,
): Long {
    var lastErr: String? = null
    for (i in 0 until maxAttempts) {
        try {
            val bal = getBalance(tokenId)
            if (i > 0) {
                Log.i(TAG, "pollBalanceUntilTrustReady: ready after $i attempts (~${i * pollMs}ms)")
            }
            return bal
        } catch (t: AssertionError) {
            val msg = t.message ?: ""
            val transient =
                msg.contains("no trust snapshot has been published") ||
                    msg.contains("trust snapshot") ||
                    msg.contains("requires genesis") ||
                    msg.contains("MinimalBootstrapRouter") ||
                    msg.contains("app router not installed")
            if (transient) {
                lastErr = msg
                android.os.SystemClock.sleep(pollMs)
                continue
            }
            throw t
        }
    }
    Log.w(TAG, "pollBalanceUntilTrustReady: gave up after $maxAttempts attempts; last error: $lastErr")
    return -1L
}

internal fun getBalance(tokenId: String): Long {
    // `balance.get` accepts `ArgPack { codec=PROTO, body=<UTF-8 token id> }`
    val body = tokenId.toByteArray(Charsets.UTF_8)
    val env = routerQuery("balance.get", body)
    if (env.payloadCase != Envelope.PayloadCase.BALANCE_GET_RESPONSE) {
        fail("balance.get: expected BALANCE_GET_RESPONSE, got ${env.payloadCase}")
    }
    val resp: BalanceGetResponse = env.balanceGetResponse
    return resp.available
}

// ─────────────────────────────────────────────────────────────────
// Faucet — fund a fresh wallet identity with ERA
// ─────────────────────────────────────────────────────────────────

/** Claim [amount] ERA from the faucet for the local device.  Returns
 *  true if the route accepted, false otherwise (best-effort — the
 *  faucet may rate-limit or refuse, in which case the caller's
 *  balance-threshold skip surfaces it).
 *
 *  Mirrors the AndroidLayerProofTest:880-892 pattern but uses the
 *  high-level NativeBoundaryBridge.routerInvoke entrypoint + generated
 *  FaucetClaimRequest proto (the existing low-level test predates the
 *  generated bindings). */
internal fun claimFaucetEra(amount: Long = FAUCET_CLAIM_AMOUNT): Boolean {
    val deviceId = try {
        Unified.getDeviceIdBin()
    } catch (t: Throwable) {
        Log.w(TAG, "claimFaucetEra: getDeviceIdBin failed: ${t.message}")
        return false
    }
    if (deviceId.size != 32) {
        Log.w(TAG, "claimFaucetEra: device_id is ${deviceId.size} bytes, expected 32")
        return false
    }
    val req = FaucetClaimRequest.newBuilder()
        .setDeviceId(ByteString.copyFrom(deviceId))
        .build()
    return try {
        val env = routerInvoke("faucet.claim", req.toByteArray())
        // The route returns an AppStateResponse with the credited amount;
        // any non-error envelope counts as success.  Errors surface via
        // decodeIngressEnvelope's fail() and would short-circuit before
        // we return.
        Log.i(TAG, "claimFaucetEra: claimed amount=$amount payloadCase=${env.payloadCase}")
        true
    } catch (t: Throwable) {
        Log.w(TAG, "claimFaucetEra: route failed: ${t.message}")
        false
    }
}

// ─────────────────────────────────────────────────────────────────
// Encoding helpers
// ─────────────────────────────────────────────────────────────────

/** Big-endian 16-byte (u128) encoding of a non-negative long. */
internal fun u128be(n: Long): ByteArray {
    require(n >= 0) { "u128be requires non-negative input" }
    val out = ByteArray(16)
    var v = n
    for (i in 15 downTo 0) {
        out[i] = (v and 0xff).toByte()
        v = v ushr 8
    }
    return out
}

/** Decode a 16-byte big-endian u128 to Long.  Truncates if > Long.MAX_VALUE
 *  (test inputs are bounded well below that). */
internal fun u128beToLong(bytes: ByteArray): Long {
    if (bytes.isEmpty()) return 0L
    require(bytes.size == 16) { "u128beToLong expects 16 bytes, got ${bytes.size}" }
    val bi = BigInteger(1, bytes)
    return bi.toLong()
}

internal fun b32(bytes: ByteArray): String = BridgeEncoding.base32CrockfordEncode(bytes)

/** Deterministic 32-byte digest from a label string.  Uses MessageDigest
 *  SHA-256 (BLAKE3 isn't in the AndroidX stdlib but the digest only
 *  needs to be 32 bytes + collision-resistant within the test scope —
 *  the dlv.create handler stores it verbatim without semantic check). */
internal fun blake3Like32(label: String): ByteArray {
    val md = java.security.MessageDigest.getInstance("SHA-256")
    md.update(label.toByteArray(Charsets.UTF_8))
    return md.digest()
}

/** Build a per-run salted OUTPUT_TOKEN that lex-sorts BELOW ERA so the
 *  canonical token pair stamping is deterministic.  Returns a triple
 *  of (outputToken, lexLower, lexHigher).  Each test run's vaults
 *  occupy a fresh per-pair advertisement bucket. */
internal fun freshOutputTokenForRun(): Triple<ByteArray, ByteArray, ByteArray> {
    val tokenSalt = ByteArray(8).also { SecureRandom().nextBytes(it) }
        .joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }
    val outputToken = "00_DEMO_$tokenSalt".toByteArray(Charsets.UTF_8)
    val lexLower = outputToken
    val lexHigher = INPUT_TOKEN
    return Triple(outputToken, lexLower, lexHigher)
}

// ─────────────────────────────────────────────────────────────────
// SoFiTestContext — token-state-bound helpers
// ─────────────────────────────────────────────────────────────────

/** Bundles the per-run token state so [createAmmVault] /
 *  [publishRoutingAdvertisement] / [syncVaultsForPair] /
 *  [findAndBindBestPath] all stamp the same canonical pair. */
internal class SoFiTestContext(
    val outputToken: ByteArray,
    val lexLower: ByteArray,
    val lexHigher: ByteArray,
) {

    /** dlv.create — instantiate an AMM constant-product vault with
     *  the run's canonical (lex-lower, lex-higher) token pair and
     *  [feeBps] fee tier.  Returns the 32-byte vault_id. */
    fun createAmmVault(label: String, feeBps: Int): ByteArray {
        val amm = AmmConstantProduct.newBuilder()
            .setTokenA(ByteString.copyFrom(lexLower))
            .setTokenB(ByteString.copyFrom(lexHigher))
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
        // a registered CPTA policy.  Sufficient for vault creation.
        val policyDigest = blake3Like32("DSM/sofi-test-policy:$label")

        val spec = DlvSpecV1.newBuilder()
            .setPolicyDigest(ByteString.copyFrom(policyDigest))
            // Leave content_digest + fulfillment_digest empty — Rust
            // computes them per the accept-or-compute path.
            .setFulfillmentBytes(ByteString.copyFrom(fulfillmentBytes))
            .setContent(ByteString.copyFrom(content))
            // Tier-2 Foundation anchor binding (REQUIRED) demands that
            // RouteCommit hops carry vault_state_reserves_digest +
            // vault_state_anchor_digest stamped from the latest
            // VaultStateAnchorV1.  `route.findAndBindBestPath` doesn't
            // wire those fields yet — that's a separate workstream.
            // For this end-to-end test, OPTIONAL is sufficient to
            // exercise the full Tier-2 envelope + composition path.
            .setAnchorEnforcement(AnchorEnforcement.ANCHOR_ENFORCEMENT_OPTIONAL)
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

    /** route.publishRoutingAdvertisement — make a vault discoverable
     *  via `route.syncVaultsForPair` on the canonical (lex-lower,
     *  lex-higher) pair. */
    fun publishRoutingAdvertisement(vaultId: ByteArray, feeBps: Int, label: String) {
        // Pass empty vault_proto_bytes so the Rust handler derives the
        // canonical VaultPostProto from the local DLVManager.  The
        // previous string-placeholder was decode-failing at the
        // trader's `route.syncVaultsForPair`, leaving the trader's
        // DLVManager empty and `dlv.unlockRouted` rejecting with
        // "vault not in local DLVManager".
        val unlockSpecDigest = blake3Like32("DSM/sofi-test-unlock:$label")
        val req = PublishRoutingAdvertisementRequest.newBuilder()
            .setVaultId(ByteString.copyFrom(vaultId))
            .setTokenA(ByteString.copyFrom(lexLower))
            .setTokenB(ByteString.copyFrom(lexHigher))
            .setReserveAU128(ByteString.copyFrom(u128be(INITIAL_RESERVE_A)))
            .setReserveBU128(ByteString.copyFrom(u128be(INITIAL_RESERVE_B)))
            .setFeeBps(feeBps)
            .setUnlockSpecDigest(ByteString.copyFrom(unlockSpecDigest))
            .setUnlockSpecKey("defi/spec/sofi-test/$label")
            // Empty owner_public_key → Rust stamps wallet pk.
            .setOwnerPublicKey(ByteString.EMPTY)
            // Empty vault_proto_bytes → Rust derives from local DLVManager.
            .setVaultProtoBytes(ByteString.EMPTY)
            .build()
        val env = routerInvoke("route.publishRoutingAdvertisement", req.toByteArray())
        val returnedVaultB32 = appStateValue(env, "route.publishRoutingAdvertisement")
        require(returnedVaultB32 == b32(vaultId)) {
            "route.publishRoutingAdvertisement returned $returnedVaultB32, expected ${b32(vaultId)}"
        }
    }

    /** route.syncVaultsForPair — refresh the local DLVManager's view of
     *  vaults advertised on the canonical pair.  Result envelope is an
     *  ack we don't need to inspect. */
    fun syncVaultsForPair() {
        val req = RoutingPairRequest.newBuilder()
            .setTokenA(ByteString.copyFrom(lexLower))
            .setTokenB(ByteString.copyFrom(lexHigher))
            .build()
        routerInvoke("route.syncVaultsForPair", req.toByteArray())
    }

    /** route.findAndBindBestPath — binds the single best path to one
     *  anchored vault state (exact output, no fallback, no slippage
     *  floor).  Returns the unsigned RouteCommit proto bytes. */
    fun findAndBindBestPath(): ByteArray {
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val req = FindAndBindRouteRequest.newBuilder()
            .setInputToken(ByteString.copyFrom(INPUT_TOKEN))
            .setOutputToken(ByteString.copyFrom(outputToken))
            .setInputAmountU128(ByteString.copyFrom(u128be(INPUT_AMOUNT)))
            .setMaxHops(0) // 0 → server default (4)
            .setNonce(ByteString.copyFrom(nonce))
            .build()
        val env = routerInvoke("route.findAndBindBestPath", req.toByteArray())
        val unsignedB32 = appStateValue(env, "route.findAndBindBestPath")
        require(unsignedB32.isNotEmpty()) { "findAndBindBestPath returned empty unsigned RouteCommit" }
        return BridgeEncoding.base32CrockfordDecode(unsignedB32)
    }

    /** route.signRouteCommit — wallet signs the unsigned RouteCommit
     *  via SPHINCS+ in Rust.  Returns the signed RouteCommit bytes. */
    fun signRouteCommit(unsignedBytes: ByteArray): ByteArray {
        val env = routerInvoke("route.signRouteCommit", unsignedBytes)
        val signedB32 = appStateValue(env, "route.signRouteCommit")
        require(signedB32.isNotEmpty()) { "signRouteCommit returned empty signed RouteCommit" }
        return BridgeEncoding.base32CrockfordDecode(signedB32)
    }

    /** route.computeExternalCommitment — query that derives the 32-byte
     *  external commitment X via BLAKE3 from the signed RouteCommit. */
    fun computeExternalCommitment(signedRcBytes: ByteArray): ByteArray {
        val env = routerQuery("route.computeExternalCommitment", signedRcBytes)
        val xB32 = appStateValue(env, "route.computeExternalCommitment")
        require(xB32.isNotEmpty()) { "computeExternalCommitment returned empty X" }
        return BridgeEncoding.base32CrockfordDecode(xB32)
    }

    /** route.publishExternalCommitment — anchor X to storage so the
     *  unlock gate sees it. */
    fun publishExternalCommitment(x: ByteArray) {
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

    /** dlv.unlockRouted — atomic settlement.  Verifies X is visible on
     *  storage, re-simulates the AMM swap, emits Operation::DlvUnlock
     *  on the unlocker's self-loop chain.  Cross-device compatible:
     *  the handler does NOT gate the unlock on owner-key match (only
     *  the post-settle anchor republish is owner-gated).  Returns the
     *  vault_id Base32 string the handler echoes back. */
    fun unlockVaultRouted(vaultId: ByteArray, signedRcBytes: ByteArray): String {
        // device_id field is informational per dlv_routes.rs — the
        // handler strict-checks `device_id.len() == 32`, nothing more.
        // 32 zero bytes passes the length gate.
        val deviceId = ByteArray(32)
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

    /** dlv.listOwnedAmmVaults — enumerate the local DLVManager,
     *  filtered to AMM vaults whose creator_public_key matches the
     *  wallet's pk.  Cross-device note: a trader who is NOT the vault
     *  owner sees no entries here — they read storage's advertisement
     *  or inclusion proof instead. */
    fun listOwnedAmmVaults(): List<AmmVaultSummaryV1> {
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
}
