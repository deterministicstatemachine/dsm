package com.dsm.wallet.bridge.ble

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleCoordinatorTest {

    private lateinit var appContext: Application
    private lateinit var coordinator: BleCoordinator

    @Before
    fun setUp() {
        appContext = ApplicationProvider.getApplicationContext()
        coordinator = BleCoordinator(
            appContext,
            BlePermissionsGate(appContext),
            BleAdvertiser(appContext),
            GattServerHost(appContext),
        )
    }

    @After
    fun tearDown() {
        coordinator.peers.clear()
        coordinator.addressIndex.clear()
        coordinator.permissionsGate.cleanup()
    }

    @Test
    fun resolveSession_returnsDirectActiveClientSession() {
        val peer = PeerSession(address = "AA:BB").apply {
            gattClientSession = activeGattClientSession("AA:BB")
            isConnected = true
        }
        coordinator.peers["AA:BB"] = peer

        val resolved = coordinator.resolveSession("AA:BB")

        assertNotNull(resolved)
        assertSame(peer, resolved!!.first)
        assertEquals("AA:BB", resolved.second)
    }

    @Test
    fun resolveSession_usesIdentityIndexForStaleAddress() {
        val identity = PeerIdentity(
            deviceId = ByteArray(32) { 0x11.toByte() },
            genesisHash = ByteArray(32) { 0x22.toByte() },
        )
        coordinator.addressIndex["old:addr"] = identity
        coordinator.peers["old:addr"] = PeerSession(address = "old:addr").apply {
            this.identity = identity
        }
        val freshPeer = PeerSession(address = "new:addr").apply {
            this.identity = identity
            gattClientSession = activeGattClientSession("new:addr")
            isConnected = true
        }
        coordinator.peers["new:addr"] = freshPeer

        val resolved = coordinator.resolveSession("old:addr")

        assertNotNull(resolved)
        assertSame(freshPeer, resolved!!.first)
        assertEquals("new:addr", resolved.second)
    }

    @Test
    fun resolveSession_fallsBackToAnyReadySession() {
        val fallbackPeer = PeerSession(address = "fallback").apply {
            gattClientSession = activeGattClientSession("fallback")
            isConnected = true
        }
        coordinator.peers["fallback"] = fallbackPeer

        val resolved = coordinator.resolveSession("unknown")

        assertNotNull(resolved)
        assertSame(fallbackPeer, resolved!!.first)
        assertEquals("fallback", resolved.second)
    }

    @Test
    fun resolveSession_returnsNullWhenNoReachablePeerExists() {
        coordinator.peers["shell"] = PeerSession(address = "shell")

        assertNull(coordinator.resolveSession("shell"))
        assertNull(coordinator.resolveSession("missing"))
    }

    @Test
    fun anchorIdentity_updatesPeerAndAddressIndex() {
        val peer = PeerSession(address = "AA:CC")
        val identity = PeerIdentity(
            deviceId = ByteArray(32) { 0x33.toByte() },
            genesisHash = ByteArray(32) { 0x44.toByte() },
        )
        coordinator.peers["AA:CC"] = peer

        coordinator.anchorIdentity("AA:CC", identity)

        assertSame(identity, peer.identity)
        assertSame(identity, coordinator.addressIndex["AA:CC"])
    }

    @Test
    fun updatePeerAddress_migratesSessionAndIndex() {
        val identity = PeerIdentity(
            deviceId = ByteArray(32) { 0x55.toByte() },
            genesisHash = ByteArray(32) { 0x66.toByte() },
        )
        val peer = PeerSession(address = "old:addr").apply {
            this.identity = identity
            gattClientSession = activeGattClientSession("old:addr")
            isConnected = true
        }
        coordinator.peers["old:addr"] = peer
        coordinator.addressIndex["old:addr"] = identity

        coordinator.updatePeerAddress(identity, "new:addr")

        assertNull(coordinator.peers["old:addr"])
        assertNull(coordinator.addressIndex["old:addr"])
        assertSame(peer, coordinator.peers["new:addr"])
        assertSame(identity, coordinator.addressIndex["new:addr"])
    }

    @Test
    fun updatePeerAddress_isNoOpForUnknownIdentity() {
        val identity = PeerIdentity(
            deviceId = ByteArray(32) { 0x77.toByte() },
            genesisHash = ByteArray(32) { 0x88.toByte() },
        )

        coordinator.updatePeerAddress(identity, "new:addr")

        assertTrue(coordinator.peers.isEmpty())
        assertTrue(coordinator.addressIndex.isEmpty())
    }

    private fun activeGattClientSession(address: String): GattClientSession {
        return GattClientSession(
            appContext,
            address,
            BleDiagnostics(),
            BlePermissionsGate(appContext),
        ) { }
    }
}
