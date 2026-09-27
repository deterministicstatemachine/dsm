package com.dsm.wallet.bridge.ble

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.mock
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleCoordinatorResolveSessionTest {

    @Test
    fun resolveSession_hydratesPersistedIdentityAndFindsFreshPeerAddress() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val coordinator = BleCoordinator(
            context = context,
            permissionsGate = mock(),
            advertiser = mock(),
            gattServer = mock(),
            scanner = mock(),
            diagnostics = BleDiagnostics(),
        )
        val staleAddress = "6B:CA:44:6D:D9:33"
        val freshAddress = "49:63:1E:15:0A:AA"
        val identity = PeerIdentity(
            deviceId = ByteArray(32) { index -> (index + 1).toByte() },
            genesisHash = ByteArray(32) { index -> (index + 65).toByte() },
        )
        coordinator.persistedIdentityLookup = { address ->
            if (address == staleAddress) identity else null
        }
        coordinator.peers[freshAddress] = PeerSession(freshAddress).apply {
            this.identity = identity
            isConnected = true
            gattClientSession = mock()
        }

        val resolved = coordinator.resolveSession(staleAddress)

        assertNotNull(resolved)
        assertEquals(freshAddress, resolved?.second)
        assertEquals(identity, coordinator.addressIndex[staleAddress])
    }

    /**
     * A ready session to some other peer is never a route to the one addressed:
     * with no identity match the answer is "no route", and the frame stays owed.
     */
    @Test
    fun resolveSession_neverRoutesToTheSoleReadyPeerWithoutIdentity() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val coordinator = BleCoordinator(
            context = context,
            permissionsGate = mock(),
            advertiser = mock(),
            gattServer = mock(),
            scanner = mock(),
            diagnostics = BleDiagnostics(),
        )
        coordinator.persistedIdentityLookup = { null }
        coordinator.peers["49:63:1E:15:0A:AA"] = PeerSession("49:63:1E:15:0A:AA").apply {
            isConnected = true
            gattClientSession = mock()
        }

        assertNull(coordinator.resolveSession("6B:CA:44:6D:D9:33"))
    }

    /**
     * The one ready peer is anchored to B; the send is addressed to A. Routing
     * it to B would hand A's frame to a third appliance.
     */
    @Test
    fun resolveSession_neverRoutesATargetToAReadyPeerAnchoredToAnotherIdentity() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val coordinator = BleCoordinator(
            context = context,
            permissionsGate = mock(),
            advertiser = mock(),
            gattServer = mock(),
            scanner = mock(),
            diagnostics = BleDiagnostics(),
        )
        val targetAddress = "2C:DA:46:4B:73:FA"
        val otherAddress = "48:4F:B6:BA:D4:02"
        val target = PeerIdentity(
            deviceId = ByteArray(32) { 0x4d },
            genesisHash = ByteArray(32) { 0x01 },
        )
        val other = PeerIdentity(
            deviceId = ByteArray(32) { 0x16 },
            genesisHash = ByteArray(32) { 0x02 },
        )
        coordinator.persistedIdentityLookup = { address -> if (address == targetAddress) target else null }
        coordinator.peers[otherAddress] = PeerSession(otherAddress).apply {
            identity = other
            isConnected = true
            gattClientSession = mock()
        }

        assertNull(coordinator.resolveSession(targetAddress))
    }
}
