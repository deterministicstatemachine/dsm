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
            outbox = mock<BleOutbox>(),
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

    @Test
    fun resolveSession_refusesSingleReadyPeerGuessWithoutIdentity() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val coordinator = BleCoordinator(
            context = context,
            permissionsGate = mock(),
            advertiser = mock(),
            gattServer = mock(),
            scanner = mock(),
            outbox = mock<BleOutbox>(),
            diagnostics = BleDiagnostics(),
        )
        coordinator.peers["49:63:1E:15:0A:AA"] = PeerSession("49:63:1E:15:0A:AA").apply {
            isConnected = true
            gattClientSession = mock()
        }

        val resolved = coordinator.resolveSession("6B:CA:44:6D:D9:33")

        assertNull(resolved)
    }
}
