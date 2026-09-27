package com.dsm.wallet.bridge.ble

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
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
        coordinator.abandonedCandidates.clear()
        coordinator.permissionsGate.cleanup()
    }

    private val target = PeerIdentity(
        deviceId = ByteArray(32) { 0x4d },
        genesisHash = ByteArray(32) { 0x01 },
    )
    private val other = PeerIdentity(
        deviceId = ByteArray(32) { 0x16 },
        genesisHash = ByteArray(32) { 0x02 },
    )

    /** Our client link, its identity read anchored to [identity]: a route to that appliance. */
    private fun anchoredClientLink(address: String, identity: PeerIdentity) =
        PeerSession(address = address).apply {
            gattClientSession = activeGattClientSession(address)
            isConnected = true
            this.identity = identity
            clientRouteReady = true
        }

    /** A peer's link to our server, subscribed to TX_RESPONSE, anchored to [identity] or to no one. */
    private fun subscribedServerLink(address: String, identity: PeerIdentity?) =
        PeerSession(address = address).apply {
            serverDevice = serverDevice(address)
            subscribedCccds[BleConstants.TX_RESPONSE_UUID] = true
            this.identity = identity
        }

    @Test
    fun resolveRoute_takesTheClientLinkAnchoredToTheTarget() {
        coordinator.peers["2C:DA:46:4B:73:FA"] = anchoredClientLink("2C:DA:46:4B:73:FA", target)

        assertEquals(
            BleCoordinator.BleRoute("2C:DA:46:4B:73:FA", clientLink = true),
            coordinator.resolveRoute(target.deviceId, ""),
        )
    }

    /** The route follows the appliance's identity to its current address, whatever the hint. */
    @Test
    fun resolveRoute_findsTheTargetAtItsCurrentAddress() {
        coordinator.peers["new:addr"] = anchoredClientLink("new:addr", target)

        assertEquals(
            BleCoordinator.BleRoute("new:addr", clientLink = true),
            coordinator.resolveRoute(target.deviceId, "old:addr"),
        )
    }

    /**
     * A connected client link is not a route until the identity read on it is
     * anchored: before that it may carry any appliance, and its CCCD chain may
     * still be running.
     */
    @Test
    fun resolveRoute_waitsForTheIdentityReadOnAClientLink() {
        coordinator.peers["2C:DA:46:4B:73:FA"] = PeerSession(address = "2C:DA:46:4B:73:FA").apply {
            gattClientSession = activeGattClientSession("2C:DA:46:4B:73:FA")
            isConnected = true
        }

        assertNull(coordinator.resolveRoute(target.deviceId, "2C:DA:46:4B:73:FA"))
    }

    /**
     * An appliance known from an earlier link: a new client link to it is not a
     * route until the identity read on that link completes, after its CCCD
     * chain — a chunk written before discovery finds no characteristic.
     */
    @Test
    fun resolveRoute_waitsForTheIdentityReadOnANewLinkToAKnownAppliance() {
        coordinator.peers["2C:DA:46:4B:73:FA"] = PeerSession(address = "2C:DA:46:4B:73:FA").apply {
            gattClientSession = activeGattClientSession("2C:DA:46:4B:73:FA")
            isConnected = true
            identity = target
        }

        assertNull(coordinator.resolveRoute(target.deviceId, "2C:DA:46:4B:73:FA"))
    }

    /**
     * The one ready link is anchored to B; the send is addressed to A, even at
     * B's address. Routing it to B would hand A's frame to a third appliance.
     */
    @Test
    fun resolveRoute_neverRoutesToALinkAnchoredToAnotherAppliance() {
        coordinator.peers["48:4F:B6:BA:D4:02"] = anchoredClientLink("48:4F:B6:BA:D4:02", other)
        coordinator.peers["49:63:1E:15:0A:AA"] = subscribedServerLink("49:63:1E:15:0A:AA", other)

        assertNull(coordinator.resolveRoute(target.deviceId, ""))
        assertNull(coordinator.resolveRoute(target.deviceId, "48:4F:B6:BA:D4:02"))
        assertNull(coordinator.resolveRoute(target.deviceId, "49:63:1E:15:0A:AA"))
    }

    @Test
    fun resolveRoute_takesTheServerLinkAnchoredToTheTarget() {
        coordinator.peers["5A:5A:5A:5A:5A:5A"] = subscribedServerLink("5A:5A:5A:5A:5A:5A", target)

        assertEquals(
            BleCoordinator.BleRoute("5A:5A:5A:5A:5A:5A", clientLink = false),
            coordinator.resolveRoute(target.deviceId, ""),
        )
    }

    /**
     * A link to our server that no identity read anchored is a route only at
     * the address the SDK names for the appliance — the link its frame
     * arrived on — never as the sole link in range.
     */
    @Test
    fun resolveRoute_takesAnUnanchoredServerLinkOnlyAtTheHint() {
        coordinator.peers["5A:5A:5A:5A:5A:5A"] = subscribedServerLink("5A:5A:5A:5A:5A:5A", null)

        assertNull(coordinator.resolveRoute(target.deviceId, ""))
        assertNull(coordinator.resolveRoute(target.deviceId, "2C:DA:46:4B:73:FA"))
        assertEquals(
            BleCoordinator.BleRoute("5A:5A:5A:5A:5A:5A", clientLink = false),
            coordinator.resolveRoute(target.deviceId, "5A:5A:5A:5A:5A:5A"),
        )
    }

    @Test
    fun resolveRoute_isNullWithNoLink() {
        coordinator.peers["shell"] = PeerSession(address = "shell")

        assertNull(coordinator.resolveRoute(target.deviceId, "shell"))
        assertNull(coordinator.resolveRoute(target.deviceId, "missing"))
    }

    /**
     * A reach ended while one of its candidates was still connecting: that
     * link's identity read is judged against the same appliance, once. With
     * no reach and no abandoned candidate, a read expects no one.
     */
    @Test
    fun anAbandonedCandidatesIdentityReadExpectsTheReachsAppliance() {
        coordinator.abandonedCandidates["76:9B:A6:69:67:06"] = target.deviceId

        assertTrue(coordinator.takeExpectedIdentity("76:9B:A6:69:67:06").contentEquals(target.deviceId))
        assertEquals(0, coordinator.takeExpectedIdentity("76:9B:A6:69:67:06").size)
        assertEquals(0, coordinator.takeExpectedIdentity("2C:DA:46:4B:73:FA").size)
    }

    @Test
    fun anchorIdentity_anchorsThePeer() {
        val peer = PeerSession(address = "AA:CC")
        coordinator.peers["AA:CC"] = peer

        coordinator.anchorIdentity("AA:CC", target)

        assertSame(target, peer.identity)
    }

    private fun activeGattClientSession(address: String): GattClientSession {
        return GattClientSession(
            appContext,
            address,
            BleDiagnostics(),
            BlePermissionsGate(appContext),
        ) { }
    }

    private fun serverDevice(address: String) =
        appContext.getSystemService(android.bluetooth.BluetoothManager::class.java)
            ?.adapter
            ?.getRemoteDevice(address)
}
