package com.dsm.wallet.bridge.ble

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

// Tests exercise `CompletableDeferred.getCompleted()` (Experimental) and
// `Channel.isClosedForSend` (Delicate). Both are deliberate test-only
// uses of unstable coroutine APIs to inspect coroutine state after
// PeerSession's lifecycle methods run — opt-in here keeps production
// code free of the annotations.
@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PeerSessionTest {

    // ═══════════════════════════════════════════════════════════════════════
    //  PeerSession – default values
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun defaultSession_isNotConnected() {
        val s = PeerSession(address = "AA:BB:CC:DD:EE:FF")
        assertFalse(s.isConnected)
    }

    @Test
    fun defaultSession_mtuIs23() {
        assertEquals(23, PeerSession(address = "X").negotiatedMtu)
    }

    @Test
    fun defaultSession_hasNoActiveClientSession() {
        assertFalse(PeerSession(address = "X").hasActiveClientSession)
    }

    @Test
    fun defaultSession_isNotServerClient() {
        assertFalse(PeerSession(address = "X").isServerClient)
    }

    @Test
    fun defaultSession_connectionNotPending() {
        assertFalse(PeerSession(address = "X").connectionPending)
    }

    @Test
    fun defaultSession_isEmpty() {
        assertTrue(PeerSession(address = "X").isEmpty)
    }

    @Test
    fun defaultSession_reconnectAttemptCountIsZero() {
        assertEquals(0, PeerSession(address = "X").reconnectAttemptCount)
    }

    @Test
    fun defaultSession_serverTransferNonceIsZero() {
        assertEquals(0.toByte(), PeerSession(address = "X").serverTransferNonce)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PeerSession – computed properties
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun connectionPending_trueWhenConnectResultSet() {
        val s = PeerSession(address = "X")
        s.connectResult = CompletableDeferred()
        assertTrue(s.connectionPending)
    }

    @Test
    fun isEmpty_falseWhenConnectResultPending() {
        val s = PeerSession(address = "X")
        s.connectResult = CompletableDeferred()
        assertFalse(s.isEmpty)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PeerSession – isSubscribedTo
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun isSubscribedTo_returnsFalseWhenEmpty() {
        val s = PeerSession(address = "X")
        assertFalse(s.isSubscribedTo(UUID.randomUUID()))
    }

    @Test
    fun isSubscribedTo_returnsTrueAfterSubscription() {
        val uuid = UUID.randomUUID()
        val s = PeerSession(address = "X")
        s.subscribedCccds[uuid] = true
        assertTrue(s.isSubscribedTo(uuid))
    }

    @Test
    fun isSubscribedTo_returnsFalseIfSetToFalse() {
        val uuid = UUID.randomUUID()
        val s = PeerSession(address = "X")
        s.subscribedCccds[uuid] = false
        assertFalse(s.isSubscribedTo(uuid))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PeerSession – clearClientState
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun clearClientState_resetsAllClientFields() {
        val s = PeerSession(address = "X").apply {
            isConnected = true
            negotiatedMtu = 512
            serviceDiscoveryCompleted = true
        }
        s.clearClientState()

        assertFalse(s.isConnected)
        assertEquals(23, s.negotiatedMtu)
        assertFalse(s.serviceDiscoveryCompleted)
        assertNull(s.lastError)
        assertFalse(s.clientRouteReady)
        assertNull(s.connectResult)
    }

    @Test
    fun clearClientState_completesConnectResultWithFalse() {
        val deferred = CompletableDeferred<Boolean>()
        val s = PeerSession(address = "X").apply { connectResult = deferred }
        s.clearClientState()

        assertTrue(deferred.isCompleted)
        assertFalse(deferred.getCompleted())
    }

    @Test
    fun clearClientState_doesNotResetReconnectAttemptCount() {
        val s = PeerSession(address = "X").apply { reconnectAttemptCount = 5 }
        s.clearClientState()
        assertEquals(5, s.reconnectAttemptCount)
    }

    @Test
    fun clearClientState_doesNotAffectServerState() {
        val uuid = UUID.randomUUID()
        val s = PeerSession(address = "X").apply {
            isConnected = true
            subscribedCccds[uuid] = true
            serverTransferNonce = 42
        }
        s.clearClientState()

        assertTrue(s.isSubscribedTo(uuid))
        assertEquals(42.toByte(), s.serverTransferNonce)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PeerSession – clearServerState
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun clearServerState_resetsAllServerFields() {
        val uuid = UUID.randomUUID()
        val s = PeerSession(address = "X").apply {
            subscribedCccds[uuid] = true
            notificationCompletion = CompletableDeferred()
            chunkAckChannel = Channel(1)
        }
        s.clearServerState()

        assertNull(s.serverDevice)
        assertTrue(s.subscribedCccds.isEmpty())
        assertNull(s.notificationCompletion)
        assertNull(s.chunkAckChannel)
    }

    @Test
    fun clearServerState_cancelsNotificationCompletion() {
        val deferred = CompletableDeferred<Boolean>()
        val s = PeerSession(address = "X").apply { notificationCompletion = deferred }
        s.clearServerState()
        assertTrue(deferred.isCancelled)
    }

    @Test
    fun clearServerState_closesChunkAckChannel() {
        val ch = Channel<Int>(1)
        val s = PeerSession(address = "X").apply { chunkAckChannel = ch }
        s.clearServerState()
        assertTrue(ch.isClosedForSend)
    }

    @Test
    fun clearServerState_doesNotAffectClientState() {
        val s = PeerSession(address = "X").apply {
            isConnected = true
            negotiatedMtu = 256
        }
        s.clearServerState()

        assertTrue(s.isConnected)
        assertEquals(256, s.negotiatedMtu)
    }

    @Test
    fun clearServerState_resetsWriteBudget() {
        val s = PeerSession(address = "X")
        s.clearServerState()
        assertNotNull(s.writeBudget)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PeerSession – data class copy
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun copy_preservesAddress() {
        val s = PeerSession(address = "A")
        val c = s.copy(negotiatedMtu = 512)
        assertEquals("A", c.address)
        assertEquals(512, c.negotiatedMtu)
    }
}
