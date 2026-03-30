package com.dsm.wallet.bridge.ble

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BleCoordinatorSingleFlightTest {
    private lateinit var context: Context
    private lateinit var coordinator: BleCoordinator

    // Mocks and counters
    private val mockPermissions: BlePermissionsGate = mock()
    private val mockAdvertiser: BleAdvertiser = mock()
    private val mockGatt: GattServerHost = mock()

    private val advStarted = AtomicBoolean(false)
    private val advStartCount = AtomicInteger(0)
    private val gattEnsureCount = AtomicInteger(0)

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Use test-friendly constructor to inject mocks
        coordinator = BleCoordinator(
            context = context,
            permissionsGate = mockPermissions,
            advertiser = mockAdvertiser,
            gattServer = mockGatt
        )

        // Stub permissions to allow advertising
        whenever(mockPermissions.hasAdvertisePermission()).thenReturn(true)

        // Stub advertiser behavior: record start calls and reflect state in isAdvertising()
        whenever(mockAdvertiser.isAdvertising()).thenAnswer { advStarted.get() }
        whenever(mockAdvertiser.startAdvertising()).thenAnswer {
            advStartCount.incrementAndGet()
            advStarted.set(true)
            true
        }
        whenever(mockAdvertiser.stopAdvertising()).thenAnswer {
            advStarted.set(false)
            true
        }

        // Stub GATT ensure: count invocations
        runBlocking {
            whenever(mockGatt.ensureStarted()).thenAnswer {
                gattEnsureCount.incrementAndGet()
                true
            }
        }
    }

    @After
    fun tearDown() {
        // Reset state between tests
        advStarted.set(false)
        advStartCount.set(0)
        gattEnsureCount.set(0)
        coordinator.cleanup()
    }

    @Test
    fun startAdvertising_isSingleFlightAcrossConcurrentRequests() = runBlocking {
        // Launch multiple concurrent requests to startAdvertising
        val tasks = (1..10).map {
            async(Dispatchers.Default) {
                coordinator.startAdvertising()
            }
        }
        tasks.forEach { it.await() }

        // Only one GATT ensure and one advertiser start should occur
        assertEquals("GattServer.ensureStarted should be called exactly once", 1, gattEnsureCount.get())
        assertEquals("BleAdvertiser.startAdvertising should be called exactly once", 1, advStartCount.get())
    }

    @Test
    fun startAdvertising_idempotentWhenAlreadyAdvertising() = runBlocking {
        // First call starts advertising
        coordinator.startAdvertising()
        assertEquals(1, advStartCount.get())
        assertEquals(1, gattEnsureCount.get())

        // Subsequent calls should short-circuit and not trigger new starts
        coordinator.startAdvertising()
        coordinator.startAdvertising()

        assertEquals("No additional advertiser start calls after already advertising", 1, advStartCount.get())
        assertEquals("No additional GATT ensure calls after initial start", 1, gattEnsureCount.get())
    }

    // No reflection helpers needed; we rely on the test-only constructor
}
