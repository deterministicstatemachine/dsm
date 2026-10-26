// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.service

import android.Manifest
import android.app.Application
import android.app.NotificationManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * The icon count is the number Rust hands over, drawn as one notice and taken
 * down at zero; without the notification permission nothing is drawn.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MoneyReceivedNoticeTest {
    private lateinit var ctx: Context
    private lateinit var manager: NotificationManager

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        manager = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        MoneyReceivedNotice.attach(ctx)
    }

    @Test
    fun theNoticeCarriesRustsCountAndGoesAtZero() {
        shadowOf(ctx as Application).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)

        MoneyReceivedNotice.show(2)
        val posted = shadowOf(manager).allNotifications
        assertEquals(1, posted.size)
        assertEquals(2, posted[0].number)
        assertEquals("dsm_money_received", posted[0].channelId)

        MoneyReceivedNotice.show(3)
        val updated = shadowOf(manager).allNotifications
        assertEquals("one notice, updated in place", 1, updated.size)
        assertEquals(3, updated[0].number)

        MoneyReceivedNotice.show(0)
        assertEquals(0, shadowOf(manager).allNotifications.size)
    }

    @Test
    fun withoutThePermissionNothingIsDrawn() {
        shadowOf(ctx as Application).denyPermissions(Manifest.permission.POST_NOTIFICATIONS)

        MoneyReceivedNotice.show(4)
        assertEquals(0, shadowOf(manager).allNotifications.size)
        assertNull(manager.getNotificationChannel("dsm_money_received"))
    }
}
