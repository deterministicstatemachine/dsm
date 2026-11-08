// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.service

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.annotation.Keep
import androidx.annotation.VisibleForTesting
import androidx.core.app.NotificationCompat
import com.dsm.wallet.ui.MainActivity

/**
 * The count on the app icon: the transfers Rust received and verified that the
 * user has not opened the b0x inbox on yet (owner, 2026-10-23).
 *
 * Rust decides the number (`sdk::money_waiting::publish`) and calls [show]
 * whenever it can have changed. Android launchers draw an icon badge only from
 * a posted notification, so the count is one quiet notification with that
 * number, taken down at zero. It names no amount and no sender: those stay in
 * the app. Its channel is low importance — no sound, no pop-up — so the icon
 * badge is the whole of it.
 */
object MoneyReceivedNotice {
    private const val TAG = "MoneyReceivedNotice"
    private const val CHANNEL_ID = "dsm_money_received"
    private const val NOTIFICATION_ID = 8342

    /** Set once by [com.dsm.wallet.App]; Rust calls in with no context of its own. */
    @Volatile private var appContext: Context? = null

    @JvmStatic
    fun attach(ctx: Context) {
        appContext = ctx.applicationContext
    }

    /** Called from Rust with the number of received transfers waiting. */
    @Keep
    @JvmStatic
    fun show(count: Int) {
        val ctx = checkNotNull(appContext) {
            "MoneyReceivedNotice.attach was not called before Rust published a count ($count)"
        }
        draw(ctx, count)
    }

    @VisibleForTesting
    internal fun draw(ctx: Context, count: Int) {
        val manager = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (count <= 0) {
            manager.cancel(NOTIFICATION_ID)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.w(TAG, "$count waiting; notifications are not permitted, so the icon shows no count")
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Money received", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "The count on the DSM icon of transfers you have not opened your b0x on yet"
                }
            )
        }
        val open = PendingIntent.getActivity(
            ctx,
            NOTIFICATION_ID,
            Intent(ctx, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val text = if (count == 1) {
            "1 transfer is waiting in your b0x"
        } else {
            "$count transfers are waiting in your b0x"
        }
        val notification = NotificationCompat.Builder(ctx, CHANNEL_ID)
            .setContentTitle("Money received")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_more)
            .setNumber(count)
            .setBadgeIconType(NotificationCompat.BADGE_ICON_SMALL)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(open)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
    }
}
