// path: app/src/main/java/com/dsm/wallet/bridge/BleEventRelay.kt
// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Log
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Protobuf-only BLE event relay.
 * Sends raw Envelope bytes to the JS bridge over the MessagePort (no JSON/base32).
 *
 * While the bridge is not ready, or a delivery fails, the event is kept in SQLite in arrival
 * order and replayed by [flushPersisted]. A row leaves the table only once the bridge accepted
 * it; a failed replay leaves that row and every row after it for the next flush, so the order
 * the events arrived in is the order the page sees them in.
 */
object BleEventRelay {
    private const val TAG = "BleEventRelay"
    private const val DB_NAME = "ble_events.db"
    private const val DB_VERSION = 2
    private const val TABLE = "pending_ble"
    private const val MAX_ROWS = 200

    /** Set once by [com.dsm.wallet.App]; events arrive with no context of their own. */
    @Volatile private var appContext: Context? = null
    // Track if WebView bridge is ready (set by MainActivity.signalBridgeReady)
    @Volatile private var bridgeReady = false
    // Lock for persist/flush synchronization (eliminates flushing race)
    private val eventLock = ReentrantLock()

    private class BleDbHelper(ctx: Context) : SQLiteOpenHelper(ctx, DB_NAME, null, DB_VERSION) {
        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL("CREATE TABLE IF NOT EXISTS $TABLE (id INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT NOT NULL, payload BLOB NOT NULL)")
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_pending_ble_id ON $TABLE(id)")
        }
        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            if (oldVersion != newVersion) {
                db.execSQL("DROP TABLE IF EXISTS $TABLE")
                onCreate(db)
            }
        }
    }

    @Volatile private var dbHelper: BleDbHelper? = null

    @Synchronized
    private fun db(ctx: Context): SQLiteDatabase {
        if (dbHelper == null) {
            dbHelper = BleDbHelper(ctx.applicationContext)
        }
        return dbHelper!!.writableDatabase
    }

    /** The application attaches itself once, before any BLE event can arrive. */
    @JvmStatic
    fun attach(ctx: Context) {
        appContext = ctx.applicationContext
    }

    /** Dispatch a DSM Envelope (protobuf bytes) into the WebView bridge. */
    @JvmStatic
    fun dispatchEnvelope(envelopeBytes: ByteArray) {
        Log.d(TAG, "dispatchEnvelope() called: size=${envelopeBytes.size}")
        postToBridgeBinary("ble.envelope.bin", envelopeBytes)
    }

    /** Dispatch an arbitrary DSM event with raw protobuf payload bytes. */
    @JvmStatic
    fun dispatchEvent(topic: String, payloadBytes: ByteArray) {
        Log.d(TAG, "dispatchEvent() topic=$topic size=${payloadBytes.size}")
        postToBridgeBinary(topic, payloadBytes)
    }

    /** Dispatch an event with an empty payload (still deterministic). */
    @JvmStatic
    fun dispatchEventEmpty(topic: String) {
        Log.d(TAG, "dispatchEventEmpty() topic=$topic")
        postToBridgeBinary(topic, ByteArray(0))
    }

    /** Mark the WebView bridge as ready and flush any persisted events. */
    @JvmStatic
    fun markBridgeReady(ctx: Context? = null) {
        bridgeReady = true
        Log.d(TAG, "Bridge marked as ready")

        try {
            if (!com.dsm.wallet.bridge.UnifiedNativeApi.isBleCoordinatorReady()) {
                Log.i(TAG, "Rust BLE stack not live yet: SDK init builds it once the identity exists")
            }
        } catch (t: Throwable) {
            Log.w(TAG, "BLE stack readiness check failed (non-fatal): ${t.message}")
        }

        if (ctx != null) {
            flushPersisted(ctx)
        }
    }

    /**
     * Hands the event to the bridge. Returns true only when the bridge accepted it; otherwise
     * the event is persisted (or, during a replay of persisted rows, left where it is).
     */
    private fun postToBridgeBinary(topic: String, payload: ByteArray, persistIfUnavailable: Boolean = true): Boolean {
        if (!bridgeReady) {
            if (persistIfUnavailable) {
                Log.d(TAG, "Bridge not ready, persisting event: topic=$topic")
                eventLock.withLock {
                    persistEventNoContext(topic, payload)
                }
            } else {
                Log.d(TAG, "Bridge not ready, leaving the persisted event in place: topic=$topic")
            }
            return false
        }

        return try {
            SinglePathWebViewBridge.postBinary(topic, payload)
            Log.v(TAG, "Event delivered to bridge: topic=$topic")
            true
        } catch (t: Throwable) {
            if (persistIfUnavailable) {
                Log.w(TAG, "WebView bridge unavailable: ${t.message} — persisting: topic=$topic")
                eventLock.withLock {
                    persistEventNoContext(topic, payload)
                }
            } else {
                Log.w(TAG, "WebView bridge unavailable: ${t.message} — leaving the persisted event in place: topic=$topic")
            }
            false
        }
    }

    private fun persistEventNoContext(topic: String, payload: ByteArray) {
        val ctx = checkNotNull(appContext) {
            "BleEventRelay.attach was not called before an event arrived (topic=$topic)"
        }
        persistEvent(ctx, topic, payload)
    }

    private fun persistEvent(ctx: Context, topic: String, payload: ByteArray) {
        try {
            val database = db(ctx)
            val countCursor = database.rawQuery("SELECT COUNT(*) FROM $TABLE", null)
            var count = 0
            if (countCursor.moveToFirst()) count = countCursor.getInt(0)
            countCursor.close()

            if (count >= MAX_ROWS) {
                database.execSQL("DELETE FROM $TABLE WHERE id IN (SELECT id FROM $TABLE ORDER BY id ASC LIMIT 1)")
                Log.w(TAG, "Pruned oldest event to enforce DB cap (was $count)")
            }

            val stmt = database.compileStatement("INSERT INTO $TABLE (topic, payload) VALUES (?, ?)")
            stmt.bindString(1, topic)
            stmt.bindBlob(2, payload)
            stmt.executeInsert()
            Log.v(TAG, "Persisted event to SQLite: topic=$topic, size=${payload.size}")
        } catch (t: Throwable) {
            Log.e(TAG, "persistEvent failed: ${t.message}", t)
        }
    }

    /**
     * Replays persisted events in arrival order. Rows the bridge accepted are deleted in one
     * transaction; the first row it did not accept stays, with every row after it.
     */
    @JvmStatic
    fun flushPersisted(ctx: Context) {
        eventLock.withLock {
            try {
                val database = db(ctx)
                database.beginTransaction()
                try {
                    val cursor = database.rawQuery("SELECT id, topic, payload FROM $TABLE ORDER BY id ASC", null)
                    val delivered = mutableListOf<Long>()

                    while (cursor.moveToNext()) {
                        val id = cursor.getLong(0)
                        val topic = cursor.getString(1)
                        val payload = cursor.getBlob(2)

                        if (!bridgeReady) {
                            Log.w(TAG, "Bridge not ready during flush, leaving event: topic=$topic")
                            break
                        }
                        if (postToBridgeBinary(topic, payload, persistIfUnavailable = false)) {
                            delivered.add(id)
                        } else {
                            Log.w(TAG, "Delivery failed during flush, leaving this event and the rest: topic=$topic")
                            break
                        }
                    }
                    cursor.close()

                    if (delivered.isNotEmpty()) {
                        database.execSQL("DELETE FROM $TABLE WHERE id IN (${delivered.joinToString(",")})")
                    }

                    database.setTransactionSuccessful()
                    if (delivered.isNotEmpty()) {
                        Log.i(TAG, "Flushed ${delivered.size} persisted BLE events from SQLite")
                    }
                } finally {
                    database.endTransaction()
                }
            } catch (t: Throwable) {
                Log.e(TAG, "flushPersisted failed: ${t.message}", t)
            }
        }
    }

    /** Test-only: forget a previous `markBridgeReady`, so a test can prove the
     *  not-ready path after another test proved the ready path. */
    @androidx.annotation.VisibleForTesting
    @JvmStatic
    fun testResetBridgeReady() {
        bridgeReady = false
    }

    @androidx.annotation.VisibleForTesting
    @JvmStatic
    fun testPersistDirect(ctx: Context, envelopeBytes: ByteArray) {
        persistEvent(ctx, "ble.envelope.bin", envelopeBytes)
    }

    @androidx.annotation.VisibleForTesting
    @JvmStatic
    fun getPendingCount(ctx: Context): Int {
        return eventLock.withLock {
            try {
                val database = db(ctx)
                val cursor = database.rawQuery("SELECT COUNT(*) FROM $TABLE", null)
                var count = 0
                if (cursor.moveToFirst()) count = cursor.getInt(0)
                cursor.close()
                count
            } catch (t: Throwable) {
                Log.w(TAG, "getPendingCount failed: ${t.message}")
                0
            }
        }
    }

    @androidx.annotation.VisibleForTesting
    @JvmStatic
    fun clearAll(ctx: Context) {
        eventLock.withLock {
            try {
                val database = db(ctx)
                database.execSQL("DELETE FROM $TABLE")
                Log.i(TAG, "Cleared all persisted BLE events")
            } catch (t: Throwable) {
                Log.w(TAG, "clearAll failed: ${t.message}")
            }
        }
    }
}
