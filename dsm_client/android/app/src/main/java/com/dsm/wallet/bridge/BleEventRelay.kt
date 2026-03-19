// path: app/src/main/java/com/dsm/wallet/bridge/BleEventRelay.kt
// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import android.util.Log
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.content.Context

/**
 * Protobuf-only BLE event relay.
 * Sends raw Envelope bytes to the JS bridge using MessagePort ArrayBuffer (no JSON/base32).
 */
object BleEventRelay {
    private const val TAG = "BleEventRelay"
    private const val DB_NAME = "ble_events.db"
    private const val DB_VERSION = 2
    private const val TABLE = "pending_ble"
    
    // Track if WebView bridge is ready (set by MainActivity.signalBridgeReady)
    @Volatile private var bridgeReady = false
    // Guard to prevent re-persisting events during flush
    @Volatile private var flushing = false

    private class BleDbHelper(ctx: Context) : SQLiteOpenHelper(ctx, DB_NAME, null, DB_VERSION) {
        override fun onCreate(db: SQLiteDatabase) {
            // No wall-clock markers: row order determined by rowid (AUTOINCREMENT)
            db.execSQL("CREATE TABLE IF NOT EXISTS $TABLE (id INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT NOT NULL, payload BLOB NOT NULL)")
            // Index on id for ORDER BY and pruning queries (rowid is implicitly indexed, but explicit doesn't hurt)
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_pending_ble_id ON $TABLE(id)")
        }
        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            if (oldVersion != newVersion) {
                db.execSQL("DROP TABLE IF EXISTS $TABLE")
                onCreate(db)
            }
        }
    }
    // Cache the helper to avoid opening a new connection on every call
    private var dbHelper: BleDbHelper? = null
    @Synchronized
    private fun db(ctx: Context): SQLiteDatabase {
        if (dbHelper == null) {
            dbHelper = BleDbHelper(ctx.applicationContext)
        }
        return dbHelper!!.writableDatabase
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

        // Ensure Rust BLE coordinator is initialized before flushing events.
        // Events dispatched to an uninitialized coordinator would be silently dropped.
        try {
            if (!com.dsm.wallet.bridge.UnifiedNativeApi.isBleCoordinatorReady()) {
                Log.i(TAG, "Rust BLE coordinator not ready — forcing init")
                com.dsm.wallet.bridge.UnifiedNativeApi.forceBleCoordinatorInit()
            }
        } catch (t: Throwable) {
            Log.w(TAG, "BLE coordinator readiness check failed (non-fatal): ${t.message}")
        }

        if (ctx != null) {
            flushPersisted(ctx)
        }
    }

    /**
     * Reflective call to avoid a hard dependency on the bridge.
     * Expected static method:
     *   SinglePathWebViewBridge.postBinary(topic: String, payload: ByteArray)
     */
    private fun postToBridgeBinary(topic: String, payload: ByteArray) {
        if (!bridgeReady) {
            if (!flushing) {
                Log.d(TAG, "Bridge not ready, persisting event: topic=$topic")
                persistEvent(topic, payload)
            }
            return
        }
        try {
            val clazz = Class.forName("com.dsm.wallet.bridge.SinglePathWebViewBridge")
            val method = clazz.getDeclaredMethod("postBinary", String::class.java, ByteArray::class.java)
            method.invoke(null, topic, payload)
        } catch (t: Throwable) {
            // During flush, don't re-persist — events remain in SQLite for next flush
            if (!flushing) {
                Log.w(TAG, "WebView bridge unavailable/incompatible: ${t.message} — persisting for later flush")
                persistEvent(topic, payload)
            } else {
                Log.w(TAG, "WebView bridge unavailable during flush: ${t.message} — will retry on next flush")
            }
        }
    }
    @Suppress("PrivateApi", "DiscouragedPrivateApi")
    private fun appContextOrNull(): Context? {
        // Try AppGlobals first (works in Robolectric and some process states)
        try {
            val app = Class.forName("android.app.AppGlobals").getMethod("getInitialApplication").invoke(null) as? Context
            if (app != null) return app
        } catch (_: Throwable) { /* ignore */ }
        // Alternate path: ActivityThread
        return try {
            val atField = Class.forName("android.app.ActivityThread").getDeclaredField("sCurrentActivityThread").apply { isAccessible = true }
            val at = atField.get(null) ?: return null
            val method = at.javaClass.getDeclaredMethod("getApplication")
            method.invoke(at) as? Context
        } catch (_: Throwable) {
            null
        }
    }

    private fun persistEvent(topic: String, payload: ByteArray) {
        val ctx = appContextOrNull() ?: return
        persistEvent(ctx, topic, payload)
    }

    private fun persistEvent(ctx: Context, topic: String, payload: ByteArray) {
        try {
            val database = db(ctx)
            // Enforce a cap (e.g., 200 rows) to avoid unbounded growth
            val countCursor = database.rawQuery("SELECT COUNT(*) FROM $TABLE", null)
            var count = 0
            if (countCursor.moveToFirst()) count = countCursor.getInt(0)
            countCursor.close()
            if (count >= 200) {
                database.execSQL("DELETE FROM $TABLE WHERE id IN (SELECT id FROM $TABLE ORDER BY id ASC LIMIT 1)")
            }
            val stmt = database.compileStatement("INSERT INTO $TABLE (topic, payload) VALUES (?, ?)")
            stmt.bindString(1, topic)
            stmt.bindBlob(2, payload)
            stmt.executeInsert()
        } catch (t: Throwable) {
            Log.w(TAG, "persistEvent failed: ${t.message}")
        }
    }

    /** Test-only hook to persist an event without requiring the WebView bridge to be missing. */
    @androidx.annotation.VisibleForTesting
    @JvmStatic
    fun testPersistDirect(ctx: Context, envelopeBytes: ByteArray) {
        persistEvent(ctx, "ble.envelope.bin", envelopeBytes)
    }

    @JvmStatic
    fun flushPersisted(ctx: Context) {
        if (flushing) return // Prevent re-entrant flush
        flushing = true
        try {
            val database = db(ctx)
            database.beginTransaction()
            try {
                val cursor = database.rawQuery("SELECT id, topic, payload FROM $TABLE ORDER BY id ASC", null)
                var flushed = 0
                val ids = mutableListOf<Long>()
                while (cursor.moveToNext()) {
                    val id = cursor.getLong(0)
                    val topic = cursor.getString(1)
                    val payload = cursor.getBlob(2)
                    postToBridgeBinary(topic, payload)
                    ids.add(id)
                    flushed++
                }
                cursor.close()
                if (flushed > 0) {
                    val idList = ids.joinToString(",")
                    database.execSQL("DELETE FROM $TABLE WHERE id IN ($idList)")
                }
                database.setTransactionSuccessful()
                if (flushed > 0) {
                    Log.i(TAG, "Flushed $flushed persisted BLE events from SQLite")
                }
            } finally {
                database.endTransaction()
            }
        } catch (t: Throwable) {
            Log.w(TAG, "flushPersisted failed: ${t.message}")
        } finally {
            flushing = false
        }
    }

    /** For test visibility. Returns count of pending persisted events. */
    @androidx.annotation.VisibleForTesting
    @JvmStatic
    fun getPendingCount(ctx: Context): Int {
        return try {
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

    /** For test cleanup. Deletes all persisted events. */
    @androidx.annotation.VisibleForTesting
    @JvmStatic
    fun clearAll(ctx: Context) {
        try {
            val database = db(ctx)
            database.execSQL("DELETE FROM $TABLE")
        } catch (t: Throwable) {
            Log.w(TAG, "clearAll failed: ${t.message}")
        }
    }
}