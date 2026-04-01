// path: app/src/main/java/com/dsm/wallet/bridge/BleEventRelay.kt
// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import android.util.Log
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.content.Context
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

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

    private fun postToBridgeBinary(topic: String, payload: ByteArray) {
        if (!bridgeReady) {
            Log.d(TAG, "Bridge not ready, persisting event: topic=$topic")
            eventLock.withLock {
                persistEventNoContext(topic, payload)
            }
            return
        }
        
        try {
            val clazz = Class.forName("com.dsm.wallet.bridge.SinglePathWebViewBridge")
            val method = clazz.getDeclaredMethod("postBinary", String::class.java, ByteArray::class.java)
            method.invoke(null, topic, payload)
            Log.v(TAG, "Event delivered to bridge: topic=$topic")
        } catch (t: Throwable) {
            Log.w(TAG, "WebView bridge unavailable: ${t.message} — persisting: topic=$topic")
            eventLock.withLock {
                persistEventNoContext(topic, payload)
            }
        }
    }

    @Suppress("PrivateApi", "DiscouragedPrivateApi")
    private fun appContextOrNull(): Context? {
        return try {
            val app = Class.forName("android.app.AppGlobals").getMethod("getInitialApplication").invoke(null) as? Context
            if (app != null) app else try {
                val atField = Class.forName("android.app.ActivityThread").getDeclaredField("sCurrentActivityThread").apply { isAccessible = true }
                val at = atField.get(null) ?: return null
                at.javaClass.getDeclaredMethod("getApplication").invoke(at) as? Context
            } catch (_: Throwable) { null }
        } catch (_: Throwable) { null }
    }

    private fun persistEventNoContext(topic: String, payload: ByteArray) {
        val ctx = appContextOrNull() ?: run {
            Log.w(TAG, "No app context for persistEvent: topic=$topic")
            return
        }
        persistEvent(ctx, topic, payload)
    }

    private fun persistEvent(ctx: Context, topic: String, payload: ByteArray) {
        try {
            val database = db(ctx)
            // Enforce cap (200 rows max)
            val countCursor = database.rawQuery("SELECT COUNT(*) FROM $TABLE", null)
            var count = 0
            if (countCursor.moveToFirst()) count = countCursor.getInt(0)
            countCursor.close()
            
            if (count >= 200) {
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

    @JvmStatic
    fun flushPersisted(ctx: Context) {
        eventLock.withLock {
            try {
                val database = db(ctx)
                database.beginTransaction()
                try {
                    val cursor = database.rawQuery("SELECT id, topic, payload FROM $TABLE ORDER BY id ASC", null)
                    val ids = mutableListOf<Long>()
                    var flushed = 0
                    
                    while (cursor.moveToNext()) {
                        val id = cursor.getLong(0)
                        val topic = cursor.getString(1)
                        val payload = cursor.getBlob(2)
                        
                        // Bridge should be ready by now, but double-check
                        if (bridgeReady) {
                            postToBridgeBinary(topic, payload)
                            ids.add(id)
                            flushed++
                        } else {
                            Log.w(TAG, "Bridge not ready during flush, leaving event: topic=$topic")
                            break
                        }
                    }
                    cursor.close()
                    
                    if (ids.isNotEmpty()) {
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
                Log.e(TAG, "flushPersisted failed: ${t.message}", t)
            }
        }
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