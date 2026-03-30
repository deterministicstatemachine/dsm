package com.dsm.wallet.bridge

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Log

/** Priority levels for outbox items. Lower value = higher priority. */
object BleOutboxPriority {
    const val PAIRING_CONFIRM = 0
    const val BILATERAL_COMMIT = 1
    const val BILATERAL_PREPARE = 2
    const val RECONCILE = 3
}

data class BleOutboxItem(
    val id: Long,
    val address: String,
    val payload: ByteArray,
    val attempts: Int,
    val priority: Int = BleOutboxPriority.BILATERAL_PREPARE,
)

/**
 * Persistent outbox for BLE write operations.
 * Ensures transactions survive process death.
 * Uses strict ordering (id) instead of wall-clock timestamps.
 */
class BleOutboxRepository(context: Context) : SQLiteOpenHelper(context, "ble_outbox.db", null, 2) {
    companion object {
        private const val TAG = "BleOutboxRepo"
        private const val TABLE = "outbox"
        private const val COL_ID = "id"
        private const val COL_ADDRESS = "address"
        private const val COL_PAYLOAD = "payload"
        private const val COL_ATTEMPTS = "attempts"
        private const val COL_PRIORITY = "priority"
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE $TABLE (
                $COL_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COL_ADDRESS TEXT NOT NULL,
                $COL_PAYLOAD BLOB NOT NULL,
                $COL_ATTEMPTS INTEGER DEFAULT 0,
                $COL_PRIORITY INTEGER NOT NULL DEFAULT ${BleOutboxPriority.BILATERAL_PREPARE}
            )
        """)
        db.execSQL("CREATE INDEX idx_outbox_priority ON $TABLE($COL_PRIORITY, $COL_ID)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            db.execSQL("ALTER TABLE $TABLE ADD COLUMN $COL_PRIORITY INTEGER NOT NULL DEFAULT ${BleOutboxPriority.BILATERAL_PREPARE}")
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_outbox_priority ON $TABLE($COL_PRIORITY, $COL_ID)")
        }
    }

    fun enqueue(address: String, payload: ByteArray, priority: Int = BleOutboxPriority.BILATERAL_PREPARE): Long {
        return try {
            val db = writableDatabase
            val stmt = db.compileStatement("INSERT INTO $TABLE ($COL_ADDRESS, $COL_PAYLOAD, $COL_PRIORITY) VALUES (?, ?, ?)")
            stmt.bindString(1, address)
            stmt.bindBlob(2, payload)
            stmt.bindLong(3, priority.toLong())
            val id = stmt.executeInsert()
            Log.d(TAG, "Enqueued item $id for $address (priority=$priority)")
            id
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enqueue", e)
            -1L
        }
    }

    fun getPending(): List<BleOutboxItem> {
        val list = mutableListOf<BleOutboxItem>()
        try {
            val db = readableDatabase
            db.rawQuery(
                "SELECT $COL_ID, $COL_ADDRESS, $COL_PAYLOAD, $COL_ATTEMPTS, $COL_PRIORITY FROM $TABLE ORDER BY $COL_PRIORITY ASC, $COL_ID ASC",
                null
            ).use { cursor ->
                while(cursor.moveToNext()) {
                    list.add(BleOutboxItem(
                        cursor.getLong(0),
                        cursor.getString(1),
                        cursor.getBlob(2),
                        cursor.getInt(3),
                        cursor.getInt(4),
                    ))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get pending items", e)
        }
        return list
    }

    fun delete(id: Long) {
        try {
            writableDatabase.execSQL("DELETE FROM $TABLE WHERE $COL_ID = ?", arrayOf(id))
            Log.d(TAG, "Deleted item $id")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete item $id", e)
        }
    }
    
    fun incrementAttempts(id: Long) {
        try {
            writableDatabase.execSQL("UPDATE $TABLE SET $COL_ATTEMPTS = $COL_ATTEMPTS + 1 WHERE $COL_ID = ?", arrayOf(id))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to increment attempts for item $id", e)
        }
    }

    fun resetAttempts(id: Long) {
        try {
            writableDatabase.execSQL("UPDATE $TABLE SET $COL_ATTEMPTS = 0 WHERE $COL_ID = ?", arrayOf(id))
            Log.d(TAG, "Reset attempts for item $id")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to reset attempts for item $id", e)
        }
    }

    fun getLastForAddress(address: String): BleOutboxItem? {
        try {
            val db = readableDatabase
            db.rawQuery(
                "SELECT $COL_ID, $COL_ADDRESS, $COL_PAYLOAD, $COL_ATTEMPTS, $COL_PRIORITY FROM $TABLE WHERE $COL_ADDRESS = ? ORDER BY $COL_PRIORITY ASC, $COL_ID DESC LIMIT 1",
                arrayOf(address)
            ).use { cursor ->
                if (cursor.moveToFirst()) {
                    return BleOutboxItem(
                        cursor.getLong(0),
                        cursor.getString(1),
                        cursor.getBlob(2),
                        cursor.getInt(3),
                        cursor.getInt(4),
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get last item for $address", e)
        }
        return null
    }
}
