package com.dsm.wallet.bridge

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Log

data class BleOutboxItem(
    val id: Long,
    val address: String,
    val payload: ByteArray,
    val attempts: Int
)

/**
 * Persistent outbox for BLE write operations.
 * Ensures transactions survive process death.
 * Uses strict ordering (id) instead of wall-clock timestamps.
 */
class BleOutboxRepository(context: Context) : SQLiteOpenHelper(context, "ble_outbox.db", null, 1) {
    companion object {
        private const val TAG = "BleOutboxRepo"
        private const val TABLE = "outbox"
        private const val COL_ID = "id"
        private const val COL_ADDRESS = "address"
        private const val COL_PAYLOAD = "payload"
        private const val COL_ATTEMPTS = "attempts"
    }

    override fun onCreate(db: SQLiteDatabase) {
        // No timestamps. ID provides logical ordering.
        db.execSQL("""
            CREATE TABLE $TABLE (
                $COL_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COL_ADDRESS TEXT NOT NULL,
                $COL_PAYLOAD BLOB NOT NULL,
                $COL_ATTEMPTS INTEGER DEFAULT 0
            )
        """)
        db.execSQL("CREATE INDEX idx_outbox_id ON $TABLE($COL_ID)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE")
        onCreate(db)
    }

    fun enqueue(address: String, payload: ByteArray): Long {
        return try {
            val db = writableDatabase
            val stmt = db.compileStatement("INSERT INTO $TABLE ($COL_ADDRESS, $COL_PAYLOAD) VALUES (?, ?)")
            stmt.bindString(1, address)
            stmt.bindBlob(2, payload)
            val id = stmt.executeInsert()
            Log.d(TAG, "Enqueued item $id for $address")
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
            db.rawQuery("SELECT $COL_ID, $COL_ADDRESS, $COL_PAYLOAD, $COL_ATTEMPTS FROM $TABLE ORDER BY $COL_ID ASC", null).use { cursor ->
                while(cursor.moveToNext()) {
                    list.add(BleOutboxItem(
                        cursor.getLong(0),
                        cursor.getString(1),
                        cursor.getBlob(2),
                        cursor.getInt(3)
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
            db.rawQuery("SELECT $COL_ID, $COL_ADDRESS, $COL_PAYLOAD, $COL_ATTEMPTS FROM $TABLE WHERE $COL_ADDRESS = ? ORDER BY $COL_ID DESC LIMIT 1", arrayOf(address)).use { cursor ->
                if (cursor.moveToFirst()) {
                    return BleOutboxItem(
                        cursor.getLong(0),
                        cursor.getString(1),
                        cursor.getBlob(2),
                        cursor.getInt(3)
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get last item for $address", e)
        }
        return null
    }
}
