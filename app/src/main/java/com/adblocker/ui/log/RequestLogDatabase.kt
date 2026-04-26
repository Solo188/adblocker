package com.adblocker.ui.log

import android.content.Context
import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

/**
 * ui.log — RequestLogDatabase (Room)
 *
 * Persists intercepted request entries across app restarts.
 * The UI observes [RequestLogDao.observeRecent] as a Flow so it auto-updates.
 *
 * Keep the log trimmed to MAX_ROWS to avoid unbounded disk growth.
 */
@Entity(tableName = "request_log")
data class RequestLogEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "timestamp_ms") val timestampMs: Long,
    @ColumnInfo(name = "method") val method: String,
    @ColumnInfo(name = "host") val host: String,
    @ColumnInfo(name = "url") val url: String,
    @ColumnInfo(name = "blocked") val blocked: Boolean,
    @ColumnInfo(name = "response_code") val responseCode: Int,
    @ColumnInfo(name = "duration_ms") val durationMs: Long
)

@Dao
interface RequestLogDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: RequestLogEntity)

    @Query("SELECT * FROM request_log ORDER BY timestamp_ms DESC LIMIT :limit")
    fun observeRecent(limit: Int = 500): Flow<List<RequestLogEntity>>

    @Query("SELECT COUNT(*) FROM request_log WHERE blocked = 1")
    fun observeBlockedCount(): Flow<Int>

    @Query("DELETE FROM request_log")
    suspend fun clearAll()

    /** Trim old entries so the table doesn't grow indefinitely. */
    @Query("DELETE FROM request_log WHERE id NOT IN (SELECT id FROM request_log ORDER BY timestamp_ms DESC LIMIT :keepCount)")
    suspend fun trim(keepCount: Int = 5000)
}

@Database(entities = [RequestLogEntity::class], version = 1, exportSchema = false)
abstract class RequestLogDatabase : RoomDatabase() {
    abstract fun dao(): RequestLogDao

    companion object {
        @Volatile private var INSTANCE: RequestLogDatabase? = null

        fun getInstance(context: Context): RequestLogDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    RequestLogDatabase::class.java,
                    "request_log.db"
                ).build().also { INSTANCE = it }
            }
    }
}
