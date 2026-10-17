package dev.adfection.scanner.data

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Append-only on-device evidence log.
 *
 * Uses raw SQLite (no Room) because the schema is one table, the query surface is three reads, and
 * this app must stay debuggable on a device with no annotation processor in the build.
 *
 * Threading: all public methods are suspend and hop to [Dispatchers.IO].
 */
class EventStore(context: Context) : SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        INTEGER NOT NULL,
                kind      TEXT    NOT NULL,
                severity  TEXT    NOT NULL,
                category  TEXT,
                subject   TEXT    NOT NULL,
                detail    TEXT    NOT NULL,
                action    TEXT    NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX idx_events_ts ON events(ts DESC)")
        db.execSQL("CREATE INDEX idx_events_subject ON events(subject)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Evidence log is disposable telemetry; a schema bump restarts it rather than migrating.
        db.execSQL("DROP TABLE IF EXISTS events")
        onCreate(db)
    }

    suspend fun append(event: ScanEvent) = withContext(Dispatchers.IO) {
        val args: Array<Any?> = arrayOf(
            event.timestamp,
            event.kind.name,
            event.severity.name,
            event.category?.name,
            event.subject,
            event.detail,
            event.action.name,
        )
        writableDatabase.execSQL(
            "INSERT INTO events (ts, kind, severity, category, subject, detail, action) VALUES (?,?,?,?,?,?,?)",
            args,
        )
    }

    /** Most recent [limit] events, newest first. */
    suspend fun recent(limit: Int = 500): List<ScanEvent> = withContext(Dispatchers.IO) {
        readableDatabase.rawQuery(
            "SELECT id, ts, kind, severity, category, subject, detail, action FROM events ORDER BY ts DESC LIMIT ?",
            arrayOf(limit.toString()),
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        ScanEvent(
                            id = c.getLong(0),
                            timestamp = c.getLong(1),
                            kind = c.getString(2)?.let { raw ->
                                EventKind.entries.firstOrNull { it.name == raw }
                            } ?: EventKind.SCAN_RUN,
                            severity = Severity.parse(c.getString(3)),
                            category = c.getString(4)?.let { raw ->
                                ThreatCategory.entries.firstOrNull { it.name == raw }
                            },
                            subject = c.getString(5),
                            detail = c.getString(6),
                            action = c.getString(7)?.let { raw ->
                                Action.entries.firstOrNull { it.name == raw }
                            } ?: Action.LOGGED,
                        )
                    )
                }
            }
        }
    }

    /** Count of blocked events, for the UI summary. */
    suspend fun blockedCount(): Int = withContext(Dispatchers.IO) {
        readableDatabase.rawQuery("SELECT COUNT(*) FROM events WHERE action = ?", arrayOf(Action.BLOCKED.name)).use { c ->
            if (c.moveToFirst()) c.getInt(0) else 0
        }
    }

    /** Distinct subjects with a blocked/alerted action, newest first, for the "what hit" summary. */
    suspend fun threatSubjects(limit: Int = 50): List<Pair<String, Severity>> = withContext(Dispatchers.IO) {
        readableDatabase.rawQuery(
            """
            SELECT subject, severity FROM events
             WHERE action IN (?, ?)
             GROUP BY subject
             ORDER BY MAX(ts) DESC
             LIMIT ?
            """.trimIndent(),
            arrayOf(Action.BLOCKED.name, Action.ALERTED.name, limit.toString()),
        ).use { c ->
            buildList {
                while (c.moveToNext()) add(c.getString(0) to Severity.parse(c.getString(1)))
            }
        }
    }

    suspend fun clear() = withContext(Dispatchers.IO) {
        writableDatabase.execSQL("DELETE FROM events")
    }

    /** De-duplication guard: was this exact subject already recorded within [withinMs]? */
    suspend fun seenRecently(subject: String, withinMs: Long, now: Long): Boolean = withContext(Dispatchers.IO) {
        readableDatabase.rawQuery(
            "SELECT 1 FROM events WHERE subject = ? AND ts >= ? LIMIT 1",
            arrayOf(subject, (now - withinMs).toString()),
        ).use { it.moveToFirst() }
    }

    override fun close() {
        super.close()
    }

    companion object {
        private const val DB_NAME = "adfection_events.db"
        private const val DB_VERSION = 1
    }
}
