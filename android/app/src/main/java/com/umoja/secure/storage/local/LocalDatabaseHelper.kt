package com.umoja.secure.storage.local

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Local message cache.
 *
 * Framework SQLiteOpenHelper (no new dependency). The plaintext column is
 * AES-GCM encrypted by MessageCrypto before insert. Metadata columns
 * (peer IDs, timestamps, statuses) are stored in plaintext — this is a
 * documented Phase 1 limitation. If the DB file is extracted without the
 * Keystore key, the messages are unreadable but the metadata leaks activity.
 *
 * Migration to SQLCipher is a drop-in replacement of this helper; the schema
 * and repository API stay unchanged.
 */
class LocalDatabaseHelper private constructor(context: Context) :
    SQLiteOpenHelper(context.applicationContext, DB_NAME, null, DB_VERSION) {

    companion object {
        const val DB_NAME = "umoja_local.db"
        const val DB_VERSION = 1

        const val TABLE_MESSAGES = "messages"
        const val TABLE_PEERS = "peers"

        @Volatile
        private var INSTANCE: LocalDatabaseHelper? = null

        /**
         * Process-wide singleton accessor. SQLiteOpenHelper owns one
         * SQLiteDatabase handle; constructing a fresh helper per caller
         * opens a fresh handle, and if no one closes it the
         * SQLiteConnectionPool logs "was leaked!" at finalization. That
         * was Session Q's observation, reproduced Session U-1: two
         * leaked connections after a ChatScreen visit + GC.
         *
         * This accessor is the fix. All MessageStore instances share
         * the one helper, one handle, one connection pool. MessageStore
         * still constructs per-call (its `helper` field reads this
         * singleton), so call sites are unchanged.
         *
         * Double-checked locking matches the standard Android pattern
         * for this (e.g. the SQLiteOpenHelper in architecture samples).
         * `@Volatile` ensures the reads-after-publish see a fully
         * constructed instance. Synchronized block only on the
         * cold-start path.
         */
        fun get(context: Context): LocalDatabaseHelper =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: LocalDatabaseHelper(context.applicationContext)
                    .also { INSTANCE = it }
            }
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE $TABLE_MESSAGES (
              id TEXT PRIMARY KEY NOT NULL,
              envelope_id TEXT,
              peer_device_id TEXT NOT NULL,
              direction TEXT NOT NULL CHECK (direction IN ('IN','OUT')),
              plaintext BLOB NOT NULL,
              created_at INTEGER NOT NULL,
              status TEXT NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            "CREATE INDEX idx_messages_peer_time ON $TABLE_MESSAGES " +
                "(peer_device_id, created_at DESC)"
        )
        db.execSQL(
            "CREATE UNIQUE INDEX idx_messages_envelope ON $TABLE_MESSAGES " +
                "(envelope_id) WHERE envelope_id IS NOT NULL"
        )

        db.execSQL(
            """
            CREATE TABLE $TABLE_PEERS (
              device_id TEXT PRIMARY KEY NOT NULL,
              label TEXT NOT NULL,
              verification_level TEXT NOT NULL,
              last_seen_at INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Phase 1: no migrations yet. Future versions add ALTER TABLE steps
        // guarded by oldVersion.
    }
}
