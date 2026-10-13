package com.umoja.secure.storage.local

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import java.util.UUID

/**
 * Repository for messages and peers.
 *
 * All methods are blocking. Callers must wrap in withContext(Dispatchers.IO)
 * before invoking from coroutines on the main thread.
 */
class MessageStore(context: Context) {

    private val helper = LocalDatabaseHelper(context)
    private val crypto = MessageCrypto()

    // ============================================================
    // Messages
    // ============================================================

    fun insertOutgoing(
        peerDeviceId: String,
        plaintext: String,
        envelopeId: String?,
        status: MessageStatus = MessageStatus.SENT,
    ): Message {
        val id = UUID.randomUUID().toString()
        val now = System.currentTimeMillis()
        val encrypted = crypto.encrypt(plaintext)

        val values = ContentValues().apply {
            put("id", id)
            put("envelope_id", envelopeId)
            put("peer_device_id", peerDeviceId)
            put("direction", MessageDirection.OUT.name)
            put("plaintext", encrypted)
            put("created_at", now)
            put("status", status.name)
        }
        helper.writableDatabase.insertWithOnConflict(
            LocalDatabaseHelper.TABLE_MESSAGES, null, values,
            android.database.sqlite.SQLiteDatabase.CONFLICT_IGNORE,
        )

        touchPeer(peerDeviceId)
        return Message(id, envelopeId, peerDeviceId, MessageDirection.OUT, plaintext, now, status)
    }

    fun insertIncoming(
        peerDeviceId: String,
        plaintext: String,
        envelopeId: String?,
    ): Message {
        val id = UUID.randomUUID().toString()
        val now = System.currentTimeMillis()
        val encrypted = crypto.encrypt(plaintext)

        val values = ContentValues().apply {
            put("id", id)
            put("envelope_id", envelopeId)
            put("peer_device_id", peerDeviceId)
            put("direction", MessageDirection.IN.name)
            put("plaintext", encrypted)
            put("created_at", now)
            put("status", MessageStatus.RECEIVED.name)
        }
        helper.writableDatabase.insertWithOnConflict(
            LocalDatabaseHelper.TABLE_MESSAGES, null, values,
            android.database.sqlite.SQLiteDatabase.CONFLICT_IGNORE,
        )

        touchPeer(peerDeviceId)
        return Message(id, envelopeId, peerDeviceId, MessageDirection.IN, plaintext, now, MessageStatus.RECEIVED)
    }

    fun hasEnvelope(envelopeId: String): Boolean {
        val cursor = helper.readableDatabase.query(
            LocalDatabaseHelper.TABLE_MESSAGES,
            arrayOf("id"),
            "envelope_id = ?",
            arrayOf(envelopeId),
            null, null, null, "1",
        )
        cursor.use { return it.count > 0 }
    }

    fun markStatus(envelopeId: String, status: MessageStatus) {
        val values = ContentValues().apply { put("status", status.name) }
        helper.writableDatabase.update(
            LocalDatabaseHelper.TABLE_MESSAGES,
            values,
            "envelope_id = ?",
            arrayOf(envelopeId),
        )
    }

    fun listMessages(peerDeviceId: String, limit: Int = 500): List<Message> {
        val cursor = helper.readableDatabase.query(
            LocalDatabaseHelper.TABLE_MESSAGES,
            arrayOf("id", "envelope_id", "peer_device_id", "direction",
                "plaintext", "created_at", "status"),
            "peer_device_id = ?",
            arrayOf(peerDeviceId),
            null, null,
            "created_at ASC",
            limit.toString(),
        )
        val out = mutableListOf<Message>()
        cursor.use { c ->
            while (c.moveToNext()) out.add(cursorToMessage(c))
        }
        return out
    }

    fun listConversations(): List<ConversationSummary> {
        // One row per peer: the most recent message and its direction.
        val sql = """
            SELECT m.peer_device_id, m.direction, m.plaintext, m.created_at,
                   COALESCE(p.label, m.peer_device_id) AS label
            FROM ${LocalDatabaseHelper.TABLE_MESSAGES} m
            LEFT JOIN ${LocalDatabaseHelper.TABLE_PEERS} p
              ON p.device_id = m.peer_device_id
            WHERE m.created_at = (
              SELECT MAX(m2.created_at)
              FROM ${LocalDatabaseHelper.TABLE_MESSAGES} m2
              WHERE m2.peer_device_id = m.peer_device_id
            )
            ORDER BY m.created_at DESC
        """.trimIndent()

        val cursor = helper.readableDatabase.rawQuery(sql, null)
        val out = mutableListOf<ConversationSummary>()
        cursor.use { c ->
            while (c.moveToNext()) {
                val peer = c.getString(0)
                val direction = MessageDirection.valueOf(c.getString(1))
                val preview = try {
                    crypto.decrypt(c.getBlob(2))
                } catch (_: Exception) {
                    "[unreadable]"
                }
                val at = c.getLong(3)
                val label = c.getString(4)
                out.add(ConversationSummary(peer, label, preview, at, direction))
            }
        }
        return out
    }

    // ============================================================
    // Peers
    // ============================================================

    fun upsertPeer(deviceId: String, label: String, verificationLevel: String) {
        val values = ContentValues().apply {
            put("device_id", deviceId)
            put("label", label)
            put("verification_level", verificationLevel)
            put("last_seen_at", System.currentTimeMillis())
        }
        helper.writableDatabase.insertWithOnConflict(
            LocalDatabaseHelper.TABLE_PEERS, null, values,
            android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE,
        )
    }

    fun getPeer(deviceId: String): Peer? {
        val cursor = helper.readableDatabase.query(
            LocalDatabaseHelper.TABLE_PEERS,
            arrayOf("device_id", "label", "verification_level", "last_seen_at"),
            "device_id = ?", arrayOf(deviceId),
            null, null, null, "1",
        )
        cursor.use { c ->
            if (!c.moveToNext()) return null
            return Peer(
                deviceId = c.getString(0),
                label = c.getString(1),
                verificationLevel = c.getString(2),
                lastSeenAt = c.getLong(3),
            )
        }
    }

    fun listPeers(): List<Peer> {
        val cursor = helper.readableDatabase.query(
            LocalDatabaseHelper.TABLE_PEERS,
            arrayOf("device_id", "label", "verification_level", "last_seen_at"),
            null, null, null, null,
            "label ASC",
        )
        val out = mutableListOf<Peer>()
        cursor.use { c ->
            while (c.moveToNext()) {
                out.add(
                    Peer(
                        deviceId = c.getString(0),
                        label = c.getString(1),
                        verificationLevel = c.getString(2),
                        lastSeenAt = c.getLong(3),
                    )
                )
            }
        }
        return out
    }

    private fun touchPeer(deviceId: String) {
        val values = ContentValues().apply {
            put("last_seen_at", System.currentTimeMillis())
        }
        val updated = helper.writableDatabase.update(
            LocalDatabaseHelper.TABLE_PEERS, values,
            "device_id = ?", arrayOf(deviceId),
        )
        if (updated == 0) {
            upsertPeer(deviceId, deviceId, "directory")
        }
    }

    private fun cursorToMessage(c: Cursor): Message {
        val encrypted = c.getBlob(4)
        val plaintext = try {
            crypto.decrypt(encrypted)
        } catch (_: Exception) {
            "[unreadable]"
        }
        return Message(
            id = c.getString(0),
            envelopeId = if (c.isNull(1)) null else c.getString(1),
            peerDeviceId = c.getString(2),
            direction = MessageDirection.valueOf(c.getString(3)),
            plaintext = plaintext,
            createdAt = c.getLong(5),
            status = MessageStatus.valueOf(c.getString(6)),
        )
    }

    fun close() {
        helper.close()
    }
}
