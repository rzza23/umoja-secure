package com.umoja.secure.storage.local

enum class MessageDirection { IN, OUT }

enum class MessageStatus { QUEUED, SENT, DELIVERED, RECEIVED, FAILED }

data class Message(
    val id: String,
    val envelopeId: String?,
    val peerDeviceId: String,
    val direction: MessageDirection,
    val plaintext: String,
    val createdAt: Long,
    val status: MessageStatus,
)

data class Peer(
    val deviceId: String,
    val label: String,
    val verificationLevel: String,
    val lastSeenAt: Long,
)

data class ConversationSummary(
    val peerDeviceId: String,
    val peerLabel: String,
    val lastMessagePreview: String,
    val lastMessageAt: Long,
    val lastDirection: MessageDirection,
)
