package com.umoja.secure.crypto

/**
 * Pure send-path authorization predicate.
 *
 * Per ADR-HARDENING-001 §4 and TASK-P1-038: outbound sends are gated on
 * the accepted authorization matrix's `permitted_contacts`. The matrix is
 * machine-verified at [MatrixStore.accept] time; the server-issued
 * `GET /me/contacts` response is a projection and is NEVER the trust
 * source (P1-026 §5 ruling; [MatrixStore] class KDoc).
 *
 * **Fail-closed.** A null matrix (never enrolled, or fetch failed before
 * any accept) and an empty `permitted_contacts` both reject all sends.
 * There is no "matrix not loaded yet -> allow" branch. An unloaded matrix
 * is not a policy to send under; it is a state where authorization is
 * unknown.
 *
 * Extracted from [MessagingService.sendMessage] so the predicate is
 * JVM-testable without an `android.content.Context` (which
 * `MessagingService` and its `SecureStorage` /
 * `PersistentSignalProtocolStore` dependencies require). The
 * registry-mandated cases live in `SendGateTest`.
 *
 * Lives in `crypto/` because its input is [MatrixStore]'s output; the
 * sole production consumer is `MessagingService`.
 */
object SendGate {

    /**
     * True iff [peerDeviceId] appears in [permittedContacts].
     *
     * @param permittedContacts the accepted matrix's `permitted_contacts`
     *   list, or null when no matrix has been stored on this device.
     *   Mirrors [MatrixStore.permittedContacts]'s return shape exactly.
     * @param peerDeviceId the outbound envelope's target device.
     */
    fun authorized(permittedContacts: List<String>?, peerDeviceId: String): Boolean =
        permittedContacts != null && peerDeviceId in permittedContacts
}
