package com.umoja.secure.crypto

import java.time.Instant

/**
 * Builds the authorization-matrix wrapper from a scanned provisioning
 * bundle, admin-entered clearance, admin-selected contacts, and the
 * admin-entered version.
 *
 * Does NOT sign. Signing is TASK-P1-033 (offline provisioning key).
 * The returned SignedMatrix is the wrapper that the offline signer will
 * JCS-canonicalize, SHA-256-digest, and Ed25519-sign.
 *
 * The builder is where TEST-PROVSCHEMA-001 is enforceable. The schema
 * layer cannot detect a swap between pub_device_auth_key and
 * pub_messaging_identity_key — both are 32 bytes of base64url,
 * indistinguishable by inspection. This object preserves field identity
 * from ProvisioningBundle through to the wire map; MatrixBuilderTest
 * proves it.
 *
 * `permitted_contacts` is sorted before insertion. The ADR says array
 * order is significant; for what is semantically a set of device IDs,
 * sorting gives deterministic bytes regardless of the admin's pick
 * order.
 *
 * Task: TASK-P1-025
 * ADR:  §4, §6 step 5
 */
object MatrixBuilder {
    fun build(
        bundle: ProvisioningBundle,
        clearance: String,
        permittedContacts: List<String>,
        version: Int,
        issuedAt: String = Instant.now().toString(),
    ): SignedMatrix {
        val wrapper = linkedMapOf<String, Any?>(
            "domain" to SignedMatrix.DOMAIN,
            "matrix" to linkedMapOf<String, Any?>(
                "version" to version,
                "device_id" to bundle.deviceId,
                "pub_device_auth_key" to bundle.pubDeviceAuthKey,
                "pub_messaging_identity_key" to bundle.pubMessagingIdentityKey,
                "pub_wipe_confirmation_key" to bundle.pubWipeConfirmationKey,
                "clearance" to clearance,
                "permitted_contacts" to permittedContacts.sorted(),
                "issued_at" to issuedAt,
            ),
        )
        // Route through the wrapper validator so every schema rule is
        // applied at build time — defense in depth against a builder
        // that constructs a malformed matrix by accident.
        return SignedMatrix.fromJsonMap(wrapper)
    }
}
