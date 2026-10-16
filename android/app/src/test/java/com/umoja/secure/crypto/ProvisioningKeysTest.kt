package com.umoja.secure.crypto

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * Cross-checks the [ProvisioningKeys] consts against the vector file.
 *
 * The provisioning const is the trust anchor for every matrix
 * verification. If it drifts from the key that actually signed the
 * vectors, every production verification silently fails. This test
 * catches that drift at commit time.
 */
class ProvisioningKeysTest {

    private fun repoRoot(): File {
        var dir = File(System.getProperty("user.dir")!!)
        for (i in 0 until 10) {
            if (File(dir, "UMOJA-SECURE-BUILD-MASTER.md").exists()) return dir
            dir = dir.parentFile ?: break
        }
        error("could not find repo root from ${System.getProperty("user.dir")}")
    }

    @Test
    fun `current provisioning pubkey matches the vector file`() {
        val path = File(repoRoot(), "docs/reference/canonical-matrix-test-vectors.json")
        val doc = JSONObject(path.readText())
        val expected = doc.getJSONArray("vectors")
            .getJSONObject(0)
            .getString("expected_provisioning_public_key_base64url")
        assertEquals(
            "ProvisioningKeys.CURRENT_PROVISIONING_PUBKEY_B64U has drifted from the vector file",
            expected,
            ProvisioningKeys.CURRENT_PROVISIONING_PUBKEY_B64U,
        )
    }

    @Test
    fun `current provisioning pubkey decodes to 32 bytes`() {
        val raw = Base64.getUrlDecoder().decode(ProvisioningKeys.CURRENT_PROVISIONING_PUBKEY_B64U)
        assertEquals(32, raw.size)
    }

    @Test
    fun `recovery pubkey decodes to 32 bytes`() {
        val raw = Base64.getUrlDecoder().decode(ProvisioningKeys.RECOVERY_PUBKEY_B64U)
        assertEquals(32, raw.size)
    }
}
