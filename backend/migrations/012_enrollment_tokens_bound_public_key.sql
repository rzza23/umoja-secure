-- Migration 012: Add bound_public_key to enrollment_tokens.
--
-- Per ADR-PROVISIONING-001 §2 Q2, enrollment tokens are bound at
-- issuance to the enrolling device's public auth key. Consumption
-- matches on the bound key, so an intercepted token presented with a
-- different key is rejected and not marked consumed.
--
-- Three-step DDL is atomic: src/db/migrator.ts wraps each file in
-- BEGIN/COMMIT.
--
-- Sentinel: 32 zero bytes. Considered-and-accepted trade-off — the
-- all-zero value is also a well-formed base64url string
-- ("AAAA...A", 43 chars), so an admin could in principle deliberately
-- issue a token bound to that value via the new route. Harmless in
-- practice: no real Keystore Ed25519 key is ever all-zeros, so such a
-- token remains unusable. The NOT NULL invariant is worth more than
-- the theoretical collision — an admin code path that accidentally
-- omits the field cannot slip through as NULL.
--
-- Consequence: pre-existing unconsumed tokens become unusable after
-- this migration. This is the correct security behaviour (tokens
-- issued before binding existed cannot be trusted as bound).

ALTER TABLE enrollment_tokens
  ADD COLUMN bound_public_key BYTEA;

UPDATE enrollment_tokens
   SET bound_public_key = decode(repeat('00', 32), 'hex')
 WHERE bound_public_key IS NULL;

ALTER TABLE enrollment_tokens
  ALTER COLUMN bound_public_key SET NOT NULL;

ALTER TABLE enrollment_tokens
  ADD CONSTRAINT enrollment_tokens_bound_public_key_len
    CHECK (octet_length(bound_public_key) = 32);
