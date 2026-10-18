#!/usr/bin/env bash
#
# bootstrap-enrollment-token.sh — one-command enrollment-token issuance
#
# Replaces the ad-hoc psql procedure that recurred five times between
# Session A and Session R-4 (see handoff.md §5 backlog). Handles three
# scenarios:
#
#   1. FRESH ENROLLMENT — device not yet in DB, token bound to the
#      public_key from the app's enrollment QR.
#
#   2. EXISTING DEVICE — device row exists, token bound to its current
#      public_key. Use for revoke-and-reauth recovery after an admin
#      has reactivated the device.
#
#   3. BROKEN-STATE RECOVERY — device row exists but is a ghost/stale
#      row blocking re-enrollment (23505 devices_key_unique collision).
#      Captures its current public_key, mutates the column to ff..ff
#      (freeing the unique index), marks revoked, issues a token
#      bound to the captured key. This is what worked in Session R-4's
#      recovery.
#
# NOTE ON GHOST VS DELETE. The R-4 recovery worked cleanly with GHOST
# (mutate column + revoke). Full DELETE requires ordered cleanup of 6
# NO ACTION FK dependents (enrollment_tokens used_by/created_by,
# org_matrix_versions asserted_by, identity_change_notices from/to,
# identity_change_acks acking, matrices) and is documented in the
# handoff as a separate "purge device" operation. It is NOT supported
# here — that operation shouldn't share a script with "issue token".
# If you genuinely need to purge (audit requires the row gone), run
# the 8-line transaction from handoff.md §3 (Session R-4) manually.
#
# Prerequisites:
#   - Docker compose running with the postgres container up
#   - Called from the repo root (so `docker compose` finds the compose
#     file)
#   - The --created-by device is an active admin or owner in --org
#
# Exit codes:
#   0  Token issued; printed for copy/paste
#   1  Usage error or validation failure (message names the problem)
#   2  Unexpected DB error (psql prints its own message; set -e aborts)
#
# Task: backlog item filed at Session R-4 close, implemented Session S-1
# Related: ADR-PROVISIONING-001 §3.2

set -euo pipefail

# ---------- args ----------
ORG=""
CREATED_BY=""
DEVICE=""
PUBKEY=""
GHOST=""
ROLE="user"
EXPIRES_IN="1 hour"

usage() {
  cat <<'USAGE_EOF'
Usage: scripts/bootstrap-enrollment-token.sh --org <uuid> --created-by <uuid> [MODE] [OPTIONS]

Issues a fresh enrollment token and prints it for pasting into the
Umoja Secure app's Enrollment screen.

Required:
  --org <uuid>          Organization ID
  --created-by <uuid>   Admin or owner device ID (must be active in --org)

Mode (exactly one required):
  --device <uuid>       Existing device_id; token binds to its public_key
  --pubkey <b64url>     Public key from QR payload (fresh enrollment,
                        43-char base64url no-pad)
  --ghost <uuid>        Recovery: capture ghost's public_key, mutate it
                        to ff..ff, revoke, and issue a token bound to
                        the captured (original) key

Options:
  --role <role>         Token role (default: user)
  --expires-in <dur>    Expiry interval (default: "1 hour"; any valid
                        PostgreSQL interval literal)
  -h, --help            This message

Examples:
  # Fresh enrollment from QR JSON
  ./scripts/bootstrap-enrollment-token.sh \
    --org 11111111-1111-1111-1111-111111111111 \
    --created-by f697b280-91dc-478c-a8eb-58e7f5233751 \
    --pubkey dQC9F5p_RpGiSdVSQqozeQwoASAeC_6N6U8em52kboo

  # Re-issue token for existing device (revoke + reauth recovery)
  ./scripts/bootstrap-enrollment-token.sh \
    --org 11111111-1111-1111-1111-111111111111 \
    --created-by f697b280-91dc-478c-a8eb-58e7f5233751 \
    --device 943fbeeb-6bae-41e7-b5e1-5ebcc534ea54

  # Recover from public_key collision (ghost stale row)
  ./scripts/bootstrap-enrollment-token.sh \
    --org 11111111-1111-1111-1111-111111111111 \
    --created-by f697b280-91dc-478c-a8eb-58e7f5233751 \
    --ghost 943fbeeb-6bae-41e7-b5e1-5ebcc534ea54
USAGE_EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --org)        ORG="$2"; shift 2 ;;
    --created-by) CREATED_BY="$2"; shift 2 ;;
    --device)     DEVICE="$2"; shift 2 ;;
    --pubkey)     PUBKEY="$2"; shift 2 ;;
    --ghost)      GHOST="$2"; shift 2 ;;
    --role)       ROLE="$2"; shift 2 ;;
    --expires-in) EXPIRES_IN="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ---------- validate ----------
if [[ -z "$ORG" ]]; then echo "ERROR: --org required" >&2; exit 1; fi
if [[ -z "$CREATED_BY" ]]; then echo "ERROR: --created-by required" >&2; exit 1; fi

MODE_COUNT=0
if [[ -n "$DEVICE" ]]; then MODE_COUNT=$((MODE_COUNT + 1)); fi
if [[ -n "$PUBKEY" ]]; then MODE_COUNT=$((MODE_COUNT + 1)); fi
if [[ -n "$GHOST" ]];  then MODE_COUNT=$((MODE_COUNT + 1)); fi
if [[ "$MODE_COUNT" -ne 1 ]]; then
  echo "ERROR: exactly one of --device / --pubkey / --ghost required (got $MODE_COUNT)" >&2
  exit 1
fi

UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
B64URL_RE='^[A-Za-z0-9_-]{43}$'

if ! [[ "$ORG" =~ $UUID_RE ]]; then echo "ERROR: --org must be a lowercase UUID" >&2; exit 1; fi
if ! [[ "$CREATED_BY" =~ $UUID_RE ]]; then echo "ERROR: --created-by must be a lowercase UUID" >&2; exit 1; fi
if [[ -n "$DEVICE" && ! "$DEVICE" =~ $UUID_RE ]]; then echo "ERROR: --device must be a lowercase UUID" >&2; exit 1; fi
if [[ -n "$GHOST" && ! "$GHOST" =~ $UUID_RE ]]; then echo "ERROR: --ghost must be a lowercase UUID" >&2; exit 1; fi
if [[ -n "$PUBKEY" && ! "$PUBKEY" =~ $B64URL_RE ]]; then
  echo "ERROR: --pubkey must be 43 chars base64url no-pad (32 bytes)" >&2
  exit 1
fi

case "$ROLE" in
  owner|admin|user|auditor) ;;
  *) echo "ERROR: --role must be one of owner|admin|user|auditor (got $ROLE)" >&2; exit 1 ;;
esac

# ---------- verify created_by is active admin/owner in org ----------
ADMIN_ROLE=$(docker compose exec -T postgres psql -U umoja -d umoja -tA -c \
  "SELECT role FROM devices
   WHERE device_id = '$CREATED_BY' AND org_id = '$ORG' AND status = 'active';")
if [[ -z "$ADMIN_ROLE" ]]; then
  echo "ERROR: --created-by $CREATED_BY is not an active device in org $ORG" >&2
  exit 1
fi
if [[ "$ADMIN_ROLE" != "admin" && "$ADMIN_ROLE" != "owner" ]]; then
  echo "ERROR: --created-by role is '$ADMIN_ROLE', must be admin or owner" >&2
  exit 1
fi

# ---------- resolve bound_public_key (hex, 64 chars) ----------
PUBKEY_HEX=""

if [[ -n "$DEVICE" ]]; then
  PUBKEY_HEX=$(docker compose exec -T postgres psql -U umoja -d umoja -tA -c \
    "SELECT encode(public_key, 'hex') FROM devices WHERE device_id = '$DEVICE';")
  if [[ -z "$PUBKEY_HEX" ]]; then
    echo "ERROR: --device $DEVICE not found" >&2
    exit 1
  fi

elif [[ -n "$GHOST" ]]; then
  PUBKEY_HEX=$(docker compose exec -T postgres psql -U umoja -d umoja -tA -c \
    "SELECT encode(public_key, 'hex') FROM devices WHERE device_id = '$GHOST';")
  if [[ -z "$PUBKEY_HEX" ]]; then
    echo "ERROR: --ghost $GHOST not found" >&2
    exit 1
  fi
  FAKE_HEX=$(printf 'ff%.0s' {1..32})
  if [[ "$PUBKEY_HEX" == "$FAKE_HEX" ]]; then
    echo "ERROR: --ghost $GHOST public_key is already ff..ff sentinel (already ghosted)" >&2
    echo "  The original public_key is unrecoverable. Generate a fresh QR from" >&2
    echo "  the app and re-run with --pubkey <b64url>." >&2
    exit 1
  fi

else
  # --pubkey mode: decode base64url → hex
  PUBKEY_HEX=$(python3 -c \
    "import base64, sys; print(base64.urlsafe_b64decode(sys.argv[1] + '=').hex())" \
    "$PUBKEY")
  if [[ ${#PUBKEY_HEX} -ne 64 ]]; then
    echo "ERROR: --pubkey decoded to ${#PUBKEY_HEX} hex chars, expected 64" >&2
    exit 1
  fi
fi

# ---------- ghost mutation (before token insert) ----------
if [[ -n "$GHOST" ]]; then
  docker compose exec -T postgres psql -U umoja -d umoja -q -c \
    "UPDATE devices
     SET public_key = decode(repeat('ff', 32), 'hex'),
         status = 'revoked',
         revoked_at = COALESCE(revoked_at, now()),
         revoke_reason = 'GHOST (bootstrap-enrollment-token recovery)'
     WHERE device_id = '$GHOST';" >/dev/null
  echo "[ghost] device $GHOST public_key mutated to ff..ff, status=revoked"
fi

# ---------- generate token ----------
TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Portable sha256: prefer sha256sum (Linux/GNU), fall back to shasum (macOS)
if command -v sha256sum &>/dev/null; then
  TOKEN_HASH=$(printf '%s' "$TOKEN" | sha256sum | awk '{print $1}')
else
  TOKEN_HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | awk '{print $1}')
fi

# ---------- insert ----------
docker compose exec -T postgres psql -U umoja -d umoja -q -c \
  "INSERT INTO enrollment_tokens
     (token_hash, org_id, role, created_by, bound_public_key, expires_at)
   VALUES (
     decode('$TOKEN_HASH', 'hex'),
     '$ORG',
     '$ROLE',
     '$CREATED_BY',
     decode('$PUBKEY_HEX', 'hex'),
     now() + interval '$EXPIRES_IN'
   );" >/dev/null

# ---------- verify the row landed ----------
ROW_CHECK=$(docker compose exec -T postgres psql -U umoja -d umoja -tA -c \
  "SELECT count(*) FROM enrollment_tokens
   WHERE encode(token_hash, 'hex') = '$TOKEN_HASH';")
if [[ "$ROW_CHECK" != "1" ]]; then
  echo "ERROR: token row not found after insert (this should not happen)" >&2
  exit 2
fi

# ---------- output ----------
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "ENROLLMENT TOKEN (paste into app's Enrollment screen):"
echo ""
echo "  $TOKEN"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Metadata:"
echo "  token_hash:       $TOKEN_HASH"
echo "  bound_public_key: $PUBKEY_HEX"
echo "  org_id:           $ORG"
echo "  role:             $ROLE"
echo "  created_by:       $CREATED_BY"
echo "  expires_at:       now() + $EXPIRES_IN"
if [[ -n "$GHOST" ]]; then
  echo "  ghosted_device:   $GHOST (original public_key preserved above)"
fi
echo "════════════════════════════════════════════════════════════════"
