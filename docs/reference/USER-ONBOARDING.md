# USER-ONBOARDING — What a User Needs to Know

Document ID: USER-ONBOARDING
Version: 0.1 (initial)
Date: 2026-10-18
Authority: Derived from UMOJA-SECURE-BUILD-MASTER.md v1.4.2 §2, §3.4;
ADR-HARDENING-001 §1; ADR-PROVISIONING-001 §2 Q3; AUTH-SPEC-001 §2;
THREAT-MODEL-001.
Status: Reference. Describes user-observable behavior and recovery
paths. Where this document and an authoritative spec disagree, the
spec governs.

---

## §1 Provenance

Authored 2026-10-18 during the Session U-2 backlog close. Referenced
by Build Master §2 (as one of the canonical reference documents) and
§3.4 (cryptographic erasure guarantee). The document was absent from
disk until this session — every prior session's §4 noted it as
"still missing."

This is the user-facing companion to AUTH-SPEC-001, THREAT-MODEL-001,
and ADR-HARDENING-001. Those documents specify how the system works
and why it's secure; this one specifies what a user experiences and
what to do when something goes wrong. Claims here are restated from
those sources, not invented.

---

## §2 What Umoja Secure is

Umoja Secure is a privacy-first messenger designed for government and
security professionals. Six properties define the product:

1. **No phone numbers for discovery.** You are not identified by a
   phone number, email, or any identifier tied to a real-world
   account. The device's identity is a key pair generated on the
   device, not tied to any personal account.

2. **Admin-provisioned contacts.** You do not discover contacts
   through a directory. An administrator defines who can message
   whom, using a signed authorization matrix that your device
   verifies.

3. **Server-blind.** The server routes encrypted messages. It never
   has your plaintext, your private keys, or the keys to your
   messages. If the server is fully compromised, the attacker still
   cannot read your conversations.

4. **Tor transport.** All messaging and signaling traffic to the
   server travels over Tor. Your network location is not visible to
   the server or the administrator.

5. **No Google runtime dependencies.** The app does not require
   Google Play Services or any Google runtime component to function.
   It runs on GrapheneOS or any Android without Google services.

6. **GrapheneOS-first.** The app is designed and tested for
   GrapheneOS as the reference baseline.

---

## §3 The trust model in one paragraph

The server is not trusted to protect your messages. When you send a
message, your device encrypts it (Signal protocol — PQXDH, X3DH,
Double Ratchet via libsignal) and the server only sees ciphertext
plus routing metadata (which device sent to which device, when). The
authorization to message someone is verified on your device against
a signed matrix whose signing key is pinned into the app. A
compromised server cannot forge a matrix that your device will
accept, cannot decrypt your messages, and cannot inject contacts
into your authorization set. This is why the server can be
self-hosted on infrastructure the administrator controls without
that administrator being able to read your conversations.

Source: ADR-PROVISIONING-001 §2 Q3, THREAT-MODEL-001.

---

## §4 Enrolling a device

You can only use Umoja Secure on a device that an administrator has
authorized. The onboarding flow gives you one of two things:

- **An enrollment token.** A short string an administrator sends you
  out-of-band (in person, over a channel you trust). You paste it
  into the app's Enrollment screen.
- **An enrollment QR.** A QR code your device can generate on
  request. An administrator scans it and creates a token bound to
  your device's public key. You then complete enrollment.

The token is single-use and expires after a short window. Your
device generates its own identity (a key pair) the first time you
open it. The administrator binds a token to that identity, and the
server records your device's public key against the token. After
enrollment, your device can authenticate without further
administrator action until the session expires or the administrator
revokes the device.

**Important:** the enrollment token is a credential. Do not share it.
If an attacker obtains a token before you use it, they cannot enroll
as you — the token is bound to your device's public key — but they
can attempt to use it and the enrollment will fail with a
diagnostic that indicates tampering.

---

## §5 Using the app

The app has three tabs:

- **Conversations** — chats with peers your administrator has
  authorized you to message.
- **Contacts** — the peers in your authorization matrix. Who you can
  message is defined by the matrix the administrator signed, not by
  who you've added to a personal list.
- **Settings** — your device ID, session information, and (if you
  are an administrator) the admin panel.

Messages are end-to-end encrypted. The app stores your message
history locally, encrypted at rest. The server never sees plaintext
and does not store your message history — it holds only the
ciphertext envelopes in transit until your peer's device fetches
them.

---

## §6 When something goes wrong

The app is designed to always show you a path forward. If you see
any of the following screens, the next step is named on the screen.
No screen leaves you without an action.

### Session expired (silent recovery)

If your session token has expired, the app silently re-authenticates
the first time you open it. You will see a brief "Connecting..." while
this happens, then the app opens normally. **No action is required
from you.**

### Session invalid / re-enrollment required

If the app cannot establish a session and the local state is
inconsistent (rare — usually means the app's storage was damaged),
the app will ask you to re-enroll. **Re-enrollment requires a new
enrollment token from your administrator.** The screen's "Re-enroll
this device" button walks you through it.

### Device revoked

If your administrator has revoked your device's access, you will see
a "Device revoked" screen with instructions to contact your
administrator. **Once the administrator reactivates your device, tap
"Log out and try again" on that screen and re-authenticate.** Do not
re-enroll — your device's identity is preserved; you just need to
authenticate again after the administrator's action.

### Connection lost

If the app cannot reach the server during startup or during a session
refresh, you will see a "Connection lost" screen with a **Retry**
button. Check your network connection and tap **Retry**. If the
problem persists, it may be that the server is down — contact your
administrator.

### Message verification failure

If a message arrives that fails cryptographic verification (in
practice: only if the server has been compromised and is attempting
to deliver a forged envelope), the message is rejected and does not
appear in your conversation. Your device's diagnostics screen
records the failure for an administrator to investigate.

Source for recovery-state structure: ADR-HARDENING-001 §1.

---

## §7 Cryptographic erasure guarantee

When you wipe the app's data (either through the app's duress-wipe
mechanism, or by uninstalling or clearing app data through Android),
the following is guaranteed:

> The app guarantees that the messaging keys and session material
> are erased and that no path exists to re-derive them from app
> storage. It does **not** guarantee that every physical storage
> remnant is forensically unrecoverable.

The distinction matters. After a wipe, the app cannot re-derive your
message keys from anything left in its storage; any backups of the
app's storage are useless without the Android Keystore key that
wrapped them. However, forensic recovery of physical remnants of
flash storage is a hardware-level concern outside the app's
control. The guarantee is about cryptographic erasure — the keys
are gone — not physical erasure — every byte of storage is gone.

Source: UMOJA-SECURE-BUILD-MASTER.md §3.4.

---

## §8 What is not in Phase 1

The following features are planned but not present in the current
build:

- **Voice and video calls.** Deferred to Phase 3 (WebRTC + TURN on
  the clearnet). Text messaging over Tor is Phase 1.
- **Session token rotation.** Bearer tokens with a fixed TTL are the
  Phase 1 design. Rotation is a Phase 2 concern.
- **Recovery key.** A device recovery flow exists in the
  administrator's tooling but a user-facing recovery key is not yet
  shipped (TASK-P1-035).
- **Cross-device sync.** Each device's local storage is
  independent; there is no server-side message history to sync from.

---

## §9 Further reading

For the technical specifications behind this document's claims:

- **`docs/architecture/ADR-PROVISIONING-001.md`** — the provisioning
  trust model and matrix signing protocol.
- **`docs/architecture/ADR-HARDENING-001.md`** — the session
  lifecycle state machine and recovery-state guarantees.
- **`docs/reference/AUTH-SPEC-001.md`** — device identity, sessions,
  and revocation.
- **`docs/reference/THREAT-MODEL-001.md`** — the full threat model.
- **`UMOJA-SECURE-BUILD-MASTER.md`** — the authoritative build
  specification, including §3.4 (cryptographic erasure) and §3.7
  (replacement-device flow).

---

## §10 Approval

Approval on disk (repository commit) is the operative approval for
this document. Amendments require a version bump and a rationale in
the header.
