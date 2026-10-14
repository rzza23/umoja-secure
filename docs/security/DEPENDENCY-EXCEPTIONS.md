# DEPENDENCY-EXCEPTIONS.md

Audit trail for dependencies that require human review beyond the
standard dependency-check process (Build Master §6).

Two categories of entry exist. Do not conflate them.

---

## 1. CVE exceptions

Known-vulnerable dependencies retained because no alternative is
available, or where the alternative is judged worse.

Required fields: CVE identifier, rationale, mitigation, owner, expiry
(≤90 days per Build Master §6).

*None on record.*

---

## 2. §11 interpretation carve-outs

Artifacts whose Maven groupId matches the `com.google.*` pattern but
which do not constitute a Google runtime dependency per US-ADD-001
§8.1. Each entry must be individually reviewed against §8.1 — this
file does not grant blanket clearance for the namespace.

Required fields: artifact, version, pulled-by, rationale, approver,
date.

### `com.google.zxing:core` @ 3.4.1

| Field | Value |
|-------|-------|
| Artifact | `com.google.zxing:core` |
| Version | 3.4.1 |
| Pulled by | `com.journeyapps:zxing-android-embedded:4.3.0` (`api` scope) |
| Rationale | Community ZXing project. Apache License 2.0. No Google service dependency, no Google runtime callback, no network egress to Google-controlled infrastructure. The `com.google.` groupId is historical; ZXing predates Google's Maven namespace conventions. Reviewed against US-ADD-001 §8.1 and cleared. |
| Approver | Project owner — see US-ADD-001 §8.1 |
| Date | 2026-10-14 |

---

## Provenance

Authored 2026-10-14 by TASK-P1-025 to record the first §8.1
interpretation carve-out. The §6 CVE-exception section is defined here
for consistency but has no entries yet.
