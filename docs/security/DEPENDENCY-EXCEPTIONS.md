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

### RESOLVED — `ws@8.18.0` (fixed 2026-10-19, commit `9a1173e`)

**Status: resolved.** This is a historical record of a finding and its
fix, not an active exception. `ws` is no longer retained at the
vulnerable version.

| Field | Value |
|-------|-------|
| CVE / advisory | GHSA-58qx-3vcg-4xpx (uninitialized memory disclosure, CWE-908, CVSS 4.4)<br>GHSA-96hv-2xvq-fx4p (memory exhaustion DoS, CWE-400/770/1050, CVSS 7.5) |
| Affected package | `ws` (WebSocket library) |
| Vulnerable range | `>=8.0.0 <8.20.2` |
| Found version | `8.18.0` (direct devDependency + transitive via `@fastify/websocket@11.0.1`) |
| Severity | HIGH (npm audit aggregates to high via the 7.5 DoS advisory) |
| Rationale | Not a deliberate retention — the version predated the advisories. Found during TASK-P1-027 execution (dependency review). |
| Mitigation applied | Bumped direct devDependency range `^8.18.0` → `^8.22.0`; `npm install` resolves to `8.22.0` (latest 8.x). `@fastify/websocket`'s `^8.16.0` range accepts the fix; no overrides, no split install, no nested `node_modules/ws` duplicate. |
| Resolution | `ws@8.22.0` installed; `npm audit` reports 0 critical, 0 high, 0 moderate, 0 low. Backend test suite green (254/254). Fix commit: `9a1173e`. |
| Owner | Project owner |
| Resolution date | 2026-10-19 (found and fixed same session) |

**Distinction from an active exception.** An active §1 entry means a
known-vulnerable dependency is currently in use, with a documented
rationale for why no safe alternative exists and an expiry date. This
entry is the opposite: the vulnerability existed, was found, was fixed,
and is now recorded for audit-trail purposes. Do not treat as a
precedent for retaining CVE-affected dependencies — the expected
response to a HIGH/CRITICAL finding remains "fix or actively document
retention with expiry," per Build Master §6.


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
