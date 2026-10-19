# Dependency Review

Document ID: DEPENDENCY-REVIEW
Date: 2026-10-19
Authority: TASK-P1-027 (SBOM + dependency review gate); Build Master §6 (dependency and audit rules)

---

## §1 Scope and purpose

This is the **human-readable review record** for backend and Android dependencies. It records:

- The current dependency inventory at each review
- The commands that produce the machine-readable artifacts
- The findings log (what was found, how it was classified, how it was resolved)
- The cadence and enforcement policy in the current project state

It does **not** replace:

- `DEPENDENCY-EXCEPTIONS.md` — the formal exception audit trail (CVE retentions, §11 interpretation carve-outs). Any CVE retained has its own entry there.
- `artifacts/dep-tree.json` — the machine-readable snapshot reviewed per PR (Build Master §6 step 3).
- `backend/sbom.json` — the CycloneDX SBOM (gitignored; generated per PR per Build Master §6 step 2).

The three documents have different purposes: this is the narrative record, the exceptions file is the formal audit trail, the artifacts are the evidence.

---

## §2 Current inventory (2026-10-19)

Backend (Node.js 24.x, `backend/package.json`):

- **22 direct dependencies** — 10 runtime (`dependencies` block) + 12 dev (`devDependencies` block)
- **~265 components** in the generated SBOM (transitive tree fully expanded)
- **Dependency tree depth distribution** (from `artifacts/dep-tree.json`):
  - depth 0: 22 (direct)
  - depth 1: 154
  - depth 2: 218
  - depth 3: 98
  - depth 4: 22
  - depth 5: 5

Android (`android/app/build.gradle.kts`, `android/gradle/libs.versions.toml`):

- Not yet covered by automated SBOM tooling. See §5's CI gap note.
- libsignal artifacts documented separately in `docs/crypto/LIBSIGNAL-REVIEW.md` and `docs/crypto/LIBSIGNAL-INTEGRATION.md`.
- zxing carve-out documented in `DEPENDENCY-EXCEPTIONS.md` §2.

**Prohibited runtime packages check** (Build Master §11, the "absolute prohibition" list): **CLEAN as of 2026-10-19.** Zero matches in `backend/sbom.json` for `@google/*`, `com.google.*`, `googleapis`, `gaxios`, `google-auth-library`, `firebase*`, or `tink`. Verified via structural SBOM parse, not grep.

**`package-lock.json` present and committed:** yes (227KB, dated 2026-10-11). Build Master §6 step 1 satisfied.

---

## §3 Method

The commands below produce the artifacts this record references. They are run each time the lockfile changes.

**Generate SBOM** (CycloneDX, gitignored output):
```
cd backend
npm run sbom
```
This invokes `cyclonedx-npm --output-file sbom.json` (dev dependency `@cyclonedx/cyclonedx-npm@6.0.1`, added at project scaffolding). Output is gitignored at both repo-root and `backend/` `.gitignore` — SBOM is a review artifact, not a committed file.

**Extract dependency tree** (JSON snapshot, tracked per PR):
```
cd backend
npm ls --all --json > ../artifacts/dep-tree.json
```

**Run audit** (JSON output for machine triage):
```
cd backend
npm audit --json > /tmp/audit-current.json
```

**Check SBOM for prohibited runtime packages** (structural parse, not grep — see §4 for why this matters):
```python
import json
with open('backend/sbom.json') as f:
    sbom = json.load(f)
prohibited = ['@google/', 'com.google.', 'googleapis',
              'gaxios', 'google-auth-library', 'firebase', 'tink']
hits = [c for c in sbom['components']
        if any(p in c.get('name', '') or p in c.get('group', '')
               for p in prohibited)]
```

**Retention discipline.** `sbom.json` and `/tmp/*.json` are ephemeral. `artifacts/dep-tree.json` is tracked; refresh it only when `package-lock.json` changes (see `artifacts/README.md`).

---

## §4 Findings log

### 2026-10-19 — TASK-P1-027 execution (first review pass)

**Finding 1 — `ws@8.18.0` with two HIGH-severity advisories (RESOLVED).**

Two advisories against `ws` (the WebSocket library):

- `GHSA-58qx-3vcg-4xpx` — uninitialized memory disclosure, CWE-908, CVSS 4.4
- `GHSA-96hv-2xvq-fx4p` — memory exhaustion DoS from tiny fragments / data chunks, CWE-400/770/1050, CVSS 7.5

Combined severity per `npm audit`: **HIGH** (aggregation via the 7.5 DoS advisory).

`ws` reached the tree two ways:
- Direct devDependency (`"ws": "^8.18.0"` in `package.json` `devDependencies`)
- Transitive via `@fastify/websocket@11.0.1` (its own dependency range: `^8.16.0`)

Per Build Master §6: **"HIGH/CRITICAL: PR blocked until fixed or documented exception."** Also per §6: "**Agent must not** add `// eslint-disable`, `.npmrc` overrides, or `npm audit --omit` flags to silence warnings." Direct version bump is the sanctioned path; overrides are not.

**Resolution:** bumped direct devDependency range `^8.18.0` → `^8.22.0`; `npm install` resolved to `ws@8.22.0` (latest 8.x, well past the `8.20.2` fix threshold). The `@fastify/websocket` consumer was satisfied by the same node — no split install, no nested duplicate, no overrides block. `npm audit` after: 0 critical, 0 high, 0 moderate, 0 low. Backend test suite: 254/254 green, no behavior regression from the minor version bump. Fix commit: `9a1173e`. Formal record: `DEPENDENCY-EXCEPTIONS.md` §1 (RESOLVED entry, not active retention).

**Finding 2 — `fsevents@2.3.3` install script not covered by `allowScripts` (OBSERVED, NOT A DEFECT).**

`npm install` emits: `npm warn allow-scripts fsevents@2.3.3 (install scripts present) not yet covered by allowScripts`.

`fsevents` is an optional macOS file-watcher pulled transitively by chokidar (used by Vite/vitest). Its install script doesn't run because it's not in `package.json`'s `allowScripts` block (which covers `esbuild@0.28.2` and `esbuild@0.25.12`).

**Classification: not a defect.** The `allowScripts` discipline is working correctly — install scripts that aren't explicitly approved don't run, which is the safe posture. `fsevents` is mac-only-optional; its absence as a script-permitted package is a note, not a fix target.

**Action:** no fix needed. Recorded here for transparency so a future `npm install` warning isn't chased as a new finding. If a future macOS dev environment requires `fsevents` install scripts to run, add `fsevents@<version>` to `allowScripts` with a rationale — not before.

**Finding 3 — `artifacts/` directory did not exist (RESOLVED same session).**

Build Master §6 step 3 names `artifacts/dep-tree.json` as a required PR artifact. The directory was absent before this execution. Resolved: created `artifacts/` with `README.md` (refresh discipline) and `dep-tree.json` (current snapshot reflecting post-ws-fix state).

**Finding 4 — no CI exists (DEFERRED, filed as P1-027b).**

Build Master §6's requirements ("attached to the PR", "PR blocked until fixed") presume a CI system. The repo has no `.github/`, no pipeline config, no automation. The gate is enforceable only as human review in the current state.

**Action:** scoped as P1-027b (see registry §A). Requires a CI-provider decision, workflow authoring, and end-to-end test — a distinct session at minimum.

**Finding 5 — Android has no dependency tooling (DEFERRED, filed as P1-027b).**

Build Master §6: "Android side: parse `./gradlew :app:dependencies --configuration releaseRuntimeClasspath` in CI; fail if any prohibited package appears in the resolved runtime tree." The Android side has zero tooling today. The prohibited-package check across the whole release runtime classpath requires Gradle task integration + a rule engine, plus CI to enforce it.

**Action:** scoped as P1-027b alongside Finding 4 — both are "gate infrastructure that depends on CI."

---

## §5 Cadence and enforcement (current state)

**Per-PR, manually:**

1. `package-lock.json` changes reviewed in PR diff (Build Master §6 step 1).
2. SBOM regenerated (`npm run sbom`); file reviewed locally (not committed; gitignored).
3. `artifacts/dep-tree.json` regenerated when lockfile changes; PR diff shows what changed in the dependency tree (Build Master §6 step 3).
4. `npm audit --audit-level=high` run manually; results triaged by the human per §6's severity rules.
5. Any new dependency — direct or transitive — flagged for human approval per §6's last bullet.

**Enforcement gap, named:** steps 2-5 are on the reviewer to remember. Without CI, "PR blocked until fixed" is documentation, not automation. This is the P1-027b gap. Until P1-027b ships, the enforcement is **the discipline of the human running these commands**, recorded in the commit message of any PR that adds or bumps a dependency.

**Cadence:** run this review whenever the lockfile changes. Not on a schedule. Not on every session. The trigger is the artifact changing, not time passing.

**Severity handling per Build Master §6** (restated for operational clarity):

| Severity | Response |
|---|---|
| HIGH / CRITICAL | Fix or documented exception in `DEPENDENCY-EXCEPTIONS.md` §1 (with CVE, rationale, mitigation, owner, expiry ≤90 days) |
| MEDIUM / LOW | Reported to human; documented acceptance |
| Unknown / ambiguous | STOP and escalate. Do not suppress. |

**Prohibited by §6:** `// eslint-disable`, `.npmrc` overrides, `npm audit --omit` flags used to silence warnings. Use direct version bump, `package.json` `overrides`, or exception entry instead.

**Prohibited by §11 (absolute):** Firebase, FCM, Google Play services, Tink, or any `com.google.*` runtime dependency (source or transitive). Violating requires reverting the entire session.

---

## §6 Related documents

- `docs/security/DEPENDENCY-EXCEPTIONS.md` — formal exception audit trail (§1 CVE retentions, §2 §11 interpretation carve-outs)
- `artifacts/README.md` — refresh discipline for the tracked dependency snapshot
- `artifacts/dep-tree.json` — the current snapshot (refresh with lockfile changes)
- `UMOJA-SECURE-BUILD-MASTER.md` §6 — the source rules this record operates under
- `UMOJA-SECURE-BUILD-MASTER.md` §11 — the absolute prohibitions
- `docs/US-TASK-P1-001.md` §A TASK-P1-027a / P1-027b — the split tasks this record satisfies (a) and defers (b)
- `docs/crypto/LIBSIGNAL-REVIEW.md` — the parallel record for the Android-side libsignal dependency

---

— end of DEPENDENCY-REVIEW —