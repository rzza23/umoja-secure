# ADR-CI-GATE-001 — CI Enforcement Gate for Dependency Review

**Status:** Proposed
**Date:** 2026-10-21
**Session:** Z-25
**Supersedes:** None (new)
**Related:** TASK-P1-027b (§B, registry v0.13), TASK-P1-027a (`9a1173e`), Build Master §6, Build Master §11, US-ADD-001 §8.1, DEPENDENCY-REVIEW.md, DEPENDENCY-EXCEPTIONS.md

---

## §1 Context and scope

TASK-P1-027a (executed 2026-10-19 at `9a1173e`) shipped the *manual*
dependency-review primitives: `npm run sbom`, `artifacts/dep-tree.json`,
`docs/security/DEPENDENCY-REVIEW.md` (method + cadence),
`docs/security/DEPENDENCY-EXCEPTIONS.md` (exception format). What it
did **not** ship is *enforcement*. `DEPENDENCY-REVIEW.md` §5 states
this honestly:

> Without CI, "PR blocked until fixed" is documentation, not automation.
> … the enforcement is **the discipline of the human running these
> commands**.

P1-027b is the automation of that gate. Its §B body (registry v0.13,
40 lines) names four deliverables plus a named blocker:

- CI provider chosen and documented
- Backend workflow: SBOM + audit + dep-tree diff; PR blocked on failure
- Android workflow: gradle dependencies parse + prohibited-package check
- End-to-end verification on a throwaway branch (clean + deliberately failing)

§B line 75–76 is explicit about the sequencing this ADR resolves:

> Do NOT bake a specific CI provider into this section's acceptance until
> the provider is chosen.

**In scope:** provider choice, enforcement policy, staged rollout,
workflow design (backend first, Android second), exception mechanism,
branch-protection requirements, test matrix.

**Out of scope, named so a future session doesn't expand it:**
- Scheduled / nightly audits (§B is per-PR)
- Dependabot / Renovate configuration (complementary, not replacement —
  they open PRs; the gate blocks the PRs that introduce problems)
- Android SBOM generation (CycloneDX-gradle is a future improvement;
  §B names only the dependency-tree parse)
- Release build automation (a full release workflow is much larger)
- Cross-platform runners (Ubuntu-only)
- Deployment automation (this is a security-critical app; deployment
  is manual by design, out of scope for a gate workflow)
- TASK-P1-024 (external security review) — distinct task

---

## §2 Decision — CI provider

**GitHub Actions.**

Rationale, in priority order:

1. **Repository is on GitHub** (`github.com:rzza23/umoja-secure`).
   Native integration eliminates the entire auth surface: no deploy
   keys, no GitHub app install, no SSH-in-CI, no cross-provider token
   rotation. Every alternative below requires at least one of these.

2. **`services:` block gives Postgres 16 natively.**
   `backend/test/global-setup.ts` requires
   `postgres://umoja:umoja@localhost:5432/umoja`; the
   `services: postgres:` block provides it in one YAML declaration,
   with built-in health-check options. CircleCI and GitLab CI require
   more setup for the same result.

3. **Android SDK integration is supported via
   `android-actions/setup-android`.** The project pins AGP 9.4.1,
   Kotlin 2.2.10, Gradle 9.8.0 — all current, no version-drift risk.
   The action accepts an SDK-level specification, not a stale
   distribution.

4. **Branch protection is the enforcement mechanism** — a GitHub
   repository setting that refuses merge until required status checks
   pass. Without it, the workflow is advisory. §6 documents the
   required settings explicitly.

Alternatives evaluated and rejected:

| Provider | Reject reason |
|---|---|
| **CircleCI** | Requires deploy-key or GitHub-app auth; Postgres setup is manual; branch-protection integration is indirect (CircleCI reports status; GitHub still needs the protection rule). |
| **GitLab CI** | Would require repository mirror or migration. Different trust boundary; no cost benefit; adds a second provider to audit. |
| **Buildkite** | Self-hosted runners — infrastructure overhead exceeds the scale. Overkill for one repo. |
| **Pre-commit hooks only** | Cannot enforce on remote. §B line 84–85's "PR blocked" is the literal acceptance criterion; hooks are advisory by design. |

**What GitHub Actions does NOT solve, named so no future session
assumes otherwise:**

- **Branch protection is a separate repository setting**, not a
  workflow file. Workflows *run*; branch protection *refuses merge*.
  Both are required. §6 documents the settings as acceptance
  requirements, not automation.
- **Fork PRs run with limited permissions.** The gate does not need
  secrets, so this is correct. If a future need for secrets appears
  (deployment, etc.), that becomes a separate ADR.
- **`pull_request` from a fork does not run with the fork's local
  workflow file** — GitHub runs the base-branch's workflow version.
  This is a security feature (a fork cannot weaken the gate); it is
  worth stating so it isn't later chased as a bug.

---

## §3 Decision — Enforcement policy

**Every PR runs the full gate. Fail-closed. Exception escape valve per
Build Master §6.**

Five principles, each a consequence of §1's invariant (a security-
critical project's gate must hold):

1. **Every PR, not just lockfile-change PRs.** A HIGH CVE can be
   disclosed against a transitive dependency that no PR touches. If
   the gate fires only on lockfile changes, drift goes undetected
   until the next dependency PR — possibly months. §B line 71–74 is
   explicit: *"Per-PR: generate SBOM, run `npm audit
   --audit-level=high` (block on high/critical)."* Every PR is a
   chance to catch drift.

2. **Fail-closed on the gate itself.** If the workflow fails to run,
   fails to reach Postgres, fails to parse the SBOM, or times out —
   the gate fails, not passes. Same discipline as `MatrixVerifier`
   failing on an empty trusted set (§7's codebase convention). A
   workflow that "can't determine status" is not green.

3. **Exception escape valve is the §6 mechanism, not silence.**
   Build Master §6 permits a HIGH/CRITICAL CVE to land *if* it's
   documented in `DEPENDENCY-EXCEPTIONS.md` §1 with CVE, rationale,
   mitigation, owner, and expiry ≤90 days. The gate honors this by
   parsing the exception file. A HIGH CVE *with* a matching active
   entry passes; *without* one it blocks. The expiry is load-bearing:
   a 91-day-old exception fails the gate on principle.

4. **MEDIUM/LOW do not block.** §B line 71 is
   `--audit-level=high`, not `--audit-level=moderate`. MEDIUM findings
   surface in workflow output for human triage but do not fail the PR.
   This matches §6's severity table exactly.

5. **Prohibited packages block unconditionally, with §8.1 carve-out
   escape.** No exception on principle for §11's absolute list — with
   one escape: a `com.google.*` runtime dep that has an active
   `DEPENDENCY-EXCEPTIONS.md` §2 carve-out (per US-ADD-001 §8.1,
   individually reviewed against the "no Google runtime service" test)
   passes. `com.google.zxing:core` is the only current carve-out. Each
   future carve-out needs its own §2 entry; §8.1 is not namespace
   blanket clearance.

---

## §4 Staged rollout

Per §B line 76–78:

> Do NOT attempt the Android build workflow before the backend
> workflow is proven on the same pipeline (staged rollout).

**Two implementation sessions, in order:**

**Session Z-26 — backend workflow only.**
- `.github/workflows/dependency-gate.yml` with backend job
- Postgres service block per §5
- SBOM generation, prohibited-package parse, audit-vs-exceptions
  parse, dep-tree-refresh check, full backend test suite
- End-to-end verified on a throwaway branch: clean pass + deliberately
  failing case (per §B line 89–90)
- Branch protection enabled after green, verified by observing the
  merge button refuses on a deliberately-failing throwaway PR
- Commit

**Session Z-27 — Android workflow + end-to-end.**
- Extend `.github/workflows/dependency-gate.yml` with Android job
- `./gradlew :app:dependencies --configuration releaseRuntimeClasspath`
  capture, prohibited-package parse on the release runtime tree
- End-to-end verified on a throwaway branch
- Branch protection named check added for the Android job
- Commit

The split is deliberate: if backend works and Android reveals a
Gradle/AGP/parse issue, the debug is scoped to one job. If both landed
at once, the failing surface is ambiguous — and this project's
`str.count` / template-anchor lessons (Z-24) show that ambiguous
failing surfaces cost sessions.

---

## §5 Backend workflow design

**Trigger.** `pull_request` (opened, synchronize, reopened). No `push`
trigger — the branch-protection gate only makes sense on PRs.

**Job: `backend-dependency-gate`.**

```yaml
name: Dependency Gate
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  backend-dependency-gate:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: umoja
          POSTGRES_PASSWORD: umoja
          POSTGRES_DB: umoja
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
    defaults:
      run:
        working-directory: backend
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: '24'
          cache: 'npm'
          cache-dependency-path: backend/package-lock.json
      - run: npm ci
      - run: npm run sbom
      - run: python3 ../scripts/ci/check-prohibited.py sbom.json
      - run: npm audit --json > /tmp/audit.json || true
      - run: python3 ../scripts/ci/check-cve-exceptions.py /tmp/audit.json ../docs/security/DEPENDENCY-EXCEPTIONS.md
      - run: python3 ../scripts/ci/check-dep-tree-refresh.py
      - run: npm test
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: backend-dep-artifacts
          path: |
            backend/sbom.json
            artifacts/dep-tree.json
            /tmp/audit.json
```


**Failure modes and their behavior** — every row is fail-closed:

| Failure | Behavior |
|---|---|
| Postgres service doesn't start | Job fails. Not a skip. |
| `npm ci` fails | Job fails — dependency resolution is part of the gate. |
| SBOM generation fails | Job fails — nothing to check means nothing passes. |
| `check-prohibited.py` finds prohibited dep without carve-out | Job fails. |
| `check-cve-exceptions.py` finds HIGH/CRITICAL without active exception (or with expired one) | Job fails. |
| `check-dep-tree-refresh.py` finds lockfile changed but dep-tree not refreshed | Job fails — refresh discipline violated. |
| `npm test` fails | Job fails — dependency-tree integrity is in question when tests fail. |

**Prohibited-package parse (`scripts/ci/check-prohibited.py`).**
Structural JSON parse of SBOM `components`:

1. Filter to runtime-scope components (dev-only deps don't ship; §11 is about runtime reachability)
2. For each component, check `group` + `name` against §11 list: `@google/*`, `com.google.*`, `googleapis`, `gaxios`, `google-auth-library`, `firebase*`, `tink`
3. On match, check `DEPENDENCY-EXCEPTIONS.md` §2 for an entry at exact `<artifact>@<version>`
4. No carve-out → exit 1 with the offending component path; job fails
5. §11's "structural parse, not grep" rule from `DEPENDENCY-REVIEW.md` §4 is inherited — substring traps like `com.google.zxing:core` cannot be silently passed by grepping "google"

**CVE-exception parse (`scripts/ci/check-cve-exceptions.py`).**

1. Parse `npm audit --json` output — extract HIGH/CRITICAL advisories with their package + CVE/advisory ID
2. Parse `DEPENDENCY-EXCEPTIONS.md` §1 — extract entries with Status active (no `RESOLVED` marker) plus their `CVE`/`advisory` field and `Expiry` date
3. For each audit finding:
   - No matching exception entry → fail
   - Exception exists but `Expiry < today` → fail (the exception has lapsed; the CVE remains)
   - Exception exists with future expiry → pass with a `::notice` workflow annotation naming the exception
4. Exit 1 on any finding without a valid active exception

**Dep-tree refresh check (`scripts/ci/check-dep-tree-refresh.py`).**

1. Compare `git diff --name-only origin/${{ github.base_ref }}...HEAD`
2. If `backend/package-lock.json` changed but `artifacts/dep-tree.json` did not → fail
3. **Amended 2026-10-22:** Verify the `_meta.lockfile_sha` in `artifacts/dep-tree.json` matches the sha256 of the current `package-lock.json`. Fail if they differ (tree is stale). Do not compare `npm ls` output — it is not platform-reproducible. Use `regen-dep-tree.py` to refresh the tree; §11 enforcement for optional deps remains in the SBOM check.
4. Output the byte-diff for review if it fails

**Artifacts upload.** `sbom.json` (gitignored, generated per PR), `artifacts/dep-tree.json` (tracked; refreshed only when lockfile changes per `artifacts/README.md`), and `audit.json` are uploaded on `always()` so a failing run leaves evidence for triage.

---

## §6 Branch protection — the actual enforcement

**The workflow runs. Branch protection refuses the merge.** Both are required. A workflow that runs and reports failure, on a branch where merge isn't gated, is documentation, not enforcement.

**Required branch-protection settings** (documented as setup steps, not automation — GitHub stores these in repository settings, not in YAML):

1. **Require status checks to pass before merging.** Named checks: `backend-dependency-gate` (Z-26), later extended with `android-dependency-gate` (Z-27).
2. **Require branches to be up to date before merging.** Prevents the "green on stale base" bypass.
3. **Do not allow administrators to bypass.** The whole point of the gate is absolute. Admin bypass creates a "we'll do it once" pattern that becomes "we always do it."
4. **Require linear history.** Not strictly a dependency-gate concern, but prevents merge-commit paths that could skip check re-evaluation.

These settings live in the GitHub repository settings UI. They are a manual setup step recorded in the implementation session's completion notes. The ADR names them as acceptance requirements.

**Plan-Tier Requirement (Added 2026-10-22):** GitHub does not enforce rulesets on private repositories on the Free tier. Z-26-B initially configured this on a private repo and discovered the rulesets were saved but dormant. The repository was made public to activate enforcement. If the repo returns to private without upgrading to GitHub Pro/Team, these settings will silently revert to dormant.

**Verification per implementation session.** Completion criteria include: enable branch protection, open a deliberately-failing throwaway PR, observe the merge button refuses. The ADR names this as the acceptance test that distinguishes "workflow ran" from "gate worked" — the same discipline as P1-038's three-case acceptance (a green case alone cannot distinguish a working gate from a sticky-open one).

---

## §7 Test matrix — maps to §B required tests

§B lines 92–96 name four tests. Each maps to a specific workflow + branch-protection behavior, exercised on a throwaway branch:

| §B test | Delivered by | Exercise |
|---|---|---|
| **TEST-CI-PROHIBITED-BLOCKED** | `check-prohibited.py` | Add a `com.google.firebase*` runtime dep to `backend/package.json`; `npm install`; open throwaway PR. Gate fails at SBOM parse. Merge refused. |
| **TEST-CI-HIGH-CVE-BLOCKED** | `check-cve-exceptions.py` | Add a dep with a known HIGH advisory, no exception entry. Gate fails at audit parse. Merge refused. |
| **TEST-CI-CLEAN-PASSES** | Full workflow | Open throwaway PR with a no-op change. All jobs green. Merge button enabled. |
| **TEST-ANDROID-DEP-PARSE** | Android workflow (Z-27) | Add a `com.google.*` dep to `releaseRuntimeClasspath` in a throwaway branch. Gate fails at parse. Remove and re-run: green. |

§B line 89–90's "both a clean pass and a deliberately-failing case" is the per-test pairing: **each test must be observed in both directions** — a `TEST-CI-PROHIBITED-BLOCKED` that only passes the clean case is indistinguishable from a gate that never fires. This is the Z-24 / P D-1 lesson applied to CI: a gate that doesn't fail is not a gate.

---

## §8 Exception mechanism

`DEPENDENCY-EXCEPTIONS.md` is the load-bearing exception file. Two mechanisms, deliberately distinct:

**§1 — CVE exceptions.** Active entries have: CVE identifier, rationale, mitigation, owner, expiry ≤90 days. The gate parses this file:

- Active entry (no `RESOLVED` marker) whose CVE matches a HIGH/CRITICAL finding → pass
- Active entry with `Expiry: <date>` past today → fail (the exception has lapsed)
- No matching entry → fail

Current state at session Z-25: **zero active §1 entries.** `ws@8.18.0` is a `RESOLVED` historical record (fixed at `9a1173e`), correctly parsed as inactive by the gate.

**§2 — §11 interpretation carve-outs.** Active entries have: artifact, version, rationale, approver, date. The gate parses this file:

- Match by full artifact path + version
- No expiry — carve-outs are reviewed per US-ADD-001 §8.1, not time-limited (a carve-out is a semantic statement: "this artifact does not constitute a Google runtime service", which cannot expire)
- The `com.google.zxing:core` entry is the only current carve-out

**What the ADR does NOT grant.** Blanket `com.google.*` clearance. A future Firebase dep would need its own §2 entry, and that entry's rationale would have to clear §8.1's standard (no Google runtime service, no network egress, no Google-controlled infrastructure). The zxing carve-out is the precedent that *individual artifacts* can be cleared when they pass §8.1 — not that any `com.google.*` dep is ever cleared.

**Fail-closed exception parse.** If `DEPENDENCY-EXCEPTIONS.md` is missing, malformed, or its format changes incompatibly, the gate fails. An unreadable exception file is not the same as "no active exceptions" — the gate distinguishes "nothing to match" (pass) from "cannot determine what to match" (fail).

---

## §9 Out of scope

Named so a future session doesn't expand:

- **Scheduled / nightly audits.** §B line 71 is per-PR. Nightly drift detection is a future improvement if PR frequency drops below the drift rate; not this task.
- **Dependabot / Renovate.** Complementary CVE-tracking tools — they open PRs; the gate blocks the PRs that introduce problems. Enabling Dependabot is a small future task, not P1-027b.
- **Android SBOM generation.** CycloneDX-gradle-plugin exists; §B names only the dependency-tree parse. Full Android SBOM is a future improvement.
- **Release build automation.** `./gradlew :app:dependencies` runs without a release build; a full release-build workflow is much larger.
- **Cross-platform runners.** Ubuntu-only; Windows/macOS add matrix complexity without a current need.
- **Deployment automation.** Manual by design for a security-critical app.
- **TASK-P1-024** (external security review). Distinct task.
- **`androidTest` in CI.** The project runs `connectedAndroidTest` on emulators, which CI cannot provide at this scale; kept manual per existing pattern.

---

## §10 Revision history

| Version | Date | Changes |
|---|---|---|
| v0.1 | 2026-10-21 | Initial ADR. Provider (GitHub Actions), enforcement policy (every PR, fail-closed, §6 exception escape valve), staged rollout (backend then Android), workflow design, branch-protection requirements, test matrix, exception-mechanism detail. |
| v0.2 | 2026-10-22 | Z-26 implementation corrections. §5 line 237 path fix (`sbom.json` not `backend/sbom.json`). §5 rule 288 amended to `lockfile_sha` freshness check (platform-invariant) instead of byte-identical `npm ls`. §6 note added on plan-tier ruleset limitations for private repos. |