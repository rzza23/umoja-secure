# Umoja Secure

Privacy messenger for government and security professionals.

## Documents

- `UMOJA-SECURE-BUILD-MASTER.md` — operational build instruction (frozen at v1.4.2)
- `docs/US-TASK-P1-001.md` — Phase 1 task registry (v0.4)

## Status

Phase 1 development. Backend complete for messaging; Android client in progress.

## Running the stack

Requires Docker Desktop or Docker Engine with Compose v2.

    docker compose up -d --build
    curl http://localhost:8080/health
    curl http://localhost:8080/ready

Logs and teardown:

    docker compose logs -f backend
    docker compose down
    docker compose down -v

## Development

Backend local development:

    cd backend
    npm install
    cp .env.example .env
    cd ..
    docker compose up -d postgres
    cd backend
    npm run migrate
    npm run dev

Tests:

    cd backend
    npm test

## Backend endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | /health | Liveness |
| GET | /ready | Readiness (DB check) |
| POST | /enrollment | Enroll device with token |
| POST | /auth/challenge | Request authentication challenge |
| POST | /auth/verify | Verify signature, issue session |
| POST | /auth/logout | Revoke session |
| GET | /me | Own device info |
| POST | /prekeys | Upload prekey bundle |
| GET | /prekeys/status | Own prekey inventory |
| GET | /prekeys/:device_id | Peer prekey bundle |
| POST | /envelopes | Submit ciphertext for recipient |
| GET | /envelopes/pending | List queued envelopes |
| GET | /envelopes/:id | Fetch envelope body |
| POST | /envelopes/:id/ack | Acknowledge retrieval |
| POST | /admin/enrollment-tokens | Create enrollment token |
| GET | /admin/enrollment-tokens | List org enrollment tokens |
| POST | /admin/enrollment-tokens/:id/revoke | Revoke token |
| GET | /admin/devices | List devices in org |
| POST | /admin/devices/:id/revoke | Revoke device |
| POST | /admin/devices/:id/suspend | Suspend device |
| POST | /admin/devices/:id/resume | Resume device |
| GET | /admin/audit/verify | Verify audit hash chain (owner only) |
| WS | /ws | Real-time envelope push |

## Contributing

Every commit message references a task ID. Every task follows the workflow in
`UMOJA-SECURE-BUILD-MASTER.md` §7.

## License

Umoja Secure is licensed under the GNU Affero General Public License,
version 3.0 (AGPLv3). See `LICENSE` for the full text.

### Source code

Users of the software have the right to obtain the Corresponding Source
under AGPLv3. The source repository is:

    https://github.com/rzza23/umoja-secure

For private-network deployments, administrators should either provide users
with access to a mirror of this repository on the same network, or update
the app's About screen to point at the internal source location. The URL
shown in the app is configurable at
`android/app/src/main/res/values/strings.xml` (`about_source_url`).

### Third-party components

See `NOTICE` for attribution of third-party components used in this project,
including their licenses. A complete inventory is generated with each build
in the SBOM (`backend/sbom.json`).

### Contributing

See `CONTRIBUTING.md`. All contributions require a DCO sign-off.
