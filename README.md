# Phamquangios SEV

SEV is the account and release-control backend for the Phamquangios iOS app. It provides a Vietnamese admin panel and FastAPI API.

## Features

- Admin-only account creation; no public sign-up endpoint.
- PBKDF2-HMAC-SHA256 password hashes and hashed server-side session tokens.
- Per-account device limits, device inventory, device lock/unlock, device release, account lock, key stop/start and password reset.
- Global app disable, maintenance message, minimum version and HTTPS update link.
- Public status endpoint and private admin API.
- SQLite persistence; Docker Compose deployment template.

## Local development

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SEV_ADMIN_USER='admin'
export SEV_ADMIN_PASSWORD='use-a-unique-long-password-here'
export SEV_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` for local testing. Do not expose plain HTTP publicly.

## Deploy

1. Copy `.env.example` to `.env` and set a unique admin password and a random secret of at least 32 characters.
2. Configure a real DNS domain and HTTPS reverse proxy (Caddy, Nginx, or Traefik).
3. Run `docker compose up -d --build`.
4. Visit the HTTPS domain and log into the SEV admin page to create app accounts.
5. Back up the `sev-data` volume. Never commit `.env`, database files, or real credentials.

## Connect the iOS app

Set `SEVBaseURL` in both `Phamquangios/Info.plist` and `Phamquangios Extension/Info.plist` to the real HTTPS server base URL, without a trailing slash, then rebuild/sign in Xcode. The integrated iOS source stores the session token in Keychain, shares session/device state with the Safari extension using the existing app group, validates sessions at launch/foreground and periodically, and validates before the extension returns userscripts.

The app ZIP currently uses `https://YOUR-SEV-DOMAIN.example` as a safe placeholder. Login is intentionally disabled until a real HTTPS URL is configured. The GitHub repository contains server code only; the integrated iOS source is delivered separately as the project ZIP.

## Admin endpoints

- `POST /api/admin/login`
- `GET/POST /api/admin/accounts`
- `PATCH /api/admin/accounts/{id}` — account lock, key active, device limit, note
- `POST /api/admin/accounts/{id}/release-device` — remove all device registrations
- `PATCH /api/admin/accounts/{id}/devices/{device_id}` — lock/unlock one device
- `DELETE /api/admin/accounts/{id}/devices/{device_id}` — release one device
- `POST /api/admin/accounts/{id}/reset-password` — JSON body `{ "password": "new-password" }`
- `GET/PUT /api/admin/settings`
- `GET /api/status`
- `POST /api/auth/login`
- `POST /api/auth/validate`
- `POST /api/auth/logout`

## Limitations before production

- This source repository does not deploy a public server, domain, TLS certificate, or live admin credentials.
- Remote revocation takes effect when the app next validates (foreground or roughly every 60 seconds while active); an offline device cannot receive an immediate remote command.
- A script already injected into an open Safari page cannot be retroactively removed; the next script fetch is blocked after revocation and reloading/navigating the page is required to stop existing page context.
- Build and sign the iOS targets on macOS with Xcode and test against a staging HTTPS SEV server before distributing.
