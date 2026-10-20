# TOM Cookie Hub

Private admin hub + encrypted API storage + a local auto-login adapter for the existing TOM script.

## Deploy

The connected Render workspace is **Jannatul's workspace**.
A free Postgres instance named `tom-cookie-hub-db` has been created in Singapore.
The root `render.yaml` connects the service to that database and generates three independent secrets.

1. Once the changes are on `main`, open:
   https://dashboard.render.com/blueprint/new?repo=https://github.com/parvez-devs/TOM-DATA
2. Select Jannatul's workspace and review the free service/database definitions.
3. Apply the Blueprint. It should link the existing database with the matching name.
4. Open the resulting web service. Its Environment page contains:
   - `HUB_ADMIN_TOKEN`: admin login password.
   - `HUB_CLIENT_TOKEN`: local client credential. Do not use the admin token for clients.
   - `ENCRYPTION_SECRET`: stable encryption key material. Keep a private backup; changing it makes existing records unreadable.
5. Login at the hub URL with the admin token, then add your own cookies, one complete cookie per line.
   You can optionally attach an own-account access token to the import.

Never commit real cookies, access tokens, hub keys, database passwords, or .env files.
The public repository contains application code only.
The admin page does not reveal cookie/token values after import.
An authenticated client can retrieve decrypted sessions: protect the client token like a password.

## Free-plan limits

Free Render Postgres expires 30 days after creation and does not provide managed backups.
The database created for this task expires around **20 November 2026, 03:29 Asia/Dhaka**.
Free web services sleep when idle. The client allows a longer timeout for startup.
Use a suitable paid database for long-term storage; no paid plan was selected here.

## Run your existing dump script

Keep your existing full script as `newd.py`, outside the public repository if it includes personal information.
The repo does not contain your uploaded script.

```bash
git clone https://github.com/parvez-devs/TOM-DATA.git
cd TOM-DATA
python -m pip install -r requirements.txt
python run_dump.py /path/to/newd.py
```

The launcher asks for the hub HTTPS URL and a hidden client token.
Alternatively set `HUB_URL` and `HUB_CLIENT_TOKEN` in your local environment.
It loads the existing `auth` class and `menu` without editing the banner, menus, validation, dump logic, or dual-output behavior.
The original file remains runnable directly for its original manual-login flow.

The hub cannot manufacture access permissions or guarantee cookie-to-token discovery.
If discovery is unavailable, add a valid own-account access token alongside the cookie.
The original script's API version and endpoint support still need to be valid.

## Selection and restriction behavior

- The first import permanently binds this vault to its cookie's `c_user`.
- Additional sessions must have the same `c_user`; the hub is not a pool of different accounts.
- The client tries saved sessions until that same account verifies.
- Every Facebook request checks hub state and is paced.
- Code 368, rate-limit codes, and HTTP 429 stop the process immediately.
- No next cookie is checked following those responses.
- The pause is stored in Postgres and in a local non-secret marker.
- A network or hub failure stops requests rather than falling back to another account.
- Public visibility is not inferred from a successful login.

After resolving the provider restriction:
1. Review the provider notice.
2. Use the hub's Resume control.
3. Clear the local marker explicitly:
   `python run_dump.py --clear-local-pause`
4. Run the launcher again.

## API

Use `Authorization: Bearer <token>` over HTTPS.

| Route | Role | Purpose |
| --- | --- | --- |
| GET /healthz | public | Minimal database health |
| GET /api/state | admin/client | Account UID and pause state |
| GET /api/sessions | admin/client | Metadata only, no cookie/token values |
| POST /api/sessions | admin | Add owned same-account sessions |
| POST /api/sessions/{id}/checkout | admin/client | Retrieve one session if not paused |
| POST /api/halt | admin/client | Persist provider-restriction pause |

Create payload shape (placeholders only):

```json
{
  "owned": true,
  "sessions": [
    {
      "label": "My phone",
      "cookie": "c_user=YOUR_UID; xs=YOUR_SESSION;",
      "access_token": "OPTIONAL_OWN_ACCOUNT_TOKEN"
    }
  ]
}
```

## Checks

```bash
python -m unittest discover -s tests -v
```

Tests cover authentication roles, encrypted storage, metadata-only lists, same-account enforcement,
atomic imports, persistent pauses, blocked checkout, CSRF, client stop behavior, and local pause persistence.
Render runs them during the build, before the service starts.
