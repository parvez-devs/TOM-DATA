"""Local auto-login adapter. Credentials are fetched only over authenticated HTTPS."""
import os
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests


STOP_CODES = {368, 4, 17, 32, 613, 429}


class HubError(RuntimeError):
    pass


class HubRestricted(BaseException):
    """Escapes legacy broad 'except Exception' collectors and stops the process."""


class HubClient:
    def __init__(self, base_url, token, pause_file="TOM/.hub-paused"):
        parsed = urlparse(base_url)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise HubError("HUB_URL must be an HTTPS origin without credentials")
        self.base = base_url.rstrip("/")
        self.http = requests.Session()
        self.http.headers["Authorization"] = "Bearer " + token
        self.pause_file = Path(pause_file)

    def call(self, method, path, **kwargs):
        try:
            response = self.http.request(
                method, self.base + path, timeout=(10, 90),
                allow_redirects=False, **kwargs
            )
        except requests.RequestException:
            raise HubError("Hub unreachable; login stopped") from None
        if response.status_code == 423:
            raise HubRestricted("Hub paused. Review Facebook restriction in the admin hub.")
        if not response.ok:
            raise HubError(f"Hub request failed (HTTP {response.status_code})")
        try:
            data = response.json()
        except ValueError:
            raise HubError("Invalid hub response") from None
        if not isinstance(data, dict):
            raise HubError("Invalid hub response")
        return data

    def ensure_open(self):
        if self.pause_file.exists():
            raise HubRestricted(
                "Local provider pause exists. Resolve the restriction, resume in the hub, "
                "then use --clear-local-pause."
            )
        state = self.call("GET", "/api/state")
        if state.get("blocked") is not False:
            raise HubRestricted("Hub paused. Review Facebook restriction in the admin hub.")
        return state

    def trip(self, code):
        self.pause_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # The marker contains no credential values.
        self.pause_file.write_text(str(code), encoding="ascii")
        try:
            self.call("POST", "/api/halt", json={"code": code})
        except (HubError, HubRestricted):
            pass
        raise HubRestricted(
            f"Provider restriction {code}; all session selection and requests stopped."
        )

    def clear_local_pause(self):
        state = self.call("GET", "/api/state")
        if state.get("blocked") is not False:
            raise HubRestricted("Resume the hub only after the provider restriction is resolved.")
        self.pause_file.unlink(missing_ok=True)


def facebook_url(url):
    host = (urlparse(url).hostname or "").lower()
    return urlparse(url).scheme == "https" and (
        host == "facebook.com" or host.endswith(".facebook.com")
    )


def protect_session(session, hub, owner_uid):
    original_request = session.request
    last_request = [0.0]

    def inspect(response, *args, **kwargs):
        if 300 <= response.status_code < 400:
            target = urljoin(response.url, response.headers.get("Location", ""))
            if not facebook_url(target):
                raise HubError("Refused redirect outside Facebook")
        try:
            data = response.json()
        except ValueError:
            data = {}
        details = data.get("error") if isinstance(data, dict) else None
        try:
            code = int(details.get("code")) if isinstance(details, dict) else None
        except (ValueError, TypeError):
            code = None
        if response.status_code == 429:
            code = 429
        if code in STOP_CODES:
            hub.trip(code)
        return response

    def guarded_request(method, url, **kwargs):
        if not facebook_url(url):
            raise HubError("Refused request outside Facebook")
        state = hub.ensure_open()
        if state.get("owner_uid") != owner_uid:
            raise HubError("Hub account identity changed; stopped")
        values = {cookie.value for cookie in session.cookies if cookie.name == "c_user"}
        if values and values != {owner_uid}:
            raise HubError("Session belongs to another account; stopped")
        delay = 3.0 - (time.monotonic() - last_request[0])
        if delay > 0:
            time.sleep(delay)
        last_request[0] = time.monotonic()
        return original_request(method, url, **kwargs)

    session.hooks.setdefault("response", []).append(inspect)
    session.request = guarded_request


def login_from_hub(account, hub):
    state = hub.ensure_open()
    owner = state.get("owner_uid")
    if not owner:
        raise HubError("Add your own account sessions in the hub first")
    records = hub.call("GET", "/api/sessions").get("sessions", [])
    if not isinstance(records, list) or not records:
        raise HubError("No sessions in the hub")
    protect_session(account.session, hub, owner)

    for record in records:
        if not isinstance(record, dict) or record.get("owner_uid") != owner:
            raise HubError("Unexpected account in hub; stopped")
        values = hub.call("POST", f"/api/sessions/{record['id']}/checkout")
        if values.get("owner_uid") != owner:
            raise HubError("Session account mismatch")
        cookie = {}
        for item in values.get("cookie", "").split(";"):
            if "=" in item:
                key, val = item.strip().split("=", 1)
                cookie[key.strip()] = val.strip()
        if cookie.get("c_user") != owner:
            raise HubError("Cookie account mismatch")

        account.cookie_dict = cookie
        account.session.cookies.clear()
        account.session.cookies.update(cookie)
        account.token_eaag = account.token_eaat = None
        token = values.get("access_token")
        verified = account._verify(token) if token else None
        if verified:
            account.token_eaag = account.token_eaat = token
        else:
            # Retain the original script's own-account token discovery.
            account.get_eaag()
            if not account.token_eaag:
                account.get_eaat()
            token = account.token_eaag or account.token_eaat
            verified = account._verify(token) if token else None

        if verified:
            if str(verified[1]) != owner:
                raise HubError("Verified account does not match vault owner")
            account.token_eaag = account.token_eaag or token
            account.token_eaat = account.token_eaat or token
            print(f"  [✓] HUB LOGIN VERIFIED :: {owner}")
            return verified

    raise HubError(
        "No session verified. Add a valid own-account access token in the hub "
        "or run your original script for manual login."
    )


def install_hub_login(account_class, hub):
    original_init = account_class.__init__

    def initialize(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        # Legacy menus sometimes verify cached tokens directly instead of
        # calling check(). Force their existing login path through the hub.
        self.token_eaag = self.token_eaat = None
        self.cookie_dict = {}
        self.session.cookies.clear()

    account_class.__init__ = initialize
    account_class.check = lambda self: login_from_hub(self, hub)
    account_class.login = account_class.check
