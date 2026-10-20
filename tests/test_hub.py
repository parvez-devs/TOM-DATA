import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from cookie_hub.app import Credential, create_app
from hub_client import HubClient, HubRestricted, login_from_hub, protect_session, install_hub_login


CONFIG = {
    "TESTING": True, "DATABASE_URL": "sqlite://",
    "HUB_ADMIN_TOKEN": "a" * 40,
    "HUB_CLIENT_TOKEN": "b" * 40,
    "ENCRYPTION_SECRET": "c" * 40,
    "SESSION_COOKIE_SECURE": False,
}


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(CONFIG)
        self.client = self.app.test_client()
        self.admin = {"Authorization": "Bearer " + CONFIG["HUB_ADMIN_TOKEN"]}
        self.worker = {"Authorization": "Bearer " + CONFIG["HUB_CLIENT_TOKEN"]}

    def tearDown(self):
        self.app.extensions["vault_engine"].dispose()

    def add(self, uid="123", label="Own session"):
        return self.client.post("/api/sessions", headers=self.admin, json={
            "owned": True,
            "sessions": [{"label": label, "cookie": f"c_user={uid}; xs=PRIVATE_COOKIE",
                          "access_token": "PRIVATE_TOKEN"}],
        })

    def test_authentication_and_roles(self):
        self.assertEqual(self.client.get("/api/sessions").status_code, 401)
        denied = self.client.post("/api/sessions", headers=self.worker, json={})
        self.assertEqual(denied.status_code, 403)

    def test_ciphertext_and_metadata_only_listing(self):
        self.assertEqual(self.add().status_code, 201)
        body = self.client.get("/api/sessions", headers=self.worker).get_data(as_text=True)
        self.assertNotIn("PRIVATE_COOKIE", body)
        self.assertNotIn("PRIVATE_TOKEN", body)
        factory = self.app.extensions["vault_db"]
        with factory() as db:
            row = db.query(Credential).one()
            self.assertNotIn("PRIVATE_COOKIE", row.sealed)
            self.assertNotIn("PRIVATE_TOKEN", row.sealed)
        sid = json.loads(body)["sessions"][0]["id"]
        payload = self.client.post(
            f"/api/sessions/{sid}/checkout", headers=self.worker
        ).json
        self.assertEqual(payload["access_token"], "PRIVATE_TOKEN")

    def test_different_account_rejected(self):
        self.add()
        self.assertEqual(self.add("456").status_code, 409)

    def test_batch_is_atomic(self):
        response = self.client.post("/api/sessions", headers=self.admin, json={
            "owned": True, "sessions": [
                {"cookie": "c_user=123; xs=one"},
                {"cookie": "c_user=456; xs=two"},
            ]
        })
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.client.get(
            "/api/sessions", headers=self.worker
        ).json["sessions"], [])

    def test_halt_denies_checkout_and_client_cannot_resume(self):
        sid = self.add().json["ids"][0]
        self.assertEqual(self.client.post(
            "/api/halt", headers=self.worker, json={"code": 368}
        ).status_code, 200)
        self.assertTrue(self.client.get("/api/state", headers=self.worker).json["blocked"])
        self.assertEqual(self.client.post(
            f"/api/sessions/{sid}/checkout", headers=self.worker
        ).status_code, 423)
        self.assertEqual(self.client.post("/resume", headers=self.worker).status_code, 401)

    def test_admin_form_needs_csrf(self):
        self.client.get("/")
        response = self.client.post("/", data={"token": CONFIG["HUB_ADMIN_TOKEN"]})
        self.assertEqual(response.status_code, 403)

    def test_ownership_confirmation_required(self):
        self.assertEqual(self.client.post(
            "/api/sessions", headers=self.admin, json={"sessions": []}
        ).status_code, 400)

    def test_pause_persists_across_app_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {**CONFIG, "DATABASE_URL": "sqlite:///" + str(Path(directory) / "vault.db")}
            first = create_app(config)
            first.test_client().post("/api/halt", headers=self.worker, json={"code": 368})
            first.extensions["vault_engine"].dispose()
            second = create_app(config)
            self.assertTrue(second.test_client().get(
                "/api/state", headers=self.worker
            ).json["blocked"])
            second.extensions["vault_engine"].dispose()

    def test_cache_headers(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")


class ClientTests(unittest.TestCase):
    def test_legacy_saved_tokens_cannot_skip_hub(self):
        class Account:
            def __init__(self):
                self.session = Mock()
                self.token_eaag = "old"
                self.token_eaat = "old"
                self.cookie_dict = {"c_user": "old"}
        install_hub_login(Account, Mock())
        account = Account()
        self.assertIsNone(account.token_eaag)
        self.assertIsNone(account.token_eaat)
        self.assertEqual(account.cookie_dict, {})
        account.session.cookies.clear.assert_called_once()

    def test_restriction_prevents_next_cookie(self):
        account = Mock()
        account._verify.side_effect = HubRestricted("368")
        hub = Mock()
        hub.ensure_open.return_value = {"owner_uid": "123", "blocked": False}
        hub.call.side_effect = [
            {"sessions": [{"id": "one", "owner_uid": "123"},
                          {"id": "two", "owner_uid": "123"}]},
            {"owner_uid": "123", "cookie": "c_user=123; xs=one",
             "access_token": "one"},
        ]
        with self.assertRaises(HubRestricted):
            login_from_hub(account, hub)
        checkout_calls = [call for call in hub.call.call_args_list
                          if "/checkout" in call.args[1]]
        self.assertEqual(len(checkout_calls), 1)

    def test_response_368_trips_global_pause(self):
        import requests
        session = requests.Session()
        hub = Mock()
        hub.trip.side_effect = HubRestricted("368")
        protect_session(session, hub, "123")
        response = requests.Response()
        response.status_code = 400
        response._content = b'{"error":{"code":368}}'
        response.url = "https://graph.facebook.com/me"
        with self.assertRaises(HubRestricted):
            session.hooks["response"][-1](response)
        hub.trip.assert_called_once_with(368)

    def test_local_pause_survives_halt_network_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            client = HubClient("https://example.com", "secret", Path(directory) / "pause")
            client.call = Mock(side_effect=RuntimeError("unreachable"))
            # Simulate a normal transport failure from the hub client.
            from hub_client import HubError
            client.call.side_effect = HubError("unreachable")
            with self.assertRaises(HubRestricted):
                client.trip(368)
            self.assertTrue(client.pause_file.exists())
            with self.assertRaises(HubRestricted):
                client.ensure_open()


if __name__ == "__main__":
    unittest.main()
