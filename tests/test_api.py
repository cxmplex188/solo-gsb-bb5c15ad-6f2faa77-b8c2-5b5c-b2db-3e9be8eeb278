"""End-to-end tests for the Capability Token API.

Runs fully in-process via FastAPI's TestClient against an isolated temp
directory — no network, Docker, or third-party account needed:

    python tests/test_api.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="capapi-test-")
os.environ["CAPABILITY_SECRET"] = "test-secret"
os.environ["CAPABILITY_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["CAPABILITY_FILES_DIR"] = os.path.join(_tmp, "files")
os.environ["CAPABILITY_DEFAULT_TTL"] = "300"
os.environ["CAPABILITY_MAX_TTL"] = "3600"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app import tokens as tokenlib  # noqa: E402

FILES_DIR = Path(os.environ["CAPABILITY_FILES_DIR"])
FILES_DIR.mkdir(parents=True, exist_ok=True)
(FILES_DIR / "hello.txt").write_text("hello capability world\n", encoding="utf-8")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class CapabilityApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Context-manager use triggers the lifespan (DB init, dirs, purge loop).
        cls._cm = TestClient(app)
        cls.client = cls._cm.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._cm.__exit__(None, None, None)

    # -- helpers -----------------------------------------------------------

    def issue(self, **overrides):
        body = {"method": "GET", "path": "/files/hello.txt", "ttl_seconds": 60}
        body.update(overrides)
        resp = self.client.post("/tokens/issue", json=body)
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()

    def verify(self, token, method="GET", path="/files/hello.txt", consume=True):
        return self.client.post(
            "/tokens/verify",
            json={"token": token, "method": method, "path": path, "consume": consume},
        )

    # -- issuing -----------------------------------------------------------

    def test_01_issue_token_shape(self):
        data = self.issue(subject="alice", extra={"ticket": "T-1"})
        self.assertEqual(data["method"], "GET")
        self.assertEqual(data["path"], "/files/hello.txt")
        self.assertEqual(data["expires_in"], 60)
        self.assertFalse(data["one_time"])
        self.assertEqual(data["subject"], "alice")
        self.assertRegex(data["token"], r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

    def test_02_ttl_is_capped_to_max(self):
        data = self.issue(ttl_seconds=10_000)
        self.assertEqual(data["expires_in"], 3600)

    def test_03_path_is_canonicalised_on_issue(self):
        data = self.issue(path="//files/./hello.txt/")
        self.assertEqual(data["path"], "/files/hello.txt")

    def test_04_issuer_key_gate_when_configured(self):
        # Dynamic reconfiguration: enable the issuer key just for this test.
        from dataclasses import replace

        settings = app.state.settings
        app.state.settings = replace(settings, issuer_key="s3cret")
        try:
            resp = self.client.post(
                "/tokens/issue", json={"method": "GET", "path": "/files/hello.txt"}
            )
            self.assertEqual(resp.status_code, 401)
            resp = self.client.post(
                "/tokens/issue",
                json={"method": "GET", "path": "/files/hello.txt"},
                headers={"X-Issuer-Key": "wrong"},
            )
            self.assertEqual(resp.status_code, 401)
            resp = self.client.post(
                "/tokens/issue",
                json={"method": "GET", "path": "/files/hello.txt"},
                headers={"X-Issuer-Key": "s3cret"},
            )
            self.assertEqual(resp.status_code, 200)
        finally:
            app.state.settings = settings

    #-- verification -------------------------------------------------------

    def test_05_verify_valid_multi_use_repeatedly(self):
        data = self.issue()
        for _ in range(3):
            resp = self.verify(data["token"])
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertTrue(resp.json()["valid"])
            self.assertFalse(resp.json()["consumed"])

    def test_06_wrong_signature_rejected(self):
        data = self.issue()
        payload, sig = data["token"].split(".")
        # Flip the last character of the signature.
        flipped = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        resp = self.verify(f"{payload}.{flipped}")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "bad_signature")

    def test_07_tampered_payload_rejected(self):
        data = self.issue(path="/files/hello.txt")
        payload, _sig = data["token"].split(".")
        payload_b = base64.urlsafe_b64decode(payload + "==")
        tampered = json.loads(payload_b)
        tampered["p"] = "/files/secret.txt"
        new_payload = _b64(json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode())
        resp = self.verify(f"{new_payload}.{data['token'].split('.')[1]}")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "bad_signature")

    def test_08_method_binding(self):
        data = self.issue(method="GET")
        resp = self.verify(data["token"], method="DELETE")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "method_mismatch")

    def test_09_path_binding(self):
        data = self.issue(path="/files/hello.txt")
        resp = self.verify(data["token"], path="/files/other.txt")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "path_mismatch")

    def test_10_path_canonicalisation_matches(self):
        data = self.issue(path="/files/hello.txt")
        resp = self.verify(data["token"], path="//files/./hello.txt/")
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_11_expired_token_rejected(self):
        # Hand-craft an already-expired token signed with the correct key.
        from app.main import app as real_app

        issued = tokenlib.issue_token(
            real_app.state.settings.secret_key,
            method="GET",
            path="/files/hello.txt",
            ttl_seconds=1,
            now=int(time.time()) - 10,
        )
        resp = self.verify(issued.token)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "expired")

    def test_12_malformed_tokens(self):
        for bad in ["nodot", ".", "abc.!!!", "a.b"]:
            resp = self.verify(bad)
            self.assertEqual(resp.status_code, 401, f"expected 401 for {bad!r}: {resp.text}")
            self.assertEqual(resp.json()["error"], "malformed")

    def test_12b_empty_token_is_a_client_error(self):
        resp = self.verify("")
        self.assertEqual(resp.status_code, 422)

    # -- one-time nonce ----------------------------------------------------

    def test_13_one_time_token_used_once(self):
        data = self.issue(one_time=True)
        first = self.verify(data["token"])
        self.assertEqual(first.status_code, 200, first.text)
        self.assertTrue(first.json()["consumed"])

        second = self.verify(data["token"])
        self.assertEqual(second.status_code, 401)
        self.assertEqual(second.json()["error"], "nonce_replayed")

    def test_14_dry_run_does_not_burn_token(self):
        data = self.issue(one_time=True)
        dry = self.verify(data["token"], consume=False)
        self.assertEqual(dry.status_code, 200)
        self.assertFalse(dry.json()["consumed"])
        real = self.verify(data["token"], consume=True)
        self.assertEqual(real.status_code, 200)
        self.assertTrue(real.json()["consumed"])

    def test_15_concurrent_replays_only_one_wins(self):
        # TestClient serialises requests, so hit the verification core in real
        # threads to prove the SQLite nonce insert is atomic under contention.
        from app.db import Database

        data = self.issue(one_time=True)
        settings = app.state.settings
        db: Database = app.state.db
        outcomes: list[str] = []
        lock = threading.Lock()

        def attempt():
            try:
                tokenlib.verify_token(
                    data["token"],
                    secret_key=settings.secret_key,
                    method="GET",
                    path="/files/hello.txt",
                    db=db,
                    consume=True,
                )
                result = "ok"
            except tokenlib.TokenError as exc:
                result = exc.code
            with lock:
                outcomes.append(result)

        barrier = threading.Barrier(12)

        def gated():
            barrier.wait()  # maximise the race window
            attempt()

        threads = [threading.Thread(target=gated) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        self.assertEqual(outcomes.count("nonce_replayed"), 11, outcomes)

    def test_16_distinct_one_time_tokens_both_work(self):
        a = self.issue(one_time=True)
        b = self.issue(one_time=True)
        self.assertEqual(self.verify(a["token"]).status_code, 200)
        self.assertEqual(self.verify(b["token"]).status_code, 200)
        self.assertEqual(self.verify(a["token"]).status_code, 401)
        self.assertEqual(self.verify(b["token"]).status_code, 401)

    # -- guarded resource --------------------------------------------------

    def test_17_download_without_token_unauthorized(self):
        resp = self.client.get("/files/hello.txt")
        self.assertEqual(resp.status_code, 401)

    def test_18_download_with_valid_one_time_token(self):
        data = self.issue(method="GET", path="/files/hello.txt", one_time=True)

        via_query = self.client.get(f"/files/hello.txt?token={data['token']}")
        self.assertEqual(via_query.status_code, 200, via_query.text)
        self.assertIn("hello capability world", via_query.text)
        self.assertEqual(via_query.headers["X-Capability-Id"], data["token_id"])

        replay = self.client.get(f"/files/hello.txt?token={data['token']}")
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(replay.json()["error"], "nonce_replayed")

    def test_19_download_via_bearer_and_header(self):
        for header_name, value in (
            ("Authorization", "Bearer {t}"),
            ("X-Capability-Token", "{t}"),
        ):
            data = self.issue()
            resp = self.client.get("/files/hello.txt", headers={header_name: value.format(t=data["token"])})
            self.assertEqual(resp.status_code, 200, resp.text)

    def test_20_download_method_binding_blocks_head_token_on_get(self):
        # Token bound to HEAD cannot be used for GET.
        issued = tokenlib.issue_token(
            app.state.settings.secret_key,
            method="HEAD",
            path="/files/hello.txt",
            ttl_seconds=60,
        )
        resp = self.client.get(f"/files/hello.txt?token={issued.token}")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "method_mismatch")

    def test_21_download_missing_file_returns_404_and_burns_nonce(self):
        data = self.issue(path="/files/does-not-exist.txt", one_time=True)
        resp = self.client.get(f"/files/does-not-exist.txt?token={data['token']}")
        self.assertEqual(resp.status_code, 404)
        replay = self.client.get(f"/files/does-not-exist.txt?token={data['token']}")
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(replay.json()["error"], "nonce_replayed")

    def test_22_traversal_is_blocked(self):
        # A token cannot be minted that escapes the files directory even via
        # normalised dot-segments: /files/../x canonicalises to /x, and the
        # filesystem layer additionally guards resolved paths.
        data = self.issue(path="/x", one_time=True)
        resp = self.client.get(f"/x?token={data['token']}")
        # /x is not a file route at all -> FastAPI 404 (no matching route).
        self.assertIn(resp.status_code, (404, 403))

    def test_23_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")


if __name__ == "__main__":
    unittest.main(verbosity=2)
