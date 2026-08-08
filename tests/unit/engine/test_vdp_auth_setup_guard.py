"""
SGK-2026-0433 — sealed auth-setup guard + provisioning tests.

Covers the sealed auth-setup capability (tests/fixtures/vdp_juiceshop_sealed/):
- AuthSetupGuard fail-closed: only the config's A/B register/login specs may
  send; any other method/path/body shape raises AuthSetupRejected BEFORE the
  transport is invoked (never sends).
- Default transport no-redirect: any 3xx raises AuthSetupError before a
  second request could be made; response URL must equal the requested URL.
- Provisioning: register→login captures the session token from the configured
  JSON path; already-exists register falls back to login; ids are generated
  when the environment provides none; partial credential pairs fail closed.
- Redaction: full-provisioning stdout/stderr contains no credential/token
  values; error messages never include response bodies; the session env file
  holds exactly the 4 VDP_ACCOUNT_* vars, is chmod 0600, and is written
  atomically (no temp leftovers).
- Config schema validation rejects malformed configs.
- Fail-closed CLI: provisioning failure exits non-zero.

These tests are communication-free: they use an injectable fake transport and
never talk to any real target.
"""
from __future__ import annotations

import importlib.util
import json
import stat
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parents[3]
AUTH_SETUP_PATH = (
    REPO_ROOT / "tests" / "fixtures" / "vdp_juiceshop_sealed" / "auth_setup.py"
)
CONFIG_PATH = (
    REPO_ROOT / "tests" / "fixtures" / "vdp_juiceshop_sealed" / "auth_setup_config.json"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("auth_setup", AUTH_SETUP_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AS = _load_module()
CONFIG = AS.load_config(str(CONFIG_PATH))

BODY_OK = {"email": "acct@example.com", "password": "pw-123456"}
LOGIN_TOKEN_A = {"authentication": {"token": "tok-a", "bid": 1, "umail": "a@example.com"}}
LOGIN_TOKEN_B = {"authentication": {"token": "tok-b", "bid": 2, "umail": "b@example.com"}}


class _Resp:
    def __init__(self, status, text):
        self.status = status
        self.text = text


class _FakeTransport:
    """Fake transport callable (auth_setup is stdlib-synchronous).

    Serves scripted responses keyed by request path (each entry is a queue
    popped per call) and records every request for assertions. The response
    objects expose ``status`` and ``text`` exactly like the real transport.
    """

    def __init__(self, routes=None, default=None):
        self.routes = {path: list(resps) for path, resps in (routes or {}).items()}
        self.default = default if default is not None else _Resp(500, '{"error":"no route"}')
        self.calls = []

    def __call__(self, req):
        self.calls.append(req)
        path = req["url"].split("://", 1)[1].split("/", 1)
        route = "/" + path[1] if len(path) == 2 and path[1] else "/"
        queue = self.routes.get(route)
        if queue:
            return queue.pop(0)
        return self.default

    @property
    def count(self):
        return len(self.calls)

    def body_json(self, index):
        return json.loads(self.calls[index]["body"].decode("utf-8"))

    def call_paths(self):
        return [req["url"] for req in self.calls]


def _make_guard(transport=None, cfg=None, base_url="http://target.local"):
    fake = transport if transport is not None else _FakeTransport()
    guard = AS.AuthSetupGuard(cfg or CONFIG, base_url=base_url, transport=fake)
    return guard, fake


def _clear_env(monkeypatch):
    for key in AS.ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


class TestAuthSetupGuardFailClosed:
    def test_rejects_non_allowlisted_post_path(self):
        guard, fake = _make_guard()
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("a", "register", "POST", "/api/Users/1", BODY_OK)
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("a", "login", "POST", "/rest/user/login?debug=1", BODY_OK)
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("a", "login", "POST", "/rest/admin", BODY_OK)
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("b", "register", "POST", "/api/Users/2", BODY_OK)
        assert fake.count == 0, "rejected requests must never reach the transport"

    def test_rejects_non_post_methods_on_allowlisted_path(self):
        guard, fake = _make_guard()
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            with pytest.raises(AS.AuthSetupRejected):
                guard.request("a", "login", method, "/rest/user/login", BODY_OK)
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("a", "register", "GET", "/api/Users", BODY_OK)
        assert fake.count == 0

    def test_rejects_extra_body_field(self):
        guard, fake = _make_guard()
        body = dict(BODY_OK, admin=True)
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("a", "login", "POST", "/rest/user/login", body)
        assert fake.count == 0

    def test_rejects_missing_body_field(self):
        guard, fake = _make_guard()
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("a", "login", "POST", "/rest/user/login", {"email": "x@y.z"})
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("a", "register", "POST", "/api/Users", {"password": "pw"})
        assert fake.count == 0

    def test_rejects_empty_or_non_string_body_values(self):
        guard, fake = _make_guard()
        with pytest.raises(AS.AuthSetupRejected):
            guard.request(
                "a", "login", "POST", "/rest/user/login", {"email": "", "password": "pw"}
            )
        with pytest.raises(AS.AuthSetupRejected):
            guard.request(
                "a", "login", "POST", "/rest/user/login", {"email": 42, "password": "pw"}
            )
        assert fake.count == 0

    def test_rejects_unknown_account_or_kind(self):
        guard, fake = _make_guard()
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("c", "login", "POST", "/rest/user/login", BODY_OK)
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("a", "delete", "POST", "/rest/user/login", BODY_OK)
        assert fake.count == 0

    def test_accepts_the_four_allowlisted_specs(self):
        fake = _FakeTransport()
        guard = AS.AuthSetupGuard(CONFIG, base_url="http://target.local", transport=fake)
        guard.request("a", "register", "POST", "/api/Users", BODY_OK)
        guard.request("a", "login", "POST", "/rest/user/login", BODY_OK)
        guard.request("b", "register", "POST", "/api/Users", BODY_OK)
        guard.request("b", "login", "POST", "/rest/user/login", BODY_OK)
        assert fake.count == 4
        assert fake.call_paths() == [
            "http://target.local/api/Users",
            "http://target.local/rest/user/login",
            "http://target.local/api/Users",
            "http://target.local/rest/user/login",
        ]
        # body serialized as JSON with exactly the configured field names
        first = fake.body_json(0)
        assert set(first) == {"email", "password"}
        assert all(req["method"] == "POST" for req in fake.calls)

    def test_trailing_slash_is_normalized(self):
        guard, fake = _make_guard()
        guard.request("a", "login", "POST", "/rest/user/login/", BODY_OK)
        assert fake.count == 1
        assert fake.calls[0]["url"] == "http://target.local/rest/user/login"

    def test_allowlist_shrinks_when_register_disallowed(self):
        cfg = json.loads(json.dumps(CONFIG))
        cfg["register"]["allowed"] = False
        guard, fake = _make_guard(cfg=cfg)
        assert sorted(s["kind"] for s in guard.allowlisted_specs) == ["login", "login"]
        with pytest.raises(AS.AuthSetupRejected):
            guard.request("a", "register", "POST", "/api/Users", BODY_OK)
        assert fake.count == 0


class TestProvisioning:
    def test_register_then_login_captures_token_from_json_path(self):
        routes = {
            "/rest/user/login": [
                _Resp(401, '{"error":"denied"}'),
                _Resp(200, json.dumps(LOGIN_TOKEN_A)),
                _Resp(401, '{"error":"denied"}'),
                _Resp(200, json.dumps(LOGIN_TOKEN_B)),
            ],
            "/api/Users": [_Resp(201, "{}"), _Resp(201, "{}")],
        }
        fake = _FakeTransport(routes=routes)
        guard = AS.AuthSetupGuard(CONFIG, base_url="http://target.local", transport=fake)
        env = {
            "VDP_ACCOUNT_A_ID": "a@example.com",
            "VDP_ACCOUNT_A_SECRET": "pw-a-123456",
            "VDP_ACCOUNT_B_ID": "b@example.com",
            "VDP_ACCOUNT_B_SECRET": "pw-b-123456",
        }
        records = AS.provision_accounts(CONFIG, guard, env)
        # SECRET is the session token from the login response, not the password
        assert records["a"] == {"id": "a@example.com", "token": "tok-a"}
        assert records["b"] == {"id": "b@example.com", "token": "tok-b"}
        assert records["a"]["token"] != env["VDP_ACCOUNT_A_SECRET"]
        # call order: login-a(denied), register-a, login-a, login-b(denied), register-b, login-b
        assert fake.call_paths() == [
            "http://target.local/rest/user/login",
            "http://target.local/api/Users",
            "http://target.local/rest/user/login",
            "http://target.local/rest/user/login",
            "http://target.local/api/Users",
            "http://target.local/rest/user/login",
        ]
        # register bodies carried the configured account id/secret field names
        reg_a = fake.body_json(1)
        assert reg_a == {"email": "a@example.com", "password": "pw-a-123456"}
        reg_b = fake.body_json(4)
        assert reg_b == {"email": "b@example.com", "password": "pw-b-123456"}

    def test_login_only_fallback_when_register_already_exists(self):
        routes = {
            "/rest/user/login": [
                _Resp(401, '{"error":"denied"}'),
                _Resp(200, json.dumps(LOGIN_TOKEN_A)),
                _Resp(401, '{"error":"denied"}'),
                _Resp(200, json.dumps(LOGIN_TOKEN_B)),
            ],
            "/api/Users": [_Resp(400, '{"error":"email already exists"}'), _Resp(400, '{"error":"email already exists"}')],
        }
        fake = _FakeTransport(routes=routes)
        guard = AS.AuthSetupGuard(CONFIG, base_url="http://target.local", transport=fake)
        env = {
            "VDP_ACCOUNT_A_ID": "a@example.com",
            "VDP_ACCOUNT_A_SECRET": "pw-a-123456",
            "VDP_ACCOUNT_B_ID": "b@example.com",
            "VDP_ACCOUNT_B_SECRET": "pw-b-123456",
        }
        records = AS.provision_accounts(CONFIG, guard, env)
        assert records["a"]["token"] == "tok-a"
        assert records["b"]["token"] == "tok-b"
        # login denied -> register (already-exists, no failure) -> login, per account
        assert fake.call_paths() == [
            "http://target.local/rest/user/login",
            "http://target.local/api/Users",
            "http://target.local/rest/user/login",
            "http://target.local/rest/user/login",
            "http://target.local/api/Users",
            "http://target.local/rest/user/login",
        ]

    def test_generated_ids_when_env_absent(self, monkeypatch):
        _clear_env(monkeypatch)
        routes = {
            "/rest/user/login": [
                _Resp(200, json.dumps(LOGIN_TOKEN_A)),
                _Resp(200, json.dumps(LOGIN_TOKEN_B)),
            ],
            "/api/Users": [_Resp(201, "{}"), _Resp(201, "{}")],
        }
        fake = _FakeTransport(routes=routes)
        guard = AS.AuthSetupGuard(CONFIG, base_url="http://target.local", transport=fake)
        records = AS.provision_accounts(CONFIG, guard, {})
        assert records["a"]["id"].startswith("vdp_a_")
        assert records["a"]["id"].endswith("@example.com")
        assert records["b"]["id"].startswith("vdp_b_")
        assert records["a"]["id"] != records["b"]["id"]
        assert records["a"]["token"] == "tok-a"
        assert records["b"]["token"] == "tok-b"
        # generated accounts were registered with the generated id + a secret
        # matching the config's id_factory shape
        reg_a = fake.body_json(0)
        assert reg_a["email"] == records["a"]["id"]
        assert len(reg_a["password"]) == CONFIG["id_factory"]["secret_length"]
        assert set(reg_a["password"]) <= set(CONFIG["id_factory"]["secret_charset"])
        assert fake.call_paths() == [
            "http://target.local/api/Users",
            "http://target.local/rest/user/login",
            "http://target.local/api/Users",
            "http://target.local/rest/user/login",
        ]

    def test_login_only_when_register_disallowed(self, monkeypatch):
        _clear_env(monkeypatch)
        cfg = json.loads(json.dumps(CONFIG))
        cfg["register"]["allowed"] = False
        routes = {
            "/rest/user/login": [
                _Resp(200, json.dumps(LOGIN_TOKEN_A)),
                _Resp(200, json.dumps(LOGIN_TOKEN_B)),
            ],
        }
        fake = _FakeTransport(routes=routes)
        guard = AS.AuthSetupGuard(cfg, base_url="http://target.local", transport=fake)
        env = {
            "VDP_ACCOUNT_A_ID": "a@example.com",
            "VDP_ACCOUNT_A_SECRET": "pw-a-123456",
            "VDP_ACCOUNT_B_ID": "b@example.com",
            "VDP_ACCOUNT_B_SECRET": "pw-b-123456",
        }
        records = AS.provision_accounts(cfg, guard, env)
        assert records["a"]["token"] == "tok-a"
        assert records["b"]["token"] == "tok-b"
        assert fake.call_paths() == [
            "http://target.local/rest/user/login",
            "http://target.local/rest/user/login",
        ]

    def test_login_denied_with_register_disallowed_raises(self, monkeypatch):
        _clear_env(monkeypatch)
        cfg = json.loads(json.dumps(CONFIG))
        cfg["register"]["allowed"] = False
        fake = _FakeTransport(
            routes={"/rest/user/login": [_Resp(401, '{"error":"denied"}')]}
        )
        guard = AS.AuthSetupGuard(cfg, base_url="http://target.local", transport=fake)
        env = {
            "VDP_ACCOUNT_A_ID": "a@example.com",
            "VDP_ACCOUNT_A_SECRET": "pw-a-123456",
            "VDP_ACCOUNT_B_ID": "b@example.com",
            "VDP_ACCOUNT_B_SECRET": "pw-b-123456",
        }
        with pytest.raises(AS.AuthSetupError):
            AS.provision_accounts(cfg, guard, env)

    def test_unexpected_register_status_raises(self, monkeypatch):
        _clear_env(monkeypatch)
        fake = _FakeTransport(
            routes={
                "/rest/user/login": [_Resp(401, '{"error":"denied"}')],
                "/api/Users": [_Resp(500, '{"error":"boom"}')],
            }
        )
        guard = AS.AuthSetupGuard(CONFIG, base_url="http://target.local", transport=fake)
        env = {"VDP_ACCOUNT_A_ID": "a@example.com", "VDP_ACCOUNT_A_SECRET": "pw-a-123456"}
        with pytest.raises(AS.AuthSetupError):
            AS.provision_accounts(CONFIG, guard, env)

    def test_login_response_without_token_path_raises(self, monkeypatch):
        _clear_env(monkeypatch)
        fake = _FakeTransport(
            routes={
                "/rest/user/login": [_Resp(200, '{"authentication": {"token": ""}}')],
                "/api/Users": [_Resp(201, "{}")],
            }
        )
        guard = AS.AuthSetupGuard(CONFIG, base_url="http://target.local", transport=fake)
        with pytest.raises(AS.AuthSetupError):
            AS.provision_accounts(CONFIG, guard, {})


class TestRedactionAndSessionEnv:
    def test_cli_output_never_contains_credentials_and_session_file_is_0600(
        self, tmp_path, capsys, monkeypatch
    ):
        _clear_env(monkeypatch)
        out = tmp_path / "session_env.txt"
        routes = {
            "/rest/user/login": [
                _Resp(200, json.dumps(LOGIN_TOKEN_A)),
                _Resp(200, json.dumps(LOGIN_TOKEN_B)),
            ],
            "/api/Users": [_Resp(201, "{}"), _Resp(201, "{}")],
        }
        fake = _FakeTransport(routes=routes)
        code = AS.main(
            ["--config", str(CONFIG_PATH), "--out", str(out), "--target", "http://target.local"],
            transport=fake,
        )
        assert code == 0
        captured = capsys.readouterr()

        # The session env file is the ONLY sink for values: learn them from it
        # and assert they never appeared in stdout/stderr.
        env_text = out.read_text(encoding="utf-8")
        lines = env_text.strip().splitlines()
        assert len(lines) == 4
        keys = sorted(line.split("=", 1)[0] for line in lines)
        assert keys == [
            "VDP_ACCOUNT_A_ID",
            "VDP_ACCOUNT_A_SECRET",
            "VDP_ACCOUNT_B_ID",
            "VDP_ACCOUNT_B_SECRET",
        ]
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
        values = [line.split("=", 1)[1] for line in lines]
        blob = captured.out + captured.err
        for value in values:
            assert value not in blob, f"credential leaked to output: {value!r}"
        # references may only appear as sha256 digests
        assert "sha256:" in captured.err

    def test_provisioning_against_fake_transport_never_echoes_provided_credentials(
        self, tmp_path, capsys, monkeypatch
    ):
        _clear_env(monkeypatch)
        monkeypatch.setenv("VDP_ACCOUNT_A_ID", "secret-id-a@example.com")
        monkeypatch.setenv("VDP_ACCOUNT_A_SECRET", "super-secret-pw-a")
        monkeypatch.setenv("VDP_ACCOUNT_B_ID", "secret-id-b@example.com")
        monkeypatch.setenv("VDP_ACCOUNT_B_SECRET", "super-secret-pw-b")
        routes = {
            "/rest/user/login": [
                _Resp(401, '{"error":"denied"}'),
                _Resp(200, json.dumps(LOGIN_TOKEN_A)),
                _Resp(401, '{"error":"denied"}'),
                _Resp(200, json.dumps(LOGIN_TOKEN_B)),
            ],
            "/api/Users": [_Resp(201, "{}"), _Resp(201, "{}")],
        }
        fake = _FakeTransport(routes=routes)
        out = tmp_path / "session_env.txt"
        code = AS.main(
            ["--config", str(CONFIG_PATH), "--out", str(out), "--target", "http://target.local"],
            transport=fake,
        )
        assert code == 0
        captured = capsys.readouterr()
        blob = captured.out + captured.err
        for value in (
            "secret-id-a@example.com",
            "super-secret-pw-a",
            "secret-id-b@example.com",
            "super-secret-pw-b",
            "tok-a",
            "tok-b",
        ):
            assert value not in blob, f"credential leaked to output: {value!r}"

    def test_error_message_omits_response_body(self, tmp_path, capsys, monkeypatch):
        _clear_env(monkeypatch)
        # server 500s on register and echoes the account id in the body; the
        # error message must carry status + fixed label only — no body excerpt
        fake = _FakeTransport(
            routes={
                "/rest/user/login": [_Resp(401, '{"error":"denied"}')],
                "/api/Users": [_Resp(500, '{"error":"boom","email":"echo-id-a@example.com"}')],
            }
        )
        guard = AS.AuthSetupGuard(CONFIG, base_url="http://target.local", transport=fake)
        env = {
            "VDP_ACCOUNT_A_ID": "echo-id-a@example.com",
            "VDP_ACCOUNT_A_SECRET": "pw-a-123456",
        }
        with pytest.raises(AS.AuthSetupError) as excinfo:
            AS.provision_accounts(CONFIG, guard, env)
        message = str(excinfo.value)
        assert "echo-id-a@example.com" not in message
        assert "pw-a-123456" not in message
        assert "boom" not in message, "response body must not be excerpted"
        assert "500" in message
        assert "response body omitted" in message

    def test_session_env_write_is_atomic_no_temp_leftovers(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        out = tmp_path / "session_env.txt"
        routes = {
            "/rest/user/login": [
                _Resp(200, json.dumps(LOGIN_TOKEN_A)),
                _Resp(200, json.dumps(LOGIN_TOKEN_B)),
            ],
            "/api/Users": [_Resp(201, "{}"), _Resp(201, "{}")],
        }
        fake = _FakeTransport(routes=routes)
        code = AS.main(
            ["--config", str(CONFIG_PATH), "--out", str(out), "--target", "http://target.local"],
            transport=fake,
        )
        assert code == 0
        # only the final file remains — the temp file was os.replace()d away
        assert sorted(p.name for p in tmp_path.iterdir()) == ["session_env.txt"]
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        keys = sorted(line.split("=", 1)[0] for line in lines)
        assert keys == [
            "VDP_ACCOUNT_A_ID",
            "VDP_ACCOUNT_A_SECRET",
            "VDP_ACCOUNT_B_ID",
            "VDP_ACCOUNT_B_SECRET",
        ]


class TestTransportNoRedirect:
    def test_no_redirect_handler_rejects_all_3xx_codes(self):
        handler = AS._NoRedirectHandler()
        req = urllib.request.Request(
            "http://target.local/rest/user/login",
            data=b'{"email":"a@example.com","password":"pw"}',
            method="POST",
        )
        for code in (301, 302, 303, 307, 308):
            with pytest.raises(AS.AuthSetupError) as excinfo:
                handler.redirect_request(req, None, code, "moved", {}, "http://evil.example/steal")
            assert "redirect not allowed" in str(excinfo.value)

    def test_default_transport_redirect_rejection_fails_provisioning(self, monkeypatch):
        # Simulates the no-redirect handler firing on a 307: the opener raises
        # AuthSetupError before any second request could be made.
        class _RedirectingOpener:
            def __init__(self):
                self.opens = 0

            def open(self, request, timeout=None):
                self.opens += 1
                raise AS.AuthSetupError(
                    "redirect not allowed (status 307) — refusing to follow "
                    "'http://evil.example/steal'"
                )

        req = {
            "method": "POST",
            "url": "http://target.local/rest/user/login",
            "headers": {"Content-Type": "application/json"},
            "body": b'{"email":"a@example.com","password":"pw"}',
            "timeout": 5,
        }
        opener = _RedirectingOpener()
        monkeypatch.setattr(AS, "_OPENER", opener)
        with pytest.raises(AS.AuthSetupError):
            AS._urllib_transport(req)
        assert opener.opens == 1, "no second request may follow a redirect"

        # full provisioning also fails closed (nothing after the first request)
        opener2 = _RedirectingOpener()
        monkeypatch.setattr(AS, "_OPENER", opener2)
        guard = AS.AuthSetupGuard(CONFIG, base_url="http://target.local", transport=AS._urllib_transport)
        with pytest.raises(AS.AuthSetupError):
            AS.provision_accounts(CONFIG, guard, {})
        assert opener2.opens == 1

    def test_default_transport_rejects_response_url_mismatch(self, monkeypatch):
        # Belt and braces: even a 2xx whose response URL differs from the
        # allowlisted request URL must fail closed.
        class _MismatchedResp:
            status = 200

            def geturl(self):
                return "http://evil.example/steal"

            def read(self):
                return b'{"ok":true}'

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class _MismatchOpener:
            def __init__(self):
                self.opens = 0

            def open(self, request, timeout=None):
                self.opens += 1
                return _MismatchedResp()

        opener = _MismatchOpener()
        monkeypatch.setattr(AS, "_OPENER", opener)
        with pytest.raises(AS.AuthSetupError) as excinfo:
            AS._urllib_transport(
                {
                    "method": "POST",
                    "url": "http://target.local/rest/user/login",
                    "headers": {"Content-Type": "application/json"},
                    "body": b'{"email":"a@example.com","password":"pw"}',
                    "timeout": 5,
                }
            )
        assert "url mismatch" in str(excinfo.value)
        assert opener.opens == 1


class TestPartialCredentialsFailClosed:
    @pytest.mark.parametrize(
        "env,missing_var",
        [
            ({"VDP_ACCOUNT_A_ID": "a@example.com"}, "VDP_ACCOUNT_A_SECRET"),
            ({"VDP_ACCOUNT_A_SECRET": "pw-a-123456"}, "VDP_ACCOUNT_A_ID"),
            (
                {
                    "VDP_ACCOUNT_A_ID": "a@example.com",
                    "VDP_ACCOUNT_A_SECRET": "pw-a-123456",
                    "VDP_ACCOUNT_B_ID": "b@example.com",
                },
                "VDP_ACCOUNT_B_SECRET",
            ),
            (
                {
                    "VDP_ACCOUNT_A_ID": "a@example.com",
                    "VDP_ACCOUNT_A_SECRET": "pw-a-123456",
                    "VDP_ACCOUNT_B_SECRET": "pw-b-123456",
                },
                "VDP_ACCOUNT_B_ID",
            ),
        ],
    )
    def test_partial_credential_pair_fails_closed(self, env, missing_var, monkeypatch):
        _clear_env(monkeypatch)
        fake = _FakeTransport(
            routes={"/rest/user/login": [_Resp(200, json.dumps(LOGIN_TOKEN_A))]}
        )
        guard = AS.AuthSetupGuard(CONFIG, base_url="http://target.local", transport=fake)
        with pytest.raises(AS.AuthSetupError) as excinfo:
            AS.provision_accounts(CONFIG, guard, env)
        assert missing_var in str(excinfo.value)
        if any(key.startswith("VDP_ACCOUNT_B_") for key in env):
            # account A provisions normally; the partial account B must never
            # have sent anything
            assert fake.call_paths() == ["http://target.local/rest/user/login"]
        else:
            assert fake.count == 0, "fail-closed: nothing may be sent with partial credentials"


class TestConfigSchema:
    def test_shipped_config_validates(self):
        normalized = AS.validate_config(CONFIG)
        assert normalized["token_scheme"] == "bearer"
        assert normalized["register"]["allowed"] is True

    def test_wrong_method_rejected(self):
        bad = json.loads(json.dumps(CONFIG))
        bad["register"]["method"] = "GET"
        with pytest.raises(AS.ConfigSchemaError):
            AS.validate_config(bad)

    def test_missing_path_rejected(self):
        bad = json.loads(json.dumps(CONFIG))
        del bad["login"]["path"]
        with pytest.raises(AS.ConfigSchemaError):
            AS.validate_config(bad)

    def test_missing_section_rejected(self):
        bad = json.loads(json.dumps(CONFIG))
        del bad["token_extraction"]
        with pytest.raises(AS.ConfigSchemaError):
            AS.validate_config(bad)

    def test_non_int_statuses_rejected(self):
        bad = json.loads(json.dumps(CONFIG))
        bad["login"]["success_statuses"] = ["200"]
        with pytest.raises(AS.ConfigSchemaError):
            AS.validate_config(bad)

    def test_empty_statuses_rejected(self):
        bad = json.loads(json.dumps(CONFIG))
        bad["register"]["already_exists_statuses"] = []
        with pytest.raises(AS.ConfigSchemaError):
            AS.validate_config(bad)

    def test_bad_token_scheme_rejected(self):
        bad = json.loads(json.dumps(CONFIG))
        bad["token_scheme"] = "basic"
        with pytest.raises(AS.ConfigSchemaError):
            AS.validate_config(bad)

    def test_bad_id_factory_pattern_rejected(self):
        bad = json.loads(json.dumps(CONFIG))
        bad["id_factory"]["account_id_pattern"] = "no-placeholders@example.com"
        with pytest.raises(AS.ConfigSchemaError):
            AS.validate_config(bad)

    def test_missing_already_exists_statuses_rejected(self):
        bad = json.loads(json.dumps(CONFIG))
        del bad["register"]["already_exists_statuses"]
        with pytest.raises(AS.ConfigSchemaError):
            AS.validate_config(bad)


class TestCliFailClosed:
    def test_provisioning_failure_exits_nonzero_and_writes_no_session_file(
        self, tmp_path, capsys, monkeypatch
    ):
        _clear_env(monkeypatch)
        out = tmp_path / "session_env.txt"
        fake = _FakeTransport(default=_Resp(500, '{"error":"server down"}'))
        code = AS.main(
            ["--config", str(CONFIG_PATH), "--out", str(out), "--target", "http://target.local"],
            transport=fake,
        )
        assert code != 0
        assert not out.exists(), "fail-closed: no session env file on failure"
        captured = capsys.readouterr()
        assert "FAILED" in captured.err

    def test_missing_config_file_exits_nonzero(self, tmp_path, capsys):
        code = AS.main(
            [
                "--config",
                str(tmp_path / "does_not_exist.json"),
                "--out",
                str(tmp_path / "session_env.txt"),
                "--target",
                "http://target.local",
            ]
        )
        assert code == 2
        captured = capsys.readouterr()
        assert "config error" in captured.err
