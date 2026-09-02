"""
SGK-2026-0467: cross-account BOLA confirmation (authB matrix) tests.

The 3-way auth context matrix (unauth / authA / authB) is finalized before
the new cross-account block runs. The block fires ONLY when both the primary
account (authA) and a second account (authB) succeed on the same protected
resource while the unauthenticated request is denied, and the two
authenticated bodies are structurally correlated. It is opt-in via
``idor_cross_account_confirm_enabled`` (default False); with no authB wired
it is a complete no-op.

Test design (mirrors tests/fixtures/vdp_authz_multiuser_app/app.py semantics
with a RECORDING fake request client, because the manager makes a variable
number of requests):

- ``Authorization: Bearer token-a`` (authA, primary) on /api/records/2
  -> 200 (viewer = user-a); ``X-Auth-Token: token-b`` (authB) on
  /api/records/2 -> 200 (viewer = user-b); no token -> 401.
- SECURE mode (negative control): token-a on /api/records/2 -> 403.
- any valid token on other /api/records/N -> 200 (object A/B probes).

The manager's "unauth" probe strips only Authorization/Cookie headers, so the
primary auth (authA) uses ``Authorization: Bearer token-a`` (making the
unauth probe genuinely token-less) and the second account uses the
``X-Auth-Token`` header.
"""
import json
import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.config.settings import Settings
from src.core.models.finding import VulnType

# monkeypatch 前に本来の get_settings を捕捉（再帰回避）
import src.core.config.settings as _settings_mod  # noqa: E402

_ORIG_GET_SETTINGS = _settings_mod.get_settings

URL_RECORDS_2 = "http://127.0.0.1:9/api/records/2"

_TOKENS = {
    "token-a": "user-a",
    "token-b": "user-b",
}

_RECORDS = {
    1: {"owner": "user-a", "note": "account-a private note alpha"},
    2: {"owner": "user-b", "note": "account-b private note beta"},
    3: {"owner": "user-a", "note": "account-a private note gamma"},
}


def _settings_flag(flag: bool):
    """get_settings() のモンキーパッチ用: 実 settings を維持しつつ
    idor_cross_account_confirm_enabled のみ上書きする（他フィールド参照を
    壊さない）。get_proxy_url も実 settings へ委譲する。"""
    real = _ORIG_GET_SETTINGS()
    return SimpleNamespace(
        idor_cross_account_confirm_enabled=flag,
        llm=getattr(real, "llm", None),
        get_proxy_url=lambda: getattr(real, "get_proxy_url", lambda: "")(),
    )


def _resolve_user(headers):
    """ヘッダからユーザーを解決する（authB は X-Auth-Token、authA は
    Bearer）。どちらも無ければ unauthenticated (None)。"""
    headers = {str(k): v for k, v in (headers or {}).items()}
    raw = ""
    for name, value in headers.items():
        if str(name).lower() == "x-auth-token":
            raw = str(value)
            break
    if not raw:
        for name, value in headers.items():
            if str(name).lower() == "authorization":
                bearer = str(value)
                break
        else:
            bearer = ""
        if bearer.lower().startswith("bearer "):
            raw = bearer[7:]
    return _TOKENS.get(str(raw or "").strip())


def _record_body(item_id: int, user: str) -> str:
    rec = _RECORDS[item_id]
    return json.dumps(
        {
            "status": "success",
            "id": item_id,
            "owner": rec["owner"],
            "note": rec["note"],
            "viewer": user,
        }
    )


def _make_request_fake(requests: list, *, secure: bool = False):
    """RECORDING fake for request_client.request.

    Mirrors the semantics of tests/fixtures/vdp_authz_multiuser_app:
    /api/records/2 requires a valid token (401 when absent) and returns the
    record for ANY valid token (the BOLA flavor) unless secure=1 (403 when
    the caller is not the owner). Any valid token on another record -> 200
    (object A/B probes). All methods/URLs are handled so the manager's
    variable-length request sequence never breaks; the sealed path only ever
    sees this mocked client, so every request lands here.
    """
    async def fake_request(*, method="GET", url="", headers=None, **kwargs):
        requests.append({"method": method, "url": url, "headers": dict(headers or {})})
        headers = dict(headers or {})
        user = _resolve_user(headers)
        if str(method).upper() == "OPTIONS":
            return SimpleNamespace(
                status=200, body="", headers={"Allow": "GET,OPTIONS"}
            )
        if str(method).upper() not in {"GET"}:
            return SimpleNamespace(
                status=404, body='{"status":"not_found"}', headers={}
            )
        match = re.search(r"/api/records/(\d+)", str(url or ""))
        if not match:
            return SimpleNamespace(
                status=404, body='{"status":"not_found"}', headers={}
            )
        item_id = int(match.group(1))
        if user is None:
            return SimpleNamespace(
                status=401,
                body='{"status":"unauthorized"}',
                headers={"Content-Type": "application/json"},
            )
        if secure and item_id == 2 and user != "user-b":
            return SimpleNamespace(
                status=403,
                body=json.dumps({"status": "forbidden", "id": 2}),
                headers={"Content-Type": "application/json"},
            )
        return SimpleNamespace(
            status=200,
            body=_record_body(item_id, user),
            headers={"Content-Type": "application/json"},
        )

    return fake_request


def _make_manager(fake_request) -> InjectionManagerAgent:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}
    request_client = MagicMock()
    request_client.request = fake_request
    manager._resolve_request_client = MagicMock(return_value=request_client)
    return manager


def _cross_account_findings(manager) -> list:
    findings = manager.current_context.get("findings", [])
    return [
        f
        for f in findings
        if (isinstance(f.additional_info, dict) and f.additional_info.get("detection_class") == "cross_account_bola")
    ]


@pytest.mark.asyncio
async def test_cross_account_bola_confirmed_vuln(monkeypatch):
    """Flag ON + authB wired + both accounts succeed + unauth denied
    -> exactly one cross_account_bola finding that is payout-grade."""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True))
    requests: list = []
    manager = _make_manager(_make_request_fake(requests))
    base_params = {
        "_auth": {
            "auth_headers": {"Authorization": "Bearer token-a"},
            "cookies": "",
            "auth_b_headers": {"X-Auth-Token": "token-b"},
            "auth_b_role": "user-b",
        }
    }
    result = await manager._run_api_minimal_check(URL_RECORDS_2, base_params)

    assert result["findings_count"] >= 1
    cross_findings = _cross_account_findings(manager)
    assert len(cross_findings) == 1
    finding = cross_findings[0]

    assert finding.vuln_type == VulnType.IDOR
    assert finding.title.startswith("Cross-Account Object Access")
    assert finding.additional_info["second_account_compared"] is True
    assert finding.additional_info["cross_account_compared"] is True
    authz = finding.additional_info["authz_differential"]
    assert isinstance(authz, dict)
    assert "auth_success" in authz["signals"]
    assert "unauth_success" in authz["signals"]
    assert finding.additional_info["auth_status"] == 200
    assert finding.additional_info["unauth_status"] == 401
    assert finding.impact and "different account" in finding.impact
    assert isinstance(finding.reproduction_steps, list)
    assert len(finding.reproduction_steps) == 3

    # authB (X-Auth-Token: token-b) really reached the client.
    assert any(str(r["headers"].get("X-Auth-Token", "")) == "token-b" for r in requests)

    # Deterministic payout-grade gate (SGK-2026-0441): reproducible req/res +
    # authz_diff firing marker + impact -> payout_grade True.
    from src.core.agents.swarm.injection.payout_grade import (
        evaluate_payout_grade,
        finding_payload,
    )

    grade = evaluate_payout_grade(finding_payload(finding))
    assert grade.payout_grade is True
    assert grade.reason == "payout_grade_satisfied"
    assert grade.marker == "authz_diff"


@pytest.mark.asyncio
async def test_cross_account_bola_secure_negative_control(monkeypatch):
    """SECURE mode: authA (token-a) is 403 on /api/records/2 -> the confirmed
    cross-account signal must NOT fire (ownership is enforced)."""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True))
    manager = _make_manager(_make_request_fake([], secure=True))
    base_params = {
        "_auth": {
            "auth_headers": {"Authorization": "Bearer token-a"},
            "cookies": "",
            "auth_b_headers": {"X-Auth-Token": "token-b"},
            "auth_b_role": "user-b",
        }
    }
    result = await manager._run_api_minimal_check(URL_RECORDS_2, base_params)

    assert _cross_account_findings(manager) == []
    matrix_signals = result["auth_context_matrix"].get("signals", [])
    assert "authA_authB_both_success" not in matrix_signals


@pytest.mark.asyncio
async def test_cross_account_bola_custom_header_confirmed_vuln(monkeypatch):
    """SGK-2026-0468: authA が独自ヘッダ（X-Auth-Token）認証でも cross-account
    確定が発火する。共有 narrow strip は X-Auth-Token を剥がせず unauth も 200 に
    なるためマトリクスに境界が立たないが、広域剥離プローブ（token 無し → 401）で
    境界が確立 → cross_account finding 1 件・payout_grade True（marker=authz_diff）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True))
    requests: list = []
    manager = _make_manager(_make_request_fake(requests))
    base_params = {
        "_auth": {
            "auth_headers": {"X-Auth-Token": "token-a"},
            "cookies": "",
            "auth_b_headers": {"X-Auth-Token": "token-b"},
            "auth_b_role": "user-b",
        }
    }
    result = await manager._run_api_minimal_check(URL_RECORDS_2, base_params)

    assert result["findings_count"] >= 1
    cross_findings = _cross_account_findings(manager)
    assert len(cross_findings) == 1
    finding = cross_findings[0]

    assert finding.vuln_type == VulnType.IDOR
    assert finding.title.startswith("Cross-Account Object Access")
    assert finding.additional_info["auth_status"] == 200
    # 共有 unauth プローブは X-Auth-Token を保持するため 200 のまま（既存 finding
    # ブロックは無改変・境界の確定は広域剥離プローブの判定のみが担う）。
    assert finding.additional_info["unauth_status"] == 200

    # マトリクス上では境界が立たない（共有 narrow strip は X-Auth-Token を残す）。
    matrix_signals = result["auth_context_matrix"].get("signals", [])
    assert "auth_boundary_observed" not in matrix_signals

    # 広域剥離プローブが走った: URL への GET のうち空ヘッダ（真に未認証）は
    # 広域剥離の 1 本のみ（共有 narrow unauth は X-Auth-Token を残す）。
    url_gets = [r for r in requests if r["method"] == "GET" and r["url"] == URL_RECORDS_2]
    assert sum(1 for r in url_gets if not r["headers"]) == 1
    assert any(
        "X-Auth-Token" not in {str(k): v for k, v in r["headers"].items()}
        for r in url_gets
    )

    from src.core.agents.swarm.injection.payout_grade import (
        evaluate_payout_grade,
        finding_payload,
    )

    grade = evaluate_payout_grade(finding_payload(finding))
    assert grade.payout_grade is True
    assert grade.marker == "authz_diff"


@pytest.mark.asyncio
async def test_cross_account_bola_custom_header_secure_negative_control(monkeypatch):
    """SGK-2026-0468 SECURE 負コントロール: authA が独自ヘッダ（X-Auth-Token:
    token-a）でも owner でないため /api/records/2 は 403 → authA_authB_both_success
    不成立 → cross_account finding 0 件（広域プローブも走らない）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True))
    requests: list = []
    manager = _make_manager(_make_request_fake(requests, secure=True))
    base_params = {
        "_auth": {
            "auth_headers": {"X-Auth-Token": "token-a"},
            "cookies": "",
            "auth_b_headers": {"X-Auth-Token": "token-b"},
            "auth_b_role": "user-b",
        }
    }
    result = await manager._run_api_minimal_check(URL_RECORDS_2, base_params)

    assert _cross_account_findings(manager) == []
    matrix_signals = result["auth_context_matrix"].get("signals", [])
    assert "authA_authB_both_success" not in matrix_signals
    # authA が 403 のため広域剥離プローブは発行されない（空ヘッダ GET は 0 本）。
    url_gets = [r for r in requests if r["method"] == "GET" and r["url"] == URL_RECORDS_2]
    assert sum(1 for r in url_gets if not r["headers"]) == 0


@pytest.mark.asyncio
async def test_cross_account_bola_bearer_no_extra_broad_probe(monkeypatch):
    """SGK-2026-0468 非回帰: Authorization: Bearer authA の既存ケース（0467
    test 1 相当）は従来どおり確定し、広域剥離プローブは走らない（マトリクスで
    既に境界が立ち、広域剥離結果も narrow と等しい）。URL への GET は
    authA/unauth/authB の 3 本のまま。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True))
    requests: list = []
    manager = _make_manager(_make_request_fake(requests))
    base_params = {
        "_auth": {
            "auth_headers": {"Authorization": "Bearer token-a"},
            "cookies": "",
            "auth_b_headers": {"X-Auth-Token": "token-b"},
            "auth_b_role": "user-b",
        }
    }
    result = await manager._run_api_minimal_check(URL_RECORDS_2, base_params)

    assert result["findings_count"] >= 1
    cross_findings = _cross_account_findings(manager)
    assert len(cross_findings) == 1
    assert "auth_boundary_observed" in result["auth_context_matrix"].get("signals", [])

    # 追加の広域プローブは発行されない（リクエスト数が増えない: 空ヘッダ GET は
    # 共有 unauth プローブの 1 本のみ）。
    url_gets = [r for r in requests if r["method"] == "GET" and r["url"] == URL_RECORDS_2]
    assert sum(1 for r in url_gets if not r["headers"]) == 1


@pytest.mark.asyncio
async def test_cross_account_bola_no_authb_noop(monkeypatch):
    """Flag ON but no authB wired -> the block is a complete no-op (no new
    requests, no cross-account finding, no exception)."""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True))
    requests: list = []
    manager = _make_manager(_make_request_fake(requests))
    base_params = {
        "_auth": {
            "auth_headers": {"Authorization": "Bearer token-a"},
            "cookies": "",
        }
    }
    result = await manager._run_api_minimal_check(URL_RECORDS_2, base_params)

    assert result["findings_count"] >= 0
    assert _cross_account_findings(manager) == []
    # No request ever carried an authB token.
    assert not any(str(r["headers"].get("X-Auth-Token", "")) == "token-b" for r in requests)


@pytest.mark.asyncio
async def test_cross_account_bola_flag_off_noop(monkeypatch):
    """Flag OFF (default) + authB wired: the authB probe still fires, but the
    cross-account finding block must not."""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(False))
    requests: list = []
    manager = _make_manager(_make_request_fake(requests))
    base_params = {
        "_auth": {
            "auth_headers": {"Authorization": "Bearer token-a"},
            "cookies": "",
            "auth_b_headers": {"X-Auth-Token": "token-b"},
            "auth_b_role": "user-b",
        }
    }
    result = await manager._run_api_minimal_check(URL_RECORDS_2, base_params)

    assert _cross_account_findings(manager) == []
    # The pre-existing authB probe behavior is unchanged: the second account's
    # token reached the client, but no cross-account finding was emitted.
    assert any(str(r["headers"].get("X-Auth-Token", "")) == "token-b" for r in requests)
    assert result["findings_count"] >= 0


@pytest.mark.asyncio
async def test_cross_account_bola_base_params_authb_passthrough():
    """STEP 3a builder: task.params auth_b_headers flow through the dispatch
    path's _auth builder into the manager's authB request. Without them, no
    authB-token request is made."""
    requests: list = []

    # Sub-case 1: authB supplied -> a request carrying X-Auth-Token: token-b
    # is observed (authB reached the client).
    manager_a = _make_manager(_make_request_fake(requests))
    manager_a.set_llm_client(MagicMock())
    task_a = Task(
        id="test-bola-wire",
        name="t",
        target=URL_RECORDS_2,
        agent_type="injection",
        action="scan",
        phase="attack",
        params={
            "category": "api",
            "auth_headers": {"Authorization": "Bearer token-a"},
            "auth_b_headers": {"X-Auth-Token": "token-b"},
            "auth_b_role": "user-b",
        },
    )
    await manager_a.dispatch(task_a)
    assert any(str(r["headers"].get("X-Auth-Token", "")) == "token-b" for r in requests)

    # Sub-case 2: no authB -> no request carries token-b.
    requests2: list = []
    manager_b = _make_manager(_make_request_fake(requests2))
    manager_b.set_llm_client(MagicMock())
    task_b = Task(
        id="test-bola-wire-no-authb",
        name="t",
        target=URL_RECORDS_2,
        agent_type="injection",
        action="scan",
        phase="attack",
        params={
            "category": "api",
            "auth_headers": {"Authorization": "Bearer token-a"},
        },
    )
    await manager_b.dispatch(task_b)
    assert not any(str(r["headers"].get("X-Auth-Token", "")) == "token-b" for r in requests2)


def test_idor_cross_account_confirm_enabled_default_off(monkeypatch):
    monkeypatch.delenv("SHIGOKU_IDOR_CROSS_ACCOUNT_CONFIRM_ENABLED", raising=False)
    assert Settings().idor_cross_account_confirm_enabled is False
