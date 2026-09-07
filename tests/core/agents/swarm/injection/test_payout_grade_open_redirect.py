"""
open_redirect 用 payout_grade テスト — SGK-2026-0471 (A①)

機械フロア evaluate_payout_grade が open_redirect を「本物確定」の材料に
できることを検証する。external_redirect マーカーは次の全てを要求する
（1 つでも欠ければ fail-closed で no_firing_marker）:

- evidence.response_status が 3xx（301/302/303/307/308）
- Location（evidence.response_headers の Location/location、無ければ
  additional_info.redirect_to）に、注入した攻撃者ホスト
  （additional_info.injected_host → redirect_to のホスト → payload の
  ホスト）が出現する
- そのホストが対象自身のホスト（evidence.request_url）と異なる（外部）

PRODUCT-INDEPENDENT: generic hosts (example.com / evil.com) のみ。
"""
from __future__ import annotations

import pytest

from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade

SELF_URL = "http://example.com/redirect?url=http%3A%2F%2Fshigoku-verify-abc.evil.com%2F"
ATTACKER_HOST = "shigoku-verify-abc.evil.com"
ATTACKER_LOCATION = f"http://{ATTACKER_HOST}/"

# OpenRedirectSpecialist (B) が生成する Finding の to_dict 形状。
_FIRING_EVIDENCE = {
    "request_method": "GET",
    "request_url": SELF_URL,
    "response_status": 302,
    "response_headers": {"Location": ATTACKER_LOCATION},
    "response_body": f"Redirect location: {ATTACKER_LOCATION}",
}

_FIRING_INFO = {
    "parameter": "url",
    "payload": f"http://{ATTACKER_HOST}/",
    "payloads_used": [f"http://{ATTACKER_HOST}/"],
    "tested_params": ["url"],
    "redirect_to": ATTACKER_LOCATION,
    "injected_host": ATTACKER_HOST,
}


def _open_redirect_finding(**overrides) -> dict:
    payload = {
        "vuln_type": "open_redirect",
        "evidence": dict(_FIRING_EVIDENCE),
        "additional_info": dict(_FIRING_INFO),
        "impact": "認証済み利用者を攻撃者が管理する外部URLへ誘導可能。",
        "reproduction_steps": [
            f"GET {SELF_URL}",
            f"応答 302 / Location: {ATTACKER_LOCATION}",
            "ヘッドレスブラウザで上記URLを開き、攻撃者管理ホストへの遷移を確認",
        ],
    }
    payload.update(overrides)
    return payload


class TestOpenRedirectPayoutGrade:
    def test_external_redirect_marker_is_payout_grade(self) -> None:
        """(a) 3xx + 攻撃者ホストが Location に出現 + 外部 → payout_grade."""
        result = evaluate_payout_grade(_open_redirect_finding())
        assert result.payout_grade is True
        assert result.reason == "payout_grade_satisfied"
        assert result.marker == "external_redirect"

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_all_3xx_statuses_fire(self, status: int) -> None:
        finding = _open_redirect_finding()
        finding["evidence"]["response_status"] = status
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "external_redirect"

    def test_headers_without_location_fall_back_to_redirect_to(self) -> None:
        """response_headers に Location が無い場合は redirect_to で照合
        （既存 finding の後方互換・redirect_to は既存フィールド）。"""
        finding = _open_redirect_finding()
        finding["evidence"]["response_headers"] = {}
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "external_redirect"

    def test_injected_host_missing_falls_back_to_redirect_to_host(self) -> None:
        """injected_host が無い場合は redirect_to のホストで照合。"""
        finding = _open_redirect_finding()
        del finding["additional_info"]["injected_host"]
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "external_redirect"

    def test_attacker_host_only_in_payload_still_fires(self) -> None:
        """injected_host / redirect_to が無い場合も payload のホストで照合。"""
        finding = _open_redirect_finding()
        finding["additional_info"] = {
            "parameter": "url",
            "payload": f"http://{ATTACKER_HOST}/",
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "external_redirect"

    def test_attacker_host_not_in_location_fails_closed(self) -> None:
        """(b) 攻撃者ホストが Location に非出現 → no_firing_marker。"""
        finding = _open_redirect_finding()
        finding["evidence"]["response_headers"] = {
            "Location": "http://legit.example.com/next"
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_relative_internal_location_fails_closed(self) -> None:
        """(c) 同一ホスト内リダイレクト（内部相対 /path）→ 発火しない。"""
        finding = _open_redirect_finding()
        finding["evidence"]["response_headers"] = {
            "Location": "/internal/home"
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"

    def test_target_own_host_location_fails_closed(self) -> None:
        """(c) 対象自身のホストへのリダイレクト → 外部でないため発火しない。"""
        finding = _open_redirect_finding()
        finding["evidence"]["response_headers"] = {
            "Location": "http://example.com/home"
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"

    def test_non_3xx_status_fails_closed(self) -> None:
        """(d) 3xx でない（200 等）→ 発火しない。"""
        for status in (200, 204, 500):
            finding = _open_redirect_finding()
            finding["evidence"]["response_status"] = status
            result = evaluate_payout_grade(finding)
            assert result.payout_grade is False
            assert result.reason == "no_firing_marker"

    def test_missing_location_and_redirect_to_fails_closed(self) -> None:
        """Location も redirect_to も無ければ判定不能 → 発火しない。"""
        finding = _open_redirect_finding()
        finding["evidence"]["response_headers"] = {}
        finding["additional_info"] = {
            "parameter": "url",
            "payload": f"http://{ATTACKER_HOST}/",
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"

    def test_other_vuln_types_unaffected(self) -> None:
        """既存種別の分岐・reason は不変（open_redirect 追加の非回帰）。"""
        sqli = {
            "vuln_type": "sqli",
            "evidence": {
                "request_method": "GET",
                "request_url": "http://example.com/sqli/?id=1'",
                "response_status": 200,
                "response_body": "Fatal error: mysqli_sql_exception SQL syntax",
            },
            "additional_info": {},
            "impact": "Attacker can extract the full user database.",
            "reproduction_steps": ["Send GET /sqli/?id=1'"],
        }
        result = evaluate_payout_grade(sqli)
        assert result.payout_grade is True
        assert result.marker == "sql_error"
