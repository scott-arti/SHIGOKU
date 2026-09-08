"""
cors 用 payout_grade テスト — SGK-2026-0475 (A①)

機械フロア evaluate_payout_grade が cors を「本物確定」の材料にできること
を検証する。cors_credentialed_reflection マーカーは次の全てを要求する
（1 つでも欠ければ fail-closed で no_firing_marker）:

- additional_info.acao が additional_info.test_origin にホスト一致で反映
  （`*`・`null`・空・対象自身のオリジンは不可）
- additional_info.acac が真（"true"・大文字小文字無視）
- additional_info.credentialed_body_excerpt が非空（認証付き越境応答本文を
  実際に読めた実証）

PRODUCT-INDEPENDENT: generic hosts (attacker.example / trusted.example /
target.example) と汎用ダミー機微データのみ。
"""
from __future__ import annotations

import pytest

from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade

API_URL = "https://target.example/api/account"
TEST_ORIGIN = "https://attacker.example"
CREDENTIALED_BODY = (
    '{"session_token":"dummy-session-3f2a9c8e1b7d","user_email":"alice@example.test",'
    '"account_role":"admin","account_id":"acct_100042"}'
)


def _cors_finding(**overrides) -> dict:
    """SmartCORSHunter (B) が生成する Finding の to_dict 形状（発火系）。"""
    payload = {
        "vuln_type": "cors",
        "evidence": {
            "request_method": "GET",
            "request_url": API_URL,
            "response_status": 200,
            "response_headers": {
                "Access-Control-Allow-Origin": TEST_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            },
            "response_body": CREDENTIALED_BODY,
        },
        "additional_info": {
            "test_origin": TEST_ORIGIN,
            "acao": TEST_ORIGIN,
            "acac": "true",
            "misconfiguration": "origin_reflection_with_credentials",
            "credentialed_body_excerpt": CREDENTIALED_BODY,
            "poc_request": f"GET {API_URL} HTTP/1.1\nOrigin: {TEST_ORIGIN}\n",
            "poc_response": (
                f"HTTP/1.1 200 OK\n"
                f"Access-Control-Allow-Origin: {TEST_ORIGIN}\n"
                f"Access-Control-Allow-Credentials: true\n"
            ),
        },
        "impact": (
            "An attacker can read sensitive cross-origin responses (tokens, PII) "
            "if the victim visits a malicious page while authenticated."
        ),
        "reproduction_steps": [
            f"1. Send GET {API_URL} with header: Origin: {TEST_ORIGIN}",
            "2. Observe response header: Access-Control-Allow-Origin: "
            f"{TEST_ORIGIN}",
            "3. If Access-Control-Allow-Credentials: true, cross-origin requests "
            "with cookies are possible.",
        ],
    }
    payload.update(overrides)
    return payload


class TestCorsPayoutGrade:
    def test_credentialed_reflection_is_payout_grade(self) -> None:
        """(a) 反映（ホスト一致）+ acac true + excerpt 非空 → payout_grade."""
        result = evaluate_payout_grade(_cors_finding())
        assert result.payout_grade is True
        assert result.reason == "payout_grade_satisfied"
        assert result.marker == "cors_credentialed_reflection"

    def test_canonical_vuln_type_cors_misconfiguration_fires(self) -> None:
        """VulnType.CORS_MISCONFIGURATION.value（"cors_misconfiguration"）でも
        発火する（Finding.to_dict 経路の正形）。"""
        finding = _cors_finding(vuln_type="cors_misconfiguration")
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "cors_credentialed_reflection"

    def test_host_match_ignores_port_and_scheme(self) -> None:
        """ホスト一致は urlparse hostname 比較（ポート差は許容）。"""
        finding = _cors_finding()
        finding["evidence"]["response_headers"] = {
            "Access-Control-Allow-Origin": "http://attacker.example:8080",
            "Access-Control-Allow-Credentials": "true",
        }
        finding["additional_info"]["acao"] = "http://attacker.example:8080"
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "cors_credentialed_reflection"

    def test_acac_is_case_insensitive(self) -> None:
        """acac の "TRUE"/"True" 表記でも発火（大文字小文字無視）。"""
        finding = _cors_finding()
        finding["additional_info"]["acac"] = "TRUE"
        finding["evidence"]["response_headers"][
            "Access-Control-Allow-Credentials"
        ] = "TRUE"
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "cors_credentialed_reflection"

    def test_response_headers_fallback_when_info_acao_missing(self) -> None:
        """additional_info.acao が無い場合は response_headers を補助参照
        （生ヘッダ名の揺れ対応・値のハードコード無し）。"""
        finding = _cors_finding()
        finding["additional_info"]["acao"] = ""
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "cors_credentialed_reflection"

    def test_wildcard_acao_fails_closed(self) -> None:
        """(b) acao="*"（公開データのみ・低影響）→ 発火しない。"""
        finding = _cors_finding()
        finding["additional_info"]["acao"] = "*"
        finding["evidence"]["response_headers"] = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_null_acao_fails_closed(self) -> None:
        """(d) acao="null" → 発火しない。"""
        finding = _cors_finding()
        finding["additional_info"]["acao"] = "null"
        finding["evidence"]["response_headers"] = {
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_acao_missing_fails_closed(self) -> None:
        """acao 空（反映なし）→ 発火しない。"""
        finding = _cors_finding()
        finding["additional_info"]["acao"] = ""
        finding["evidence"]["response_headers"] = {}
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"

    def test_acao_not_matching_test_origin_fails_closed(self) -> None:
        """反映がテストオリジンとホスト不一致（別ホスト）→ 発火しない。"""
        finding = _cors_finding()
        finding["additional_info"]["acao"] = "https://trusted.example"
        finding["evidence"]["response_headers"] = {
            "Access-Control-Allow-Origin": "https://trusted.example",
            "Access-Control-Allow-Credentials": "true",
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"

    def test_credentials_not_true_fails_closed(self) -> None:
        """(c) 反映するが acac != true（認証なし反映）→ 発火しない。"""
        finding = _cors_finding()
        finding["additional_info"]["acac"] = "false"
        finding["evidence"]["response_headers"] = {
            "Access-Control-Allow-Origin": TEST_ORIGIN,
            "Access-Control-Allow-Credentials": "false",
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_excerpt_missing_fails_closed(self) -> None:
        """(e) credentialed_body_excerpt 空（機微本文を読めた実証なし）→
        発火しない。"""
        finding = _cors_finding()
        finding["additional_info"]["credentialed_body_excerpt"] = ""
        finding["evidence"]["response_body"] = ""
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_whitespace_only_excerpt_fails_closed(self) -> None:
        """空白のみの excerpt も非空扱いにしない（fail-closed）。"""
        finding = _cors_finding()
        finding["additional_info"]["credentialed_body_excerpt"] = "   \n  "
        finding["evidence"]["response_body"] = ""
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"

    def test_self_origin_reflection_fails_closed(self) -> None:
        """対象自身のオリジンへの反映は攻撃者オリジンでない → 発火しない。"""
        finding = _cors_finding()
        finding["additional_info"]["acao"] = "https://target.example"
        finding["additional_info"]["test_origin"] = "https://target.example"
        finding["evidence"]["response_headers"] = {
            "Access-Control-Allow-Origin": "https://target.example",
            "Access-Control-Allow-Credentials": "true",
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"

    def test_other_vuln_types_unaffected(self) -> None:
        """既存種別の分岐・reason は不変（cors 追加の非回帰）。"""
        sqli = {
            "vuln_type": "sqli",
            "evidence": {
                "request_method": "GET",
                "request_url": "http://target.example/sqli/?id=1'",
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

    def test_unknown_category_still_unknown(self) -> None:
        """cors 以外の未登録カテゴリは従来どおり unknown_category。"""
        finding = _cors_finding(vuln_type="csrf")
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "unknown_category"
        assert result.marker is None
