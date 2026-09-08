"""
jwt_alg_none 用 payout_grade テスト — SGK-2026-0476 (A①)

機械フロア evaluate_payout_grade が JWT alg=none 無署名偽造の受理を
「本物確定」の材料にできることを検証する。jwt_forgery_accepted マーカーは
次の全てを要求する（1 つでも欠ければ fail-closed で no_firing_marker）:

- additional_info.jwt_alg が "none"（無署名/未検証。RS256/HS256 等の
  署名検証済みトークンでは発火しない）
- additional_info.unauth_baseline_absent が真（トークン無しでは
  fabricate identity 非出現＝盗んだセッションの再生でなく偽造の受理）
- additional_info.forged_identity が非空 かつ 応答に反映
  （forged_identity_reflected フラグまたは response_body への出現）

PRODUCT-INDEPENDENT: generic hosts (target.example / evil.example は
reserved example TLD)・エンジン fabricate の example 系 identity のみ。
"""
from __future__ import annotations

import pytest

from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade

API_URL = "https://target.example/api/identity"
FABRICATED_IDENTITY = "forge-3f2a9c8e@evil.example"
FORGED_BODY = f'{{"user":{{"id":1,"email":"{FABRICATED_IDENTITY}"}}}}'
UNAUTH_BODY = '{"user":{}}'


def _jwt_finding(**overrides) -> dict:
    """AuthNinja (B) が生成する Finding の to_dict 形状（発火系・SGK-2026-0476）。"""
    payload = {
        "vuln_type": "jwt_alg_none",
        "evidence": {
            "request_method": "GET",
            "request_url": API_URL,
            "response_status": 200,
            "response_body": FORGED_BODY,
        },
        "additional_info": {
            "jwt_alg": "none",
            "unauth_baseline_absent": True,
            "forged_identity": FABRICATED_IDENTITY,
            "forged_identity_reflected": True,
            "auth_endpoint": API_URL,
            "forged_token": (
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0."
                "eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImZvcmdlLTNmMmE5YzhlQGV2aWwuZXhhbXBsZSJ9LCJpYXQiOjEyM30."
            ),
        },
        "impact": (
            "The server accepts unsigned (alg=none) JWT tokens without signature "
            "verification: an attacker can impersonate an arbitrary identity."
        ),
        "reproduction_steps": [
            "1. GET the identity endpoint with no token (identity absent).",
            "2. Fabricate a local alg=none token with an attacker-chosen identity.",
            "3. GET the same endpoint with the forged token in Authorization/Cookie.",
            "4. Observe the fabricated identity reflected in the response.",
        ],
    }
    payload.update(overrides)
    return payload


class TestJwtForgeryPayoutGrade:
    def test_unsigned_forgery_reflected_and_baseline_absent_is_payout_grade(self) -> None:
        """(a) alg=none + forged 反映 + baseline 不在 → payout_grade."""
        result = evaluate_payout_grade(_jwt_finding())
        assert result.payout_grade is True
        assert result.reason == "payout_grade_satisfied"
        assert result.marker == "jwt_forgery_accepted"

    def test_reflection_via_response_body_without_flag_fires(self) -> None:
        """反映フラグが無くても evidence.response_body への forged_identity
        出現で発火する（反映の実体は応答本文）。"""
        finding = _jwt_finding()
        finding["additional_info"].pop("forged_identity_reflected", None)
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "jwt_forgery_accepted"

    def test_signed_rs256_fails_closed(self) -> None:
        """(b) jwt_alg=RS256（署名検証済み経路）→ 発火しない。"""
        finding = _jwt_finding()
        finding["additional_info"]["jwt_alg"] = "RS256"
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_signed_hs256_fails_closed(self) -> None:
        """(b) jwt_alg=HS256（署名検証済み経路）→ 発火しない。"""
        finding = _jwt_finding()
        finding["additional_info"]["jwt_alg"] = "HS256"
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_jwt_alg_missing_fails_closed(self) -> None:
        """jwt_alg 欠落（無署名と証明されていない）→ 発火しない。"""
        finding = _jwt_finding()
        finding["additional_info"].pop("jwt_alg", None)
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_forged_not_reflected_fails_closed(self) -> None:
        """(c) forged 非反映（フラグ無し・本文にも非出現）→ 発火しない。"""
        finding = _jwt_finding()
        finding["additional_info"].pop("forged_identity_reflected", None)
        finding["evidence"]["response_body"] = UNAUTH_BODY
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_reflected_but_flag_false_fails_closed(self) -> None:
        """反映フラグが明示的に偽（本文に identity が無い）→ 発火しない。"""
        finding = _jwt_finding()
        finding["additional_info"]["forged_identity_reflected"] = False
        finding["evidence"]["response_body"] = UNAUTH_BODY
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_baseline_not_absent_fails_closed(self) -> None:
        """(d) baseline に既出（unauth_baseline_absent 偽・差分なし）→ 発火しない。"""
        finding = _jwt_finding()
        finding["additional_info"]["unauth_baseline_absent"] = False
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_baseline_flag_missing_fails_closed(self) -> None:
        """unauth_baseline_absent 欠落（差分証明なし）→ 発火しない。"""
        finding = _jwt_finding()
        finding["additional_info"].pop("unauth_baseline_absent", None)
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_forged_identity_empty_fails_closed(self) -> None:
        """forged_identity 空（何を反映したのか不明）→ 発火しない。"""
        finding = _jwt_finding()
        finding["additional_info"]["forged_identity"] = ""
        finding["additional_info"].pop("forged_identity_reflected", None)
        finding["evidence"]["response_body"] = UNAUTH_BODY
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_other_vuln_types_unaffected(self) -> None:
        """既存種別の分岐は不変（jwt 追加の非回帰・マーカー相乗りなし）。"""
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
        """jwt_alg_none 以外の未登録カテゴリは従来どおり unknown_category。"""
        finding = _jwt_finding(vuln_type="csrf")
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "unknown_category"
        assert result.marker is None
