"""SGK-2026-0484: GraphQL 認可欠陥（認証なしで機微データ取得）の機械フロア
（payout_grade）発火と fail-closed を検証する。製品非依存（合成データのみ・
秘密の実値は使わない=キー側で照合）。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_ENDPOINT = "https://target.example/graphql"
# 保存形（値 redact 済み・実秘密なし）。matched_fields のキーが本文に実在。
_SERVED = (
    '{"data": {"users": [{"id": "1", "username": "admin", '
    '"password": "<redacted len=6>"}]}}'
)
_QUERY = "{users{id username password}}"


def _finding(**overrides):
    gee = {
        "endpoint": _ENDPOINT,
        "query": _QUERY,
        "response_status": 200,
        "matched_fields": ["password"],
        "served_body": _SERVED,
    }
    gee.update(overrides.pop("gee", {}))
    base = {
        "vuln_type": "graphql_authz_exposure",
        "impact": "認証なしで機微データ（password）を取得できる。",
        "reproduction_steps": ["認証なしで GraphQL クエリを POST する。"],
        "evidence": {
            "request_method": "POST",
            "request_url": _ENDPOINT,
            "response_status": 200,
            "response_body": _SERVED,
        },
        "additional_info": {"graphql_exposure_evidence": gee},
    }
    base.update(overrides)
    return base


def test_marker_category_registered():
    assert _MARKER_CATEGORIES.get("graphql_authz_exposure") == "graphql_sensitive_exposed"


def test_fires_when_complete():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "graphql_sensitive_exposed"


def test_fail_closed_missing_evidence_dict():
    f = _finding()
    f["additional_info"] = {}
    r = evaluate_payout_grade(f)
    assert r.payout_grade is False


def test_fail_closed_empty_endpoint():
    r = evaluate_payout_grade(_finding(gee={"endpoint": ""}))
    assert r.payout_grade is False


def test_fail_closed_non_200():
    # evidence.response_status も 200 以外にして再現ゲートも締める
    f = _finding(gee={"response_status": 403})
    f["evidence"]["response_status"] = 403
    r = evaluate_payout_grade(f)
    assert r.payout_grade is False


def test_fail_closed_empty_served_body():
    f = _finding(gee={"served_body": ""})
    f["evidence"]["response_body"] = ""
    r = evaluate_payout_grade(f)
    assert r.payout_grade is False


def test_fail_closed_empty_matched_fields():
    r = evaluate_payout_grade(_finding(gee={"matched_fields": []}))
    assert r.payout_grade is False


def test_fail_closed_empty_query():
    r = evaluate_payout_grade(_finding(gee={"query": ""}))
    assert r.payout_grade is False


def test_fail_closed_matched_key_absent_from_body():
    # matched_fields に本文に存在しないキーを指定 → 発火しない
    r = evaluate_payout_grade(
        _finding(gee={"matched_fields": ["not_in_body_field"]})
    )
    assert r.payout_grade is False


def test_legacy_secret_leak_unchanged():
    # 既存 secret_leak 経路が graphql 追加後も byte-identical に動く（非回帰）
    f = {
        "vuln_type": "secret_leak",
        "impact": "公開URLで資格情報が配信される。",
        "reproduction_steps": ["認証なしで /.env を GET する。"],
        "evidence": {
            "request_method": "GET",
            "request_url": "https://target.example/.env",
            "response_status": 200,
            "response_body": "DB_PASSWORD=<redacted len=6>\n",
        },
        "additional_info": {
            "secret_exposure_evidence": {
                "retrieved_url": "https://target.example/.env",
                "response_status": 200,
                "served_body": "DB_PASSWORD=<redacted len=6>\n",
            }
        },
    }
    r = evaluate_payout_grade(f)
    assert r.payout_grade is True
    assert r.marker == "secret_exposed"
