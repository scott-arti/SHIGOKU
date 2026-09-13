"""SGK-2026-0484: SmartGraphQLHunter が「認証なしで機微データが返る GraphQL
認可欠陥」を実クエリで検証し、実害 Finding を発行することを検証する。
製品非依存（合成スキーマ/合成データ）。秘密の実値は evidence/poc に残さない
（合成の偽値がどこにも現れないことをアサート）。"""

import json

import pytest
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_graphql import SmartGraphQLHunter
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_ENDPOINT = "https://target.example/graphql"
_FAKE_PW = "PLAINTEXT_FAKE_PW_9f3"  # 合成の偽パスワード（どこにも永続してはならない）

# 機微スカラーフィールド password を持つ UserObject を返す root Query field users
_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "users",
                            "args": [],
                            "type": {
                                "name": None,
                                "kind": "LIST",
                                "ofType": {"name": "UserObject", "kind": "OBJECT",
                                           "ofType": None},
                            },
                        }
                    ],
                },
                {
                    "name": "UserObject",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "id", "args": [],
                         "type": {"name": "ID", "kind": "SCALAR", "ofType": None}},
                        {"name": "username", "args": [],
                         "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
                        {"name": "password", "args": [],
                         "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
                    ],
                },
            ],
        }
    }
}

# 非機微スキーマ（Query.pastes -> PasteObject に機微フィールドなし）
_SCHEMA_NO_SENSITIVE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"name": "Query", "kind": "OBJECT", "fields": [
                    {"name": "pastes", "args": [], "type": {
                        "name": None, "kind": "LIST",
                        "ofType": {"name": "PasteObject", "kind": "OBJECT", "ofType": None}}},
                ]},
                {"name": "PasteObject", "kind": "OBJECT", "fields": [
                    {"name": "id", "args": [],
                     "type": {"name": "ID", "kind": "SCALAR", "ofType": None}},
                    {"name": "title", "args": [],
                     "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
                ]},
            ],
        }
    }
}

_DATA_WITH_SECRET = {
    "data": {"users": [
        {"id": "1", "username": "admin", "password": _FAKE_PW},
    ]}
}
_DATA_EMPTY = {"data": {"users": []}}


class _Client:
    """schema クエリと data クエリで別応答を返す注入クライアント。"""

    def __init__(self, schema, data, status=200):
        self._schema = schema
        self._data = data
        self._status = status
        self.calls = []

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        self.calls.append({"method": method, "url": url, "data": data})
        body = json.loads(data)["query"] if data else ""
        if "__schema" in body:
            payload = json.dumps(self._schema)
            st = 200
        else:
            payload = json.dumps(self._data)
            st = self._status
        return SimpleNamespace(status=st, text=payload, body=payload, headers={})


def _run(client):
    import asyncio

    class T:
        target = _ENDPOINT
        params = {}

    eng = SmartGraphQLHunter()
    eng._client = client
    return asyncio.run(eng.execute(T()))


def test_builds_exposure_finding_when_credentials_served():
    findings = _run(_Client(_SCHEMA, _DATA_WITH_SECRET))
    exp = [f for f in findings if f.vuln_type == VulnType.GRAPHQL_AUTHZ_EXPOSURE]
    assert exp, "GraphQL authz exposure finding not produced"
    f = exp[0]
    gee = f.to_dict()["additional_info"]["graphql_exposure_evidence"]
    assert gee["matched_fields"] == ["password"]
    assert gee["query"] == "{users{id username password}}"
    assert gee["response_status"] == 200


def test_built_finding_is_payout_grade():
    findings = _run(_Client(_SCHEMA, _DATA_WITH_SECRET))
    f = [x for x in findings if x.vuln_type == VulnType.GRAPHQL_AUTHZ_EXPOSURE][0]
    r = evaluate_payout_grade(f.to_dict())
    assert r.payout_grade is True
    assert r.marker == "graphql_sensitive_exposed"


def test_no_secret_value_persisted_in_finding():
    findings = _run(_Client(_SCHEMA, _DATA_WITH_SECRET))
    f = [x for x in findings if x.vuln_type == VulnType.GRAPHQL_AUTHZ_EXPOSURE][0]
    blob = json.dumps(f.to_dict(), ensure_ascii=False)
    assert _FAKE_PW not in blob, "raw secret value leaked into finding"
    # キー（フィールド名）は残る＝実害の証拠は保持
    assert "password" in blob
    assert "<redacted len=" in blob


def test_no_finding_when_no_sensitive_fields():
    findings = _run(_Client(_SCHEMA_NO_SENSITIVE, {"data": {"pastes": [{"id": "1"}]}}))
    exp = [f for f in findings if f.vuln_type == VulnType.GRAPHQL_AUTHZ_EXPOSURE]
    assert exp == []


def test_no_finding_when_data_empty():
    findings = _run(_Client(_SCHEMA, _DATA_EMPTY))
    exp = [f for f in findings if f.vuln_type == VulnType.GRAPHQL_AUTHZ_EXPOSURE]
    assert exp == []


def test_fail_closed_when_data_query_non_200():
    findings = _run(_Client(_SCHEMA, _DATA_WITH_SECRET, status=403))
    exp = [f for f in findings if f.vuln_type == VulnType.GRAPHQL_AUTHZ_EXPOSURE]
    assert exp == []
