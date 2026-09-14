"""SGK-2026-0490: SmartJWTForgeryHunter が RS256→HS256 キー混同を3者差分で確定
グレードの Finding に変換することを検証する。製品非依存（合成データ・注入クライアント）。
正規トークンは payload 導出にのみ使い finding に含めない。"""

import asyncio
import base64
import hashlib
import hmac
import json
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_jwt_forgery import SmartJWTForgeryHunter, _hs256
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/whoami"
_PUBKEY = "-----BEGIN RSA PUBLIC KEY-----\nTESTPUBKEYBYTES\n-----END RSA PUBLIC KEY-----"
_LEGIT_PAYLOAD = {"data": {"email": "real@target.example", "role": "customer", "id": 7},
                  "iat": 1000, "exp": 9999999999}
_LEGIT_TOKEN = _hs256(b"irrelevant-legit-secret", _LEGIT_PAYLOAD)


def _b64d(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


class _KeyConfusionServer:
    """HS256 を公開鍵(_PUBKEY)で検証し、正しければ data.email を反映＝本物のキー混同。"""

    def __init__(self, secret=_PUBKEY):
        self.secret = secret.encode("utf-8")

    async def request(self, method, url, params=None, data=None, headers=None, use_proxy=True, **kw):
        auth = str((headers or {}).get("Authorization") or "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        empty = SimpleNamespace(status=200, body='{"user":{}}', text='{"user":{}}', headers={})
        if not token:
            return empty
        try:
            h, p, s = token.split(".")
            si = (h + "." + p).encode()
            expect = base64.urlsafe_b64encode(
                hmac.new(self.secret, si, hashlib.sha256).digest()
            ).rstrip(b"=").decode()
            if s != expect:  # 誤り秘密 → 拒否
                return empty
            payload = json.loads(_b64d(p))
            email = payload.get("data", {}).get("email", "")
            body = json.dumps({"user": {"id": 7, "email": email}})
            return SimpleNamespace(status=200, body=body, text=body, headers={})
        except Exception:
            return empty


class _NoVerifyServer:
    """署名を検証せず常に反映（＝キー混同でなく署名未検証）→ 本エンジンは非確定。"""

    async def request(self, method, url, params=None, data=None, headers=None, use_proxy=True, **kw):
        auth = str((headers or {}).get("Authorization") or "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            return SimpleNamespace(status=200, body='{"user":{}}', text="", headers={})
        p = token.split(".")[1]
        email = json.loads(_b64d(p)).get("data", {}).get("email", "")
        body = json.dumps({"user": {"email": email}})
        return SimpleNamespace(status=200, body=body, text=body, headers={})


def _run(client):
    eng = SmartJWTForgeryHunter()
    eng._client = client
    task = Task(id="t", name="jwt", target=_URL, tags=["jwt"])
    task.params = {
        "jwt_token": _LEGIT_TOKEN,
        "jwt_public_key": _PUBKEY,
        "jwt_observe": {"method": "GET", "url": _URL},
    }
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_key_confusion():
    findings = _run(_KeyConfusionServer())
    exp = [f for f in findings if f.vuln_type == VulnType.JWT_RS256_HS256]
    assert exp, "jwt key confusion finding not produced"
    d = exp[0].to_dict()
    info = d["additional_info"]
    assert info["jwt_alg"] == "hs256"
    assert info["jwt_key_confusion"] is True
    assert info["unauth_baseline_absent"] is True
    assert info["forged_identity"] in info["jwt_forgery_evidence"]["forged_served_body"]
    assert info["forged_identity"] not in info["jwt_forgery_evidence"]["wrong_secret_served_body"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "jwt_forgery_accepted"


def test_legit_token_not_in_finding():
    d = _run(_KeyConfusionServer())[0].to_dict()
    assert _LEGIT_TOKEN not in json.dumps(d, ensure_ascii=False)


def test_three_way_poc():
    d = _run(_KeyConfusionServer())[0].to_dict()
    poc_req = d["additional_info"]["poc_request"]
    assert "Step 1" in poc_req and "Step 2" in poc_req and "Step 3" in poc_req
    marker = d["additional_info"]["forged_identity"]
    assert marker in d["additional_info"]["poc_response"]


def test_forged_token_present_for_replay():
    d = _run(_KeyConfusionServer())[0].to_dict()
    ft = d["additional_info"]["forged_token"]
    assert ft and ft.count(".") == 2


def test_no_finding_when_signature_not_verified():
    # 誤り秘密でも反映＝署名未検証（キー混同でない）→ 確定しない。
    findings = _run(_NoVerifyServer())
    assert [f for f in findings if f.vuln_type == VulnType.JWT_RS256_HS256] == []


def test_no_finding_without_pubkey():
    eng = SmartJWTForgeryHunter()
    eng._client = _KeyConfusionServer()
    task = Task(id="t", name="jwt", target=_URL, tags=["jwt"])
    task.params = {"jwt_token": _LEGIT_TOKEN, "jwt_observe": {"method": "GET", "url": _URL}}
    assert asyncio.run(eng.execute(task)) == []
