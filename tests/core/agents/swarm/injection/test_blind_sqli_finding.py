"""SGK-2026-0502: SmartBlindSQLiHunter が boolean ベースのブラインド SQLi を
自己校正オラクル＋実データ抽出で確定グレードの Finding に変換することを検証する。
製品非依存（合成・注入クライアント）。標的の DB は fake が模擬（実 SQL は実行しない）。"""

import asyncio
import re
import urllib.parse
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_blind_sqli import SmartBlindSQLiHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_BASE = "https://target.example/home"
_VERSION = "3.25.3"  # fake DB が返す sqlite_version()

_TRUE_BODY = (
    "<html>\n<head><title>Article Page</title></head>\n"
    "<body>\n<p>Some article content is shown here for readers to enjoy.</p>\n"
    "<footer>copyright example corp</footer>\n</body>\n</html>"
)
_FALSE_BODY = (
    "<html>\n<head><title>Not Found</title></head>\n"
    "<body>\n<p>The requested article does not exist on this server anymore.</p>\n"
    "<footer>copyright example corp</footer>\n</body>\n</html>"
)


def _eval_condition(cond: str) -> bool:
    """fake DB でブール条件を評価する（engine が送る形だけ対応）。"""
    cond = cond.strip()
    m = re.fullmatch(r"(\d+)=(\d+)", cond)
    if m:
        return m.group(1) == m.group(2)
    m = re.fullmatch(r"length\(\(SELECT sqlite_version\(\)\)\)>=(\d+)", cond)
    if m:
        return len(_VERSION) >= int(m.group(1))
    m = re.fullmatch(r"unicode\(substr\(\(SELECT sqlite_version\(\)\),(\d+),1\)\)([>=])(\d+)", cond)
    if m:
        pos, op, num = int(m.group(1)), m.group(2), int(m.group(3))
        if pos < 1 or pos > len(_VERSION):
            return False
        code = ord(_VERSION[pos - 1])
        return code > num if op == ">" else code == num
    return False


class _FakeBlindClient:
    """boolean-blind 注入点を模擬。注入値 ``1 AND <cond>`` を評価し true/false ページを返す。"""

    def __init__(self, oracle=True):
        self.oracle = oracle
        self.calls = 0

    async def request(self, method, url, headers=None, use_proxy=True, **kw):
        self.calls += 1
        value = urllib.parse.unquote(url.rsplit("/", 1)[1])
        m = re.fullmatch(r"1 AND (.+)", value)
        cond_true = _eval_condition(m.group(1)) if m else True
        if not self.oracle:
            # オラクル不成立: 常に同じページ（真偽で差が出ない）。
            return SimpleNamespace(status=200, body=_TRUE_BODY, text=_TRUE_BODY, headers={})
        body = _TRUE_BODY if cond_true else _FALSE_BODY
        return SimpleNamespace(status=200, body=body, text=body, headers={})


def _run(client):
    eng = SmartBlindSQLiHunter()
    eng._client = client
    task = Task(id="t", name="bsqli", target=_BASE,
                params={"blind_sqli_mode": "path", "blind_sqli_base_url": _BASE,
                        "blind_sqli_base_value": "1"})
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_and_extracts_data():
    findings = _run(_FakeBlindClient(oracle=True))
    exp = [f for f in findings if f.vuln_type == VulnType.BLIND_SQLI]
    assert exp, "blind SQLi finding not produced"
    d = exp[0].to_dict()
    be = d["additional_info"]["blind_sqli_evidence"]
    assert be["extracted_field"] == "sqlite_version()"
    assert be["extracted_value"] == _VERSION          # 真偽差分だけで実データ復元
    assert be["oracle_true_class"] == "true"
    assert be["oracle_false_class"] == "false"
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "blind_sqli_confirmed"


def test_no_finding_when_oracle_indistinguishable():
    # 真偽で応答が変わらない（オラクル不成立）→ fail-closed で finding なし。
    findings = _run(_FakeBlindClient(oracle=False))
    assert [f for f in findings if f.vuln_type == VulnType.BLIND_SQLI] == []


def test_poc_contains_extraction_transcript():
    d = _run(_FakeBlindClient(oracle=True))[0].to_dict()
    poc = d["additional_info"]["poc_response"]
    assert "extraction transcript" in poc
    # 先頭文字 '3'(code 51) の等値確認が transcript に載る。
    assert "=51" in poc and "== '3'" in poc


def test_payout_grade_fail_closed_without_extracted_value():
    d = _run(_FakeBlindClient(oracle=True))[0].to_dict()
    d["additional_info"]["blind_sqli_evidence"]["extracted_value"] = ""
    r = evaluate_payout_grade(d)
    assert r.payout_grade is False


def test_payout_grade_fail_closed_when_oracle_not_true_false():
    d = _run(_FakeBlindClient(oracle=True))[0].to_dict()
    d["additional_info"]["blind_sqli_evidence"]["oracle_false_class"] = "true"
    r = evaluate_payout_grade(d)
    assert r.payout_grade is False


def test_payout_grade_fail_closed_without_boolean_condition():
    d = _run(_FakeBlindClient(oracle=True))[0].to_dict()
    d["additional_info"]["blind_sqli_evidence"]["true_condition"] = "name IS NOT NULL"
    d["additional_info"]["blind_sqli_evidence"]["false_condition"] = "name IS NULL"
    r = evaluate_payout_grade(d)
    assert r.payout_grade is False
