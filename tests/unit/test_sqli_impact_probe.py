"""
SGK-2026-0452 STEP 2: SmartSQLiHunter 安全実証プローブ（boolean 差分オラクル
＋ 非機微1トークン抽出）と evidence チェーン整合の単体テスト。

- boolean 差分の決定的観測 -> impact_probe_records.boolean_differential.observed=True
  （quote/comment 閉じバリアント族を順に試し、最初に差分が観測された
  形状を採用・true/false の観測結果が記録される）
- 未観測時 fail-closed（全バリアントで差分なし -> observed=False・impact 拡張されない）
- 抽出は非機微トークンに限定（DB バージョン関数マッピング以外の抽出経路が存在しない）
- evidence チェーン整合（0451 実 run の 4 矛盾の再発防止）: sql_error_observed 時、
  evidence.response_body は raw 抜粋（LLM 主張文が入らない）・poc_request/poc_response
  はエラー観測プローブ・impact の payload/status は同一プローブ
- 既定 OFF バイト等価（フラグ OFF 時は 0451 の finding 構築・result キーと同一）
- 採用バリアントでの ORDER BY 列数発見 + UNION 抽出が機能し、
  値が本文に出現したときのみ observed=True

既存 test_smart_sqli_firing_path.py の mock パターンを踏襲する。
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

# monkeypatch 前に本来の get_settings を捕捉（再帰回避）
import src.core.config.settings as _settings_mod  # noqa: E402

_ORIG_GET_SETTINGS = _settings_mod.get_settings


def _settings_flag(firing: bool, impact: bool):
    """get_settings() のモンキーパッチ用: 実 settings を維持しつつ
    sqli_firing_path_enabled / sqli_impact_probe_enabled のみ上書きする
    （LLMClient 等の他フィールド参照を壊さない）。get_proxy_url も実
    settings へ委譲し、単独実行（-k 部分実行）でも SmartSQLiHunter.__init__
    の get_proxy_manager() が壊れないようにする。"""
    from types import SimpleNamespace

    real = _ORIG_GET_SETTINGS()
    return SimpleNamespace(
        sqli_firing_path_enabled=firing,
        sqli_impact_probe_enabled=impact,
        llm=getattr(real, "llm", None),
        get_proxy_url=lambda: getattr(real, "get_proxy_url", lambda: "")(),
    )


def _make_hunter() -> SmartSQLiHunter:
    hunter = SmartSQLiHunter(config={"mode": "vulntest"})
    hunter.llm = MagicMock()
    return hunter


def _obs(status=200, diff="normal", body="", error_type="none", db_type="sqlite"):
    return {
        "status": status,
        "diff": diff,
        "body_snippet": body,
        "elapsed_seconds": 0.01,
        "db_detection": {"type": db_type, "confidence": 0.8, "patterns": []},
        "error_classification": {
            "type": error_type, "severity": "high", "details": "observed"
        },
        "poc_request": "GET /search?q=1 HTTP/1.1\nHost: x",
        "poc_response": f"HTTP/1.1 {status}\n\n{body}",
    }


def _obs_error():
    return _obs(
        status=500, diff="syntax",
        body="SQL syntax error near 1", error_type="syntax",
    )


def _demo_hunter() -> SmartSQLiHunter:
    """sql_error 観測済み状態の hunter（実証プローブの前提状態）。"""
    hunter = _make_hunter()
    hunter.context = {
        "target": "http://x/search?q=1", "param": "q", "method": "GET",
        "params": {"q": "1"}, "auth_headers": {}, "cookies": "", "forms": [],
    }
    hunter._sql_error_observed = True
    hunter._sql_error_evidence = {
        "error_type": "syntax",
        "details": "Syntax error detected",
        "db_detection": {"type": "sqlite", "confidence": 0.8, "patterns": []},
        "body_snippet": "SQL syntax error near 1",
        "payload": "q=1'",
    }
    hunter._response_differential = {
        "attack_status": 500,
        "attack_body_snippet": "SQL syntax error near 1",
        "diff_type": "syntax",
    }
    return hunter


def _task(url="http://x/search?q=test"):
    return Task(id="t1", name="SQLi Check", target=url, params={}, tags=["sqli"])


def _fire_result_0451():
    """0451 の fire 結果（ゲート OFF 時の回帰用: LLM 散文が evidence に残る）。"""
    return {
        "vulnerable": False,
        "evidence": "",
        "param": "q",
        "tested_params": ["q"],
        "payloads_used": ["q=1'"],
        "description": "No SQL Injection detected.",
        "loop_result": {"status": "completed"},
        "blind_correlation": {},
        "sql_error_observed": True,
        "sql_error_evidence": {
            "error_type": "syntax",
            "details": "Syntax error detected",
            "body_snippet": "SQL syntax error near",
        },
        "response_differential": {
            "attack_status": 200,
            "attack_body_snippet": "SQL syntax error near",
            "diff_type": "syntax",
        },
        "poc_request": "GET /search?q=1' HTTP/1.1\nHost: x",
        "poc_response": "HTTP/1.1 200\n\nSQL syntax error near",
    }


def _observed_fire_result():
    """ゲート ON の fire 結果: エラー観測プローブ（q=1%27・500）に固定された
    poc ペア + boolean 観測済みの impact_probe_records。"""
    return {
        "vulnerable": False,
        "evidence": "",
        "param": "q",
        "tested_params": ["q"],
        "payloads_used": ["q=1'", 'q=1"', "q=1')) OR 1=1 --", "q=1')) OR 1=2 --"],
        "description": "No SQL Injection detected.",
        "loop_result": {"status": "completed"},
        "blind_correlation": {},
        "sql_error_observed": True,
        "sql_error_evidence": {
            "error_type": "syntax",
            "details": "Syntax error detected",
            "db_detection": {"type": "sqlite", "confidence": 0.8, "patterns": []},
            "body_snippet": "<html><title>Error: SQLITE_ERROR: incomplete input</title></html>",
            "payload": "q=1'",
        },
        "response_differential": {
            "attack_status": 500,
            "attack_body_snippet": "<html><title>Error: SQLITE_ERROR: incomplete input</title></html>",
            "diff_type": "syntax",
        },
        "poc_request": "GET /search?q=1%27 HTTP/1.1\nHost: x",
        "poc_response": (
            "HTTP/1.1 500\n\n<html><title>Error: SQLITE_ERROR: incomplete input</title></html>"
        ),
        "impact_probe_records": {
            "boolean_differential": {
                "observed": True,
                "true_probe": "q=1')) OR 1=1 --",
                "true_result": "HTTP 200, rows=8, body_len=1234",
                "false_probe": "q=1')) OR 1=2 --",
                "false_result": "HTTP 200, rows=0, body_len=60",
            },
            "extraction": {
                "observed": False,
                "expr": "", "value": "", "probe": "", "response_excerpt": "",
            },
            "error_probe": {
                "payload": "q=1'",
                "status": 500,
                "marker_excerpt": (
                    "<html><title>Error: SQLITE_ERROR: incomplete input</title></html>"
                ),
            },
        },
    }


# ---------------------------------------------------------------------------
# 1) boolean 差分の決定的観測
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_boolean_differential_rows_differ_is_observed():
    """実測形状の mock（`1'))` 系のみが 200/差分を返す）: バリアント族を
    順に試し、最初に決定的差分（行数差）が観測されたペア（`'))` + OR）を
    採用して observed=True・両結果が記録される。"""
    hunter = _demo_hunter()
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        # 閉じバリアントが足りない（' / ')）と 500（実測: incomplete input）
        if "))" not in payload:
            return _obs_error()
        if "OR 1=1" in payload:
            return _obs(status=200, body='{"status":"success","data":[{},{},{}]}')
        if "OR 1=2" in payload:
            return _obs(status=200, body='{"status":"success","data":[]}')
        if "AND 1=1" in payload:
            return _obs(status=200, body='{"status":"success","data":[{},{},{}]}')
        if "AND 1=2" in payload:
            return _obs(status=200, body='{"status":"success","data":[]}')
        return _obs(status=200, body='{"status":"success","data":[]}')

    hunter._send_request = fake_send
    await hunter._fire_impact_demonstration_probe("q", "1")

    records = hunter._impact_probe_records
    boolean = records["boolean_differential"]
    assert boolean["observed"] is True
    # 最初の成功形状（実測の 1')) 系）が採用される
    assert boolean["true_probe"] == "q=1')) OR 1=1 --"
    assert boolean["false_probe"] == "q=1')) OR 1=2 --"
    assert boolean["true_result"].startswith("HTTP 200, rows=3")
    assert boolean["false_result"].startswith("HTTP 200, rows=0")
    # 試行順: ' の OR/AND → ') の OR/AND → ')) の OR（10 プローブで採用・
    # 最初の差分で打ち切るため ')) の AND は試行されない）
    boolean_probes = [p for p in calls if "1=1" in p or "1=2" in p]
    assert len(boolean_probes) == 10
    assert "q=1' OR 1=1 --" in calls
    assert "q=1' AND 1=1 --" in calls
    assert "q=1') OR 1=1 --" in calls
    assert not any("1')) AND" in p for p in calls)
    # 未観測の抽出節は observed=False のまま（ORDER BY 遷移なし）
    assert records["extraction"]["observed"] is False
    # error_probe は常に充填される
    assert records["error_probe"]["payload"] == "q=1'"
    assert records["error_probe"]["status"] == 500
    assert records["error_probe"]["marker_excerpt"] == "SQL syntax error near 1"


@pytest.mark.asyncio
async def test_boolean_differential_status_differ_is_observed():
    """真/偽で HTTP status が異なる -> 最初のペア（`'` + OR）で採用され
    observed=True（OR が AND より先に試される）。"""
    hunter = _demo_hunter()
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        if "1=1" in payload:
            return _obs(status=200, body="ok")
        if "1=2" in payload:
            return _obs(status=500, diff="error", body="error", error_type="syntax")
        return _obs(status=200, body="ok")

    hunter._send_request = fake_send
    await hunter._fire_impact_demonstration_probe("q", "1")

    boolean = hunter._impact_probe_records["boolean_differential"]
    assert boolean["observed"] is True
    assert boolean["true_probe"] == "q=1' OR 1=1 --"
    assert boolean["false_probe"] == "q=1' OR 1=2 --"
    assert boolean["true_result"] == "HTTP 200, body_len=2"
    assert boolean["false_result"] == "HTTP 500, body_len=5"
    # 最初の差分で打ち切られる（AND ペアは送信されない）
    assert not any("AND 1=1" in p for p in calls)


@pytest.mark.asyncio
async def test_boolean_differential_fail_closed_when_no_difference():
    """全バリアント（3 close × 2 条件ペア = 12 プローブ）で差分なし ->
    observed=False・観測値は空のまま（impact 拡張されない）。"""
    hunter = _demo_hunter()
    calls = []

    async def fake_send(payload):
        # 真/偽で完全に同一の応答 -> 決定的差分なし
        calls.append(payload)
        return _obs(status=200, body='{"status":"success","data":[1]}')

    hunter._send_request = fake_send
    await hunter._fire_impact_demonstration_probe("q", "1")

    records = hunter._impact_probe_records
    boolean = records["boolean_differential"]
    assert boolean["observed"] is False
    assert boolean["true_result"] == ""
    assert boolean["false_result"] == ""
    # 有限のバリアント族が全て試行される（close 3 × 条件ペア 2 × 真偽 2）
    boolean_probes = [p for p in calls if "1=1" in p or "1=2" in p]
    assert len(boolean_probes) == 12
    assert "q=1' OR 1=1 --" in calls
    assert "q=1') OR 1=1 --" in calls
    assert "q=1')) OR 1=1 --" in calls
    # 抽出も全バリアントで ORDER BY 遷移なし -> fail-closed
    assert records["extraction"]["observed"] is False


# ---------------------------------------------------------------------------
# 2) 未観測時 fail-closed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_impact_probe_not_run_without_sql_error():
    """fail-closed: 発火プローブが SQL エラーを観測しなければ実証プローブは動かない。"""
    hunter = _make_hunter()
    hunter.context = {
        "target": "http://x/search?q=1", "param": "q", "method": "GET",
        "params": {"q": "1"}, "auth_headers": {}, "cookies": "", "forms": [],
    }
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return _obs(status=200, diff="normal", body="ok", error_type="none")

    hunter._send_request = fake_send
    hunter._probe_sent = False
    await hunter._fire_error_based_probe("q", "1")

    assert len(calls) == 2  # 発火プローブのみ
    assert hunter._sql_error_observed is False
    assert hunter._impact_probe_records == {}


# ---------------------------------------------------------------------------
# 3) 抽出は非機微トークンに限定（安全境界）
# ---------------------------------------------------------------------------


def test_extraction_expressions_are_non_sensitive_only():
    """抽出式は閉じた非機微集合（DB バージョン関数のみ）から導出され、
    それ以外の抽出経路（ユーザーデータ・資格情報・PII）が存在しない。"""
    exprs = {
        SmartSQLiHunter._version_expr_for_db(db)
        for db in ("sqlite", "mysql", "postgresql", "mssql")
    }
    assert exprs == SmartSQLiHunter.NON_SENSITIVE_EXTRACTION_EXPRS
    for expr in exprs:
        assert any(
            name in str(expr) for name in ("sqlite_version", "version", "@@VERSION")
        )
    # 未対応/不明 DB には抽出式が存在しない（経路なし）
    assert SmartSQLiHunter._version_expr_for_db("oracle") is None
    assert SmartSQLiHunter._version_expr_for_db("unknown") is None
    assert SmartSQLiHunter._version_expr_for_db("") is None


@pytest.mark.asyncio
async def test_extraction_skipped_for_unknown_db():
    """DB 検出不能 -> UNION 抽出は送信されない（observed=False）。"""
    hunter = _demo_hunter()
    hunter._sql_error_evidence["db_detection"] = {
        "type": "unknown", "confidence": 0.0, "patterns": []
    }
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return _obs(status=200, body='{"status":"success","data":[]}')

    hunter._send_request = fake_send
    await hunter._fire_impact_demonstration_probe("q", "1")

    assert hunter._impact_probe_records["extraction"]["observed"] is False
    assert not any("UNION" in payload for payload in calls)
    assert not any("ORDER BY" in payload for payload in calls)


# ---------------------------------------------------------------------------
# 6) ORDER BY 列数発見 + UNION 抽出
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_order_by_discovery_and_union_extraction():
    """実測形状の mock（`1'))` 系のみ 200）: boolean で採用された閉じ
    バリアント（`'))`）が ORDER BY 列数発見（3 正常 / 4 エラー遷移）と
    UNION SELECT に再利用され、バージョン式値が本文に出現したときのみ
    observed=True になる。"""
    hunter = _demo_hunter()
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        # 閉じバリアントが足りない（' / ')）と 500（実測: incomplete input）
        if "))" not in payload:
            return _obs_error()
        if payload == "q=-1')) --":
            return _obs(status=200, body='{"status":"success","data":[]}')
        if "UNION SELECT" in payload:
            return _obs(status=200, body='{"status":"success","data":[{"col":"3.45.1"}]}')
        if "ORDER BY" in payload:
            n = int(payload.split("ORDER BY")[1].strip().split(" ")[0])
            if n <= 3:
                return _obs(status=200, body='{"status":"success","data":[{},{},{}]}')
            return _obs(
                status=500, diff="error", error_type="syntax",
                body="SQLITE_ERROR: ORDER BY term out of range",
            )
        if "OR 1=1" in payload:
            return _obs(status=200, body='{"status":"success","data":[{},{},{}]}')
        if "OR 1=2" in payload:
            return _obs(status=200, body='{"status":"success","data":[]}')
        return _obs(status=200, body='{"status":"success","data":[]}')

    hunter._send_request = fake_send
    await hunter._fire_impact_demonstration_probe("q", "1")

    records = hunter._impact_probe_records
    assert records["boolean_differential"]["observed"] is True
    assert records["boolean_differential"]["true_probe"] == "q=1')) OR 1=1 --"
    extraction = records["extraction"]
    assert extraction["observed"] is True
    assert extraction["expr"] == "sqlite_version()"
    assert extraction["value"] == "3.45.1"
    assert extraction["probe"] == "q=-1')) UNION SELECT sqlite_version(), NULL, NULL --"
    assert "3.45.1" in extraction["response_excerpt"]
    # 列数発見は boolean で採用された閉じバリアントで実行され、遷移
    # （3 正常 / 4 エラー）で即採用される（N=1..4 の 4 件のみ）
    order_by_sent = [p for p in calls if "ORDER BY" in p]
    assert len(order_by_sent) == 4
    assert order_by_sent == [
        "q=1')) ORDER BY 1 --",
        "q=1')) ORDER BY 2 --",
        "q=1')) ORDER BY 3 --",
        "q=1')) ORDER BY 4 --",
    ]


@pytest.mark.asyncio
async def test_union_padding_fallback_when_null_padding_rejected():
    """実測のアプリ挙動（Juice Shop）: UNION 行の NULL パディング 2+ 列は
    500、リテラルパディングは 200。NULL が拒否されたらリテラル 1
    フォールバックで値を観測し observed=True（パディング族も有限・
    全パディングで値なしなら fail-closed）。"""
    hunter = _demo_hunter()
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        if "))" not in payload:
            return _obs_error()
        if "UNION SELECT" in payload:
            if "NULL" in payload:
                return _obs(status=500, diff="error", error_type="syntax",
                            body="Error: Unexpected path")
            return _obs(status=200, body='{"status":"success","data":[{"col":"3.45.1"}]}')
        if "ORDER BY" in payload:
            n = int(payload.split("ORDER BY")[1].strip().split(" ")[0])
            if n <= 3:
                return _obs(status=200, body='{"status":"success","data":[{},{},{}]}')
            return _obs(status=500, diff="error", error_type="syntax",
                        body="ORDER BY term out of range")
        if "OR 1=1" in payload:
            return _obs(status=200, body='{"status":"success","data":[{},{},{}]}')
        if "OR 1=2" in payload:
            return _obs(status=200, body='{"status":"success","data":[]}')
        return _obs(status=200, body='{"status":"success","data":[]}')

    hunter._send_request = fake_send
    await hunter._fire_impact_demonstration_probe("q", "1")

    extraction = hunter._impact_probe_records["extraction"]
    assert extraction["observed"] is True
    assert extraction["value"] == "3.45.1"
    # NULL パディングが拒否され、リテラル 1 パディングで観測された
    assert extraction["probe"] == "q=-1')) UNION SELECT sqlite_version(), 1, 1 --"
    assert any("UNION SELECT sqlite_version(), NULL" in p for p in calls)
    assert any("UNION SELECT sqlite_version(), 1, 1" in p for p in calls)


@pytest.mark.asyncio
async def test_extraction_fail_closed_when_value_not_in_body():
    """UNION 応答にバージョン値が出現しない -> observed=False（捏造しない）。"""
    hunter = _demo_hunter()
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        if "))" not in payload:
            return _obs_error()
        if "UNION SELECT" in payload:
            return _obs(status=200, body='{"status":"success","data":[{"col":"nope"}]}')
        if "ORDER BY" in payload:
            n = int(payload.split("ORDER BY")[1].strip().split(" ")[0])
            if n <= 3:
                return _obs(status=200, body='{"status":"success","data":[{},{},{}]}')
            return _obs(status=500, diff="error", body="error", error_type="syntax")
        if "OR 1=1" in payload:
            return _obs(status=200, body='{"status":"success","data":[{},{},{}]}')
        if "OR 1=2" in payload:
            return _obs(status=200, body='{"status":"success","data":[]}')
        return _obs(status=200, body='{"status":"success","data":[]}')

    hunter._send_request = fake_send
    await hunter._fire_impact_demonstration_probe("q", "1")

    extraction = hunter._impact_probe_records["extraction"]
    assert extraction["observed"] is False
    assert extraction["value"] == ""
    # UNION プローブは採用バリアントで送信された（観測はされたが値が無い）
    assert any("q=-1')) UNION SELECT" in p for p in calls)


# ---------------------------------------------------------------------------
# 4) evidence チェーン整合（4矛盾の再発防止）
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_chain_error_observation_pinned(monkeypatch):
    """ゲート ON: sql_error_observed 時、evidence.response_body は raw 抜粋
    （LLM 主張文が入らない）・poc_request/poc_response はエラー観測プローブ・
    evidence の URL/status と impact の payload/status は同一プローブ。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True))
    hunter = _make_hunter()
    hunter.run_as_tool = AsyncMock(return_value=_observed_fire_result())

    findings = await hunter.execute(_task())

    assert len(findings) == 1
    f = findings[0]
    # ① status 不一致なし: evidence.status=500 = エラー観測プローブの実測
    assert f.evidence.response_status == 500
    # ③ evidence.response_body は raw 一次証拠（LLM 散文・主張文が入らない）
    assert f.evidence.response_body == (
        "<html><title>Error: SQLITE_ERROR: incomplete input</title></html>"
    )
    assert "SQL error observed" not in f.evidence.response_body
    assert "vulnerable" not in f.evidence.response_body
    # ② poc ペアはエラー観測プローブ（q=1%27・500）に固定（最後の成功プローブで
    # 上書きされない）
    assert f.additional_info["poc_request"] == "GET /search?q=1%27 HTTP/1.1\nHost: x"
    assert f.additional_info["poc_response"].startswith("HTTP/1.1 500")
    assert f.evidence.request_url == "http://x/search?q=1%27"
    # ④ impact の payload/status は同一（エラー観測）プローブ由来
    assert "q=1'" in f.impact
    assert "HTTP 500" in f.impact
    # 実証観測（boolean）が impact に載る
    assert "Boolean differential oracle" in f.impact
    assert "HTTP 200, rows=8, body_len=1234" in f.impact


@pytest.mark.asyncio
async def test_evidence_chain_llm_vulnerable_does_not_override_raw(monkeypatch):
    """A-5: LLM が vulnerable 主張を返しても、sql_error 観測時の evidence は
    raw 観測のまま（LLM 散文で上書きされない）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True))
    hunter = _make_hunter()
    result = _observed_fire_result()
    result["vulnerable"] = True
    result["evidence"] = "vulnerable - Confirmed SQL injection via double quote"
    result["description"] = "SQL Injection detected."
    hunter.run_as_tool = AsyncMock(return_value=result)

    findings = await hunter.execute(_task())

    assert len(findings) == 1
    f = findings[0]
    assert f.evidence.response_body == (
        "<html><title>Error: SQLITE_ERROR: incomplete input</title></html>"
    )
    assert "Confirmed SQL injection" not in f.evidence.response_body


# ---------------------------------------------------------------------------
# 5) 既定 OFF バイト等価
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_off_keeps_0451_finding_construction(monkeypatch):
    """firing ON + impact OFF（0451 互換）: evidence は 0451 の散文のまま
    （raw 置換なし）・impact_probe_records は finding に載らない。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, False))
    hunter = _make_hunter()
    hunter.run_as_tool = AsyncMock(return_value=_fire_result_0451())

    findings = await hunter.execute(_task())

    assert len(findings) == 1
    f = findings[0]
    assert "SQL error observed" in f.evidence.response_body
    assert "impact_probe_records" not in f.additional_info


@pytest.mark.asyncio
async def test_firing_on_impact_off_no_demo_probe(monkeypatch):
    """firing ON + impact OFF: 発火プローブ2件のみ送信され、実証プローブは
    動かず result に新キーが出ない（0451 バイト等価）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, False))
    import src.core.agents.swarm.injection.smart_sqli as mod
    monkeypatch.setattr(mod, "_fetch_and_parse_form", AsyncMock(return_value=[]))

    hunter = _make_hunter()
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return _obs_error()

    hunter._send_request = fake_send

    async def fake_run_loop(ctx):
        return {"status": "completed", "turns": 1}
    hunter.run_loop = fake_run_loop

    result = await hunter.run_as_tool(
        "http://x/search?q=test",
        {
            "_auth": {"auth_headers": {}, "cookies": ""},
            "method": "GET",
            "forms": [],
            "q": "1",
        },
    )

    assert len(calls) == 2
    assert "impact_probe_records" not in result
    # 0451 の記録キーは従来どおり
    assert result["probe_sent"] is True


# ---------------------------------------------------------------------------
# 統合: 発火 -> 実証の積み上げ + A-2 の poc 固定（run_as_tool 経由）
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_error_based_probe_runs_demo_after_sql_error(monkeypatch):
    """フラグ両 ON かつ sql_error 観測時: 発火の上に実証プローブが積まれる。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True))
    hunter = _make_hunter()
    hunter.context = {
        "target": "http://x/search?q=1", "param": "q", "method": "GET",
        "params": {"q": "1"}, "auth_headers": {}, "cookies": "", "forms": [],
    }
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        if "AND 1=1" in payload:
            return _obs(status=200, body='{"status":"success","data":[{},{}]}')
        if "AND 1=2" in payload:
            return _obs(status=200, body='{"status":"success","data":[]}')
        if "ORDER BY" in payload:
            return _obs(status=200, body='{"status":"success","data":[]}')
        return _obs_error()

    hunter._send_request = fake_send
    hunter._probe_sent = False
    await hunter._fire_error_based_probe("q", "1")

    assert len(calls) > 2  # 発火プローブ + 実証プローブ
    assert hunter._sql_error_observed is True
    assert hunter._impact_probe_records["boolean_differential"]["observed"] is True
    # 実証 payload も used_payloads に記録される（0449 充填の payload 要件）
    assert any("AND 1=1" in p for p in hunter.used_payloads)
    assert any("ORDER BY" in p for p in hunter.used_payloads)


@pytest.mark.asyncio
async def test_run_as_tool_pins_error_pair_when_gate_on(monkeypatch):
    """A-2: ゲート ON 時、result の poc ペアはエラー観測プローブ（q=1' 系）に
    固定され、後続の成功プローブ（q=1"）で上書きされない。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True))
    import src.core.agents.swarm.injection.smart_sqli as mod
    monkeypatch.setattr(mod, "_fetch_and_parse_form", AsyncMock(return_value=[]))

    hunter = _make_hunter()
    error_obs = {
        "status": 500, "diff": "syntax",
        "body_snippet": "SQL syntax error near 1",
        "elapsed_seconds": 0.01,
        "db_detection": {"type": "sqlite", "confidence": 0.8, "patterns": []},
        "error_classification": {"type": "syntax", "severity": "high", "details": "observed"},
        "poc_request": "GET /search?q=1%27 HTTP/1.1\nHost: x",
        "poc_response": "HTTP/1.1 500\n\nSQL syntax error near 1",
    }
    success_obs = {
        "status": 200, "diff": "normal",
        "body_snippet": '{"status":"success","data":[]}',
        "elapsed_seconds": 0.01,
        "db_detection": {"type": "sqlite", "confidence": 0.0, "patterns": []},
        "error_classification": {"type": "none", "severity": "none", "details": ""},
        "poc_request": 'GET /search?q=1%22 HTTP/1.1\nHost: x',
        "poc_response": 'HTTP/1.1 200\n\n{"status":"success","data":[]}',
    }

    async def fake_send(payload):
        if "AND 1=1" in payload:
            return _obs(status=200, body='{"status":"success","data":[{},{}]}')
        if "AND 1=2" in payload:
            return _obs(status=200, body='{"status":"success","data":[]}')
        if "ORDER BY" in payload or "UNION" in payload:
            return _obs(status=200, body='{"status":"success","data":[]}')
        if payload == 'q=1"':
            return success_obs
        return error_obs

    hunter._send_request = fake_send

    async def fake_run_loop(ctx):
        return {"status": "completed", "turns": 1}
    hunter.run_loop = fake_run_loop

    result = await hunter.run_as_tool(
        "http://x/search?q=test",
        {
            "_auth": {"auth_headers": {}, "cookies": ""},
            "method": "GET",
            "forms": [],
            "q": "1",
        },
    )

    assert result["sql_error_observed"] is True
    # エラー観測プローブ（q=1%27・500）に固定
    assert result["poc_request"] == "GET /search?q=1%27 HTTP/1.1\nHost: x"
    assert result["poc_response"].startswith("HTTP/1.1 500")
    # error_probe 記録も同一プローブ
    assert result["impact_probe_records"]["error_probe"]["payload"] == "q=1'"
    assert result["impact_probe_records"]["error_probe"]["status"] == 500


# --- manager 記録配線（承認設計の項目5・recording only / dispatch 無改変） ---


def _make_manager_with_stub():
    from src.core.agents.swarm.injection.manager import InjectionManagerAgent

    m = InjectionManagerAgent.__new__(InjectionManagerAgent)
    m.current_context = {"params": {}, "auth_headers": {}, "findings": []}
    m._phase2_detection_mode = "phase2"
    stub = MagicMock()
    stub.execute_with_retry = AsyncMock(return_value=[])
    stub.last_tested_params = []
    stub.last_blind_correlation = {}
    stub._last_probe_sent = True
    stub._last_poc_request = "GET /search?q=1' HTTP/1.1\nHost: x"
    stub._last_poc_response = "HTTP/1.1 500\n\nSQL syntax error near 1"
    stub._impact_probe_records = {
        "boolean_differential": {
            "observed": True,
            "true_probe": "q=1')) OR 1=1 --",
            "true_result": "HTTP 200, rows=8, body_len=1234",
            "false_probe": "q=1')) OR 1=2 --",
            "false_result": "HTTP 200, rows=0, body_len=60",
        },
        "extraction": {"observed": False, "expr": "", "value": "", "probe": "", "response_excerpt": ""},
        "error_probe": {"payload": "q=1'", "status": 500, "marker_excerpt": "SQL syntax error near 1"},
    }
    m.specialists = {"sqli": stub}
    return m


@pytest.mark.asyncio
async def test_run_sqli_hunter_surfaces_impact_records_when_gates_on(monkeypatch):
    """項目5: 0451 fire ON ∧ 0452 impact ON のとき run_sqli_hunter が
    impact_probe_records を返す（記録配線・dispatch 無改変）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True))
    m = _make_manager_with_stub()

    result = await m.run_sqli_hunter(url="http://x/search?q=test", params={})

    assert result["impact_probe_records"]["boolean_differential"]["observed"] is True
    assert result["impact_probe_records"]["error_probe"]["payload"] == "q=1'"


@pytest.mark.asyncio
async def test_run_sqli_hunter_impact_records_none_when_gate_off(monkeypatch):
    """項目5: 既定 OFF（両フラグ OFF）では impact_probe_records は None（バイト等価）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(False, False))
    m = _make_manager_with_stub()

    result = await m.run_sqli_hunter(url="http://x/search?q=test", params={})

    assert result["impact_probe_records"] is None


@pytest.mark.asyncio
async def test_run_sqli_hunter_impact_records_none_when_firing_only(monkeypatch):
    """項目5: firing ON のみ（impact OFF）では impact_probe_records は None
    （0451 の上に積む・impact フラグが要る）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, False))
    m = _make_manager_with_stub()

    result = await m.run_sqli_hunter(url="http://x/search?q=test", params={})

    assert result["impact_probe_records"] is None
