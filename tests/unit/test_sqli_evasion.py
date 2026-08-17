"""
SGK-2026-0453 STEP 2: 防御回避カタログの単体テスト（決定的な機構を固める）。

必須カバレッジ（承認済み契約 6 項目）:
- 妨害検知の各 signal（blocked / stripped_suspected / no_interference / fail-closed）
- カタログの決定的順序（同一入力→同一列・recon 優先・identity 先頭）
- renderer=None のバイト等価（既存3関数の現行挙動不変）
- 抽出フォールバックの回数上限で fail-closed
- 勝ち筋凍結が変形済み要求（素のプローブではない）を固定する
- 既定 OFF バイト等価（新フラグ OFF で既存挙動不変）
"""
import re
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter
import src.core.agents.swarm.injection.sqli_transform_catalog as catalog_mod
from src.core.agents.swarm.injection.sqli_transform_catalog import (
    DeterministicFixedOrderStrategy,
    ProbeObservation,
    ReconInfo,
    TransformStep,
    catalog_sequence,
    classify_interference,
)
import src.core.config.settings as _settings_mod

_ORIG_GET_SETTINGS = _settings_mod.get_settings


def _settings_flag(firing: bool, impact: bool, evasion: bool):
    """get_settings() モンキーパッチ: 実 settings を維持しつつ 3 フラグのみ
    上書きする（test_sqli_impact_probe.py の流儀）。"""
    from types import SimpleNamespace

    real = _ORIG_GET_SETTINGS()
    return SimpleNamespace(
        sqli_firing_path_enabled=firing,
        sqli_impact_probe_enabled=impact,
        sqli_evasion_catalog_enabled=evasion,
        llm=getattr(real, "llm", None),
        get_proxy_url=lambda: getattr(real, "get_proxy_url", lambda: "")(),
    )


def _make_hunter() -> SmartSQLiHunter:
    hunter = SmartSQLiHunter(config={"mode": "vulntest"})
    hunter.llm = MagicMock()
    return hunter


def _obs(status=200, body="", diff="normal", error_type="none", poc_request=None):
    return {
        "status": status,
        "diff": diff,
        "body_snippet": body[:200],
        "elapsed_seconds": 0.01,
        "db_detection": {"type": "unknown", "confidence": 0.0, "patterns": []},
        "error_classification": {
            "type": error_type, "severity": "high", "details": "observed"
        },
        "poc_request": poc_request or f"GET /search?q={body} HTTP/1.1\nHost: x",
        "poc_response": f"HTTP/1.1 {status}\n\n{body[:500]}",
    }


def _demo_hunter() -> SmartSQLiHunter:
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
        "body_snippet": "SQLite error: incomplete input",
        "payload": "q=1'",
    }
    hunter._response_differential = {
        "attack_status": 500,
        "attack_body_snippet": "SQLite error: incomplete input",
        "diff_type": "syntax",
    }
    return hunter


# ---------------------------------------------------------------------------
# 1) カタログ: 決定的順序・recon 優先・家族レンダリング
# ---------------------------------------------------------------------------


def _oracle_eval_pred(pred: str, value: str) -> bool:
    """boolean オラクルの述語を実評価する（テスト専用の ground truth）。
    `1=2` 等の定数偽は False を返す。"""
    pred = pred.strip()
    m = re.fullmatch(
        r"length\(\(SELECT sqlite_version\(\)\)\) (>=|<=|=|<>|>|<) (\d+)", pred
    )
    if m:
        op, n = m.group(1), int(m.group(2))
        length = len(value)
        return {
            "<": length < n, ">": length > n,
            "<=": length <= n, ">=": length >= n,
            "=": length == n, "<>": length != n,
        }[op]
    m = re.fullmatch(
        r"unicode\(substr\(\(SELECT sqlite_version\(\)\),(\d+),1\)\) "
        r"(>=|<=|=|<>|>|<) (\d+)",
        pred,
    )
    if m:
        pos, op, val = int(m.group(1)), m.group(2), int(m.group(3))
        ch = ord(value[pos - 1])
        return {
            "<": ch < val, ">": ch > val,
            "<=": ch <= val, ">=": ch >= val,
            "=": ch == val, "<>": ch != val,
        }[op]
    m = re.fullmatch(
        r"substr\(\(SELECT sqlite_version\(\)\),1,(\d+)\)(=|<>)(.*)", pred
    )
    if m:
        length, op, tok = int(m.group(1)), m.group(2), m.group(3).strip("'")
        return (value[:length] == tok) if op == "=" else (value[:length] != tok)
    return False


def test_catalog_deterministic_same_input():
    a = catalog_sequence("1' OR 1=1 --", "sqlite")
    b = catalog_sequence("1' OR 1=1 --", "sqlite")
    assert a == b
    assert [s.rendered for s in a] == [s.rendered for s in b]
    assert a[0].kind == "identity"
    assert a[0].rendered == "1' OR 1=1 --"


def test_catalog_recon_priority_and_db_specific():
    sqlite_steps = catalog_sequence("1' OR 1=1 --", "sqlite")
    mysql_steps = catalog_sequence("1' OR 1=1 --", "mysql")
    sqlite_kinds = [s.kind for s in sqlite_steps]
    mysql_kinds = [s.kind for s in mysql_steps]
    # recon 優先: mysql は TERMINATOR(#) と COMMENT_SPLIT を含む。
    # sqlite は TERMINATOR の汎用形 (/* */) のみで # も COMMENT_SPLIT も無い
    assert "terminator" in sqlite_kinds
    assert "comment_split" in mysql_kinds
    assert "comment_split" not in sqlite_kinds
    assert any(s.rendered == "1' OR 1=1 #" for s in mysql_steps)
    assert not any(s.rendered == "1' OR 1=1 #" for s in sqlite_steps)
    assert any(s.kind == "comment_split" for s in mysql_steps)
    assert not any(s.kind == "comment_split" for s in sqlite_steps)
    # ENCODING は最後・pre_encoded=True
    assert mysql_kinds[-1] == "encoding" and sqlite_kinds[-1] == "encoding"
    assert all(s.kind == "encoding" for s in mysql_steps if s.pre_encoded)
    # 同一入力 → 毎回同一順序（純関数）
    assert catalog_sequence("1' OR 1=1 --", "mysql") == mysql_steps


def test_catalog_families_render():
    steps = catalog_sequence("1' OR 1=1 --", "sqlite")
    by_kind = {s.kind: s for s in steps}
    by_key = {s.key: s for s in steps}
    assert by_key[("case_mix", 1)].rendered == "1' oR 1=1 --"
    assert by_key[("ws_comment", 1)].rendered == "1'/**/OR 1=1 --"
    assert by_key[("no_quote", 1)].rendered == "1 OR 1=1 --"
    assert by_key[("cond_paraphrase", 1)].rendered == "1' OR 'a'='a' --"
    assert by_kind["encoding"].pre_encoded is True
    assert "%2527" in by_kind["encoding"].rendered  # 二重 URL 符号化


def test_catalog_error_probe_family():
    # エラープローブ（引用のみ）では encoding 系のみが追加される（決定的・有限）
    steps = catalog_sequence("1'", "unknown")
    kinds = [s.kind for s in steps]
    assert kinds == ["identity", "encoding"]
    assert steps[1].rendered == "1%2527"


# ---------------------------------------------------------------------------
# 2) 妨害検知: 各 signal と fail-closed
# ---------------------------------------------------------------------------


def test_interference_blocked_status_code():
    baseline = _obs(200, '{"data":[1,2]}')
    probes = [
        ("q=1'", _obs(403, "forbidden")),
        ('q=1"', _obs(403, "forbidden")),
    ]
    v = classify_interference(baseline, probes)
    assert v.verdict == "blocked"
    assert v.reason == "block_status_code"


def test_interference_blocked_uniform_page():
    baseline = _obs(200, '{"data":[1,2]}')
    probes = [
        ("q=1'", _obs(200, "<html>blocked page</html>")),
        ('q=1"', _obs(200, "<html>blocked page</html>")),
    ]
    v = classify_interference(baseline, probes)
    assert v.verdict == "blocked"
    assert v.reason == "uniform_block_page"


def test_interference_stripped_suspected():
    baseline = _obs(200, '{"data":[]}')
    # 全プローブが baseline と完全同一・かつペイロード非反映 → stripped
    probes = [
        ("q=1'", _obs(200, '{"data":[]}')),
        ('q=1"', _obs(200, '{"data":[]}')),
    ]
    v = classify_interference(baseline, probes)
    assert v.verdict == "stripped_suspected"


def test_interference_no_interference_differential():
    baseline = _obs(200, '{"data":[1]}')
    probes = [
        ("q=1'", _obs(500, "SQLite error: incomplete input")),
        ('q=1"', _obs(200, '{"data":[1,2]}')),
    ]
    v = classify_interference(baseline, probes)
    assert v.verdict == "no_interference"
    assert v.reason == "differential_observed"


def test_interference_no_interference_payload_reflected():
    # プローブ応答が baseline と同一 (status, body_snippet) でも、poc_response
    # にペイロード（≥3文字の断片）が反映されていれば「刺さらない」= 妨害なし。
    baseline = {
        "status": 200,
        "body_snippet": '{"data":[]}',
        "poc_response": 'HTTP/1.1 200\n\n{"data":[]}',
    }
    probes = [
        (
            "q=1'",
            {
                "status": 200,
                "body_snippet": '{"data":[]}',
                "poc_response": 'HTTP/1.1 200\n\n{"data":[],"echo":"q=1\'"}',
            },
        ),
    ]
    v = classify_interference(baseline, probes)
    assert v.verdict == "no_interference"
    assert v.reason == "payload_reflected"


def test_interference_reflection_ignores_short_syntax_fragments():
    # JSON 構文の引用符（2文字断片）を「反映」と誤判定しない
    # （`1"` はどの JSON 応答にも現れるため）。
    baseline = {"status": 200, "body_snippet": '{"data":[]}', "poc_response": 'HTTP/1.1 200\n\n{"data":[]}'}
    probes = [
        ('q=1"', {"status": 200, "body_snippet": '{"data":[]}', "poc_response": 'HTTP/1.1 200\n\n{"data":[]}'}),
    ]
    v = classify_interference(baseline, probes)
    assert v.verdict == "stripped_suspected"


def test_interference_fail_closed_insufficient():
    assert classify_interference({}, []).verdict == "no_interference"
    # status キー欠如（観測不足）→ fail-closed で妨害なし
    assert classify_interference({}, [("q", {})]).verdict == "no_interference"
    assert classify_interference(_obs(200, "x"), [("q", {})]).verdict == "no_interference"


# ---------------------------------------------------------------------------
# 3) renderer=None バイト等価（既存3関数の現行挙動不変）
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_boolean_oracle_renderer_none_byte_identical():
    hunter = _demo_hunter()
    calls = []

    async def fake_send(payload, **kwargs):
        calls.append(payload)
        return _obs(status=200, body='{"status":"success","data":[]}')

    hunter._send_demo_probe = fake_send
    records, close = await hunter._run_boolean_oracle("q", "1")
    assert records["observed"] is False and close == ""
    # 現行（0452）と同一: close 3 × 条件ペア 2 × 真偽 2 = 12 件・canonical のみ
    assert calls == [
        "q=1' OR 1=1 --", "q=1' OR 1=2 --",
        "q=1' AND 1=1 --", "q=1' AND 1=2 --",
        "q=1') OR 1=1 --", "q=1') OR 1=2 --",
        "q=1') AND 1=1 --", "q=1') AND 1=2 --",
        "q=1')) OR 1=1 --", "q=1')) OR 1=2 --",
        "q=1')) AND 1=1 --", "q=1')) AND 1=2 --",
    ]


@pytest.mark.asyncio
async def test_discover_union_column_count_renderer_none_byte_identical():
    hunter = _demo_hunter()
    calls = []

    async def fake_send(payload, **kwargs):
        calls.append(payload)
        return _obs(status=200, body='{"status":"success","data":[]}')

    hunter._send_demo_probe = fake_send
    result = await hunter._discover_union_column_count("q", "1", preferred_close="'")
    assert result == (0, "")
    # 現行: close 族 3 種（preferred 先頭） × N=1..13 = 39 件・canonical のみ
    assert calls[:13] == [f"q=1' ORDER BY {n} --" for n in range(1, 14)]
    assert len(calls) == 3 * 13


@pytest.mark.asyncio
async def test_extract_non_sensitive_token_renderer_none_byte_identical(monkeypatch):
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(False, False, False))
    hunter = _demo_hunter()
    calls = []

    async def fake_send(payload, **kwargs):
        calls.append(payload)
        return _obs(status=200, body='{"status":"success","data":[]}')

    hunter._send_demo_probe = fake_send
    records = await hunter._extract_non_sensitive_token("q", "1", preferred_close="'")
    assert records["observed"] is False
    # 現行: ORDER BY close 族 3×13 件（遷移なし → 早期 fail-closed、control なし）
    assert "UNION" not in "\n".join(calls)
    assert len(calls) == 3 * 13


# ---------------------------------------------------------------------------
# 4) 抽出フォールバック: 上限 fail-closed / 導出 / 時間差なし
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extraction_oracle_cap_fail_closed(monkeypatch):
    monkeypatch.setattr(
        "src.core.agents.swarm.injection.smart_sqli.ORACLE_EXTRACTION_PROBE_CAP", 6
    )
    hunter = _demo_hunter()
    sent = 0

    async def fake_send(payload, **kwargs):
        nonlocal sent
        sent += 1
        return _obs(status=200, body='{"status":"success","data":[]}')

    hunter._send_demo_probe = fake_send
    records = await hunter._extract_token_by_boolean_oracle("q", "1", "'", "sqlite_version()")
    # 予算超過 → 即中止・observed=False（fail-closed・捏造しない）
    assert records["observed"] is False
    assert sent <= 6


@pytest.mark.asyncio
async def test_extraction_oracle_derives_token_bit_by_bit():
    """実際のオラクル機構（二分探索・述語評価・確定ペア）を transport のみ
    mock して検証する。値は観測された差分から導出され、最終確定ペアで
    直接確認される。"""
    VALUE = "3.44.2"
    hunter = _demo_hunter()
    sent = []

    async def fake_send(payload, **kwargs):
        sent.append(payload)
        m = re.search(r"OR (.*?) --$", payload)
        if not m:
            return _obs(status=200, body='{"status":"success","data":[]}')
        truth = _oracle_eval_pred(m.group(1), VALUE)
        body = (
            '{"status":"success","data":[{"x":1}]}'
            if truth
            else '{"status":"success","data":[]}'
        )
        return _obs(status=200, body=body)

    hunter._send_demo_probe = fake_send
    records = await hunter._extract_token_by_boolean_oracle("q", "1", "'", "sqlite_version()")
    assert records["observed"] is True
    assert records["value"] == VALUE
    assert records["method"] == "boolean_oracle"
    assert records["expr"] == "sqlite_version()"
    # 最悪ケース 172 ≦ 上限 200（本ケース実測: 長さ10 + 6文字×(4〜5比較ペア+等号) + 確定2 = 68）
    assert len(sent) == 68
    assert len(sent) <= catalog_mod.ORACLE_EXTRACTION_PROBE_CAP
    # 時間差ペイロード（SLEEP 等）が一切含まれない
    assert not any("sleep" in p.lower() for p in sent)


@pytest.mark.asyncio
async def test_extraction_oracle_fail_closed_when_chars_mismatch():
    """文字候補の等号確認が差分を返さない → 即中止・observed=False。"""
    VALUE = "3.44.2"
    hunter = _demo_hunter()
    sent = []

    async def fake_send(payload, **kwargs):
        sent.append(payload)
        m = re.search(r"OR (.*?) --$", payload)
        if not m:
            return _obs(status=200, body='{"status":"success","data":[]}')
        pred = m.group(1)
        # 文字の等号確認（捏造防止: 値が帰属できない）だけ差分を返さない
        if re.fullmatch(
            r"unicode\(substr\(\(SELECT sqlite_version\(\)\),\d+,1\)\) = \d+", pred
        ):
            return _obs(status=200, body='{"status":"success","data":[]}')
        truth = _oracle_eval_pred(pred, VALUE)
        body = (
            '{"status":"success","data":[{"x":1}]}'
            if truth
            else '{"status":"success","data":[]}'
        )
        return _obs(status=200, body=body)

    hunter._send_demo_probe = fake_send
    records = await hunter._extract_token_by_boolean_oracle("q", "1", "'", "sqlite_version()")
    assert records["observed"] is False


# ---------------------------------------------------------------------------
# 5) 勝ち筋凍結: 変形済み要求（素のプローブではない）を固定
# ---------------------------------------------------------------------------


def _evasion_hunter() -> SmartSQLiHunter:
    hunter = _make_hunter()
    hunter.context = {
        "target": "http://x/search?q=1", "param": "q", "method": "GET",
        "params": {"q": "1"}, "auth_headers": {}, "cookies": "", "forms": [],
    }
    return hunter


@pytest.mark.asyncio
async def test_win_route_freeze_pins_transformed_probe(monkeypatch):
    """素のプローブ（'）は弾かれ、変形済み encoding プローブが sql_error を
    発火 → _error_poc_request / adopted.rendered / route がその変形済み要求を
    固定する（素のプローブではない）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True, True))
    hunter = _evasion_hunter()
    calls = []

    async def fake_send(payload, **kwargs):
        calls.append(payload)
        if payload.endswith("%2527"):  # encoding 変形が勝利
            return _obs(
                status=500, diff="syntax", error_type="syntax",
                body="SQLite error: incomplete input",
                poc_request=f"GET /search?{payload} HTTP/1.1\nHost: x",
            )
        return _obs(status=200, body='{"data":[]}')  # 素のプローブは弾かれる

    hunter._send_request = fake_send
    plain = [
        await hunter._send_request("q=1'"),
        await hunter._send_request('q=1"'),
    ]
    await hunter._fire_evasion_probes("q", "1", plain)

    assert hunter._sql_error_observed is True
    records = hunter._evasion_probe_records
    assert records is not None
    assert records["interference"]["verdict"] == "stripped_suspected"
    adopted = records["adopted"]
    assert adopted is not None
    # 勝ち筋は変形済み要求そのもの（素の q=1' ではない）
    assert adopted["kind"] == "encoding"
    assert adopted["rendered"].endswith("%2527")
    assert "q=1'" not in adopted["rendered"]
    # A-1 ピン留め: evidence の poc ペア = 変形済み要求
    assert hunter._error_poc_request == f"GET /search?q=1%2527 HTTP/1.1\nHost: x"
    assert adopted["poc_request"] == hunter._error_poc_request
    # route = 送信順（identity の敗北 → encoding の勝利）
    kinds = [entry["kind"] for entry in records["route"]]
    assert kinds == ["identity", "encoding"]
    assert "q=1'" in records["route"][0]["probe"]
    assert records["route"][1]["probe"].endswith("%2527")
    # 弾かれた手の記録（否定の記録・Ver.2 が再利用）
    assert any(r["kind"] == "identity" for r in records["rejected"])


@pytest.mark.asyncio
async def test_win_route_freeze_fail_closed_when_catalog_loses(monkeypatch):
    """カタログ全敗 → sql_error 未観測のまま・adopted=None・回避前状態に
    復帰（ハンティング結果を変えない）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True, True))
    hunter = _evasion_hunter()

    async def fake_send(payload, **kwargs):
        return _obs(status=200, body='{"data":[]}')

    hunter._send_request = fake_send
    plain = [
        await hunter._send_request("q=1'"),
        await hunter._send_request('q=1"'),
    ]
    await hunter._fire_evasion_probes("q", "1", plain)

    assert hunter._sql_error_observed is False
    assert hunter._evasion_probe_records is not None
    assert hunter._evasion_probe_records["adopted"] is None
    assert hunter._evasion_probe_records["interference"]["verdict"] == "stripped_suspected"


# ---------------------------------------------------------------------------
# 6) 既定 OFF バイト等価 + 発火点上の分岐ゲート
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evasion_flag_off_byte_identical(monkeypatch):
    """firing+impact ON・evasion OFF（既定）: 発火プローブ2件のみ送信され、
    実証/回避プローブは動かず、新キーも出ない（0452 バイト等価）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True, False))
    hunter = _make_hunter()
    hunter.context = {
        "target": "http://x/search?q=1", "param": "q", "method": "GET",
        "params": {"q": "1"}, "auth_headers": {}, "cookies": "", "forms": [],
    }
    calls = []

    async def fake_send(payload, **kwargs):
        calls.append(payload)
        return _obs(status=200, body='{"data":[]}')

    hunter._send_request = fake_send
    hunter._probe_sent = False
    await hunter._fire_error_based_probe("q", "1")

    assert calls == ["q=1'", 'q=1"']
    assert hunter._evasion_probe_records is None
    assert hunter._impact_probe_records == {}


@pytest.mark.asyncio
async def test_evasion_branch_runs_then_demo_gate_holds(monkeypatch):
    """evasion ON: plain 全敗 → 妨害検知 → カタログ再試行で sql_error 獲得 →
    既存の実証ゲート（impact demo）がそのまま進行する。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True, True))
    hunter = _evasion_hunter()
    demo_called = False

    async def fake_demo(param_name, base):
        nonlocal demo_called
        demo_called = True

    hunter._fire_impact_demonstration_probe = fake_demo  # type: ignore[method-assign]

    async def fake_send(payload, **kwargs):
        if payload.endswith("%2527"):
            return _obs(
                status=500, diff="syntax", error_type="syntax",
                body="SQLite error: incomplete input",
                poc_request=f"GET /search?{payload} HTTP/1.1\nHost: x",
            )
        return _obs(status=200, body='{"data":[]}')

    hunter._send_request = fake_send
    hunter._probe_sent = False
    await hunter._fire_error_based_probe("q", "1")

    assert hunter._sql_error_observed is True
    assert hunter._evasion_probe_records is not None
    assert hunter._evasion_probe_records["adopted"]["kind"] == "encoding"
    assert demo_called is True


@pytest.mark.asyncio
async def test_impact_records_evasion_key_flag_gated(monkeypatch):
    """flag ON: impact_probe_records に "evasion" キーが載る（route 含む）。
    flag OFF: キーなし（バイト等価）。"""
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True, True))
    hunter = _demo_hunter()
    hunter._evasion_route = [
        {"step": 1, "kind": "identity", "probe": "q=1' OR 1=1 --", "observed": "HTTP 200, rows=8"}
    ]
    calls = []

    async def fake_send(payload, **kwargs):
        calls.append(payload)
        return _obs(status=200, body='{"data":[]}')

    hunter._send_demo_probe = fake_send
    await hunter._fire_impact_demonstration_probe("q", "1")
    assert "evasion" in hunter._impact_probe_records
    assert hunter._impact_probe_records["evasion"]["route"][0]["probe"] == "q=1' OR 1=1 --"

    # flag OFF → キーなし
    monkeypatch.setattr("src.core.config.settings.get_settings", lambda: _settings_flag(True, True, False))
    hunter2 = _demo_hunter()
    hunter2._send_demo_probe = fake_send
    await hunter2._fire_impact_demonstration_probe("q", "1")
    assert "evasion" not in hunter2._impact_probe_records


# ---------------------------------------------------------------------------
# 7) 選択戦略インターフェイス（Ver.2 差し込みの継ぎ目）
# ---------------------------------------------------------------------------


def test_selection_strategy_deterministic_and_skips_rejected():
    steps = catalog_sequence("1' OR 1=1 --", "sqlite")
    strategy = DeterministicFixedOrderStrategy()
    recon = ReconInfo(db_type="sqlite")
    first = strategy.next_candidate(
        candidates=steps, observations=[], recon=recon, rejected=frozenset()
    )
    assert first == steps[0]  # identity が先頭
    second = strategy.next_candidate(
        candidates=steps,
        observations=[],
        recon=recon,
        rejected=frozenset({steps[0].key}),
    )
    assert second == steps[1]  # rejected をスキップ
    exhausted = strategy.next_candidate(
        candidates=steps,
        observations=[],
        recon=recon,
        rejected=frozenset(s.key for s in steps),
    )
    assert exhausted is None
