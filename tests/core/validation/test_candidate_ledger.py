"""
Candidate Ledger Tests - SGK-2026-0444 T2

PRODUCT-INDEPENDENT fixtures: generic targets (https://target.example/),
fake secrets only (never real credentials).

Covers: round-trip equality (save -> open -> get on every field),
list_by_state / all() ordering, secret-scan (zero raw secrets persisted,
including nested dict/list values), idempotent re-masking (no drift),
corruption quarantine (garbage / non-UTF-8 / non-object payloads), missing
file fail-safe, unknown schema version best-effort load, malformed record
skip, atomic save with temp cleanup, OSError fail-loud, and one run-spanning
integration flow (apply -> put/save -> reopen -> revisit -> apply).
"""
import json
import logging
import os
from dataclasses import replace
from typing import Optional

import pytest

from src.core.agents.swarm.injection.payout_grade import PayoutGradeResult
from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.validation.candidate_lifecycle import (
    CandidateLifecycleManager,
    CandidateRecord,
    LifecycleState,
)
from src.core.validation.candidate_ledger import (
    LEDGER_SCHEMA_VERSION,
    CandidateLedger,
)
from src.core.validation.finding_validator import (
    HybridVerdict,
    ReproductionOutcome,
    VerdictState,
)

# ---------------------------------------------------------------------------
# Fake secrets (product-independent)
# ---------------------------------------------------------------------------

SECRET_QUERY = "supersecretvalue123"
SECRET_SK = "sk-test-abcdefghijklmnopqrstuvwx"
SECRET_BEARER = "Bearer abcdef0123456789"
SECRET_EMAIL = "user@example.com"

_FAKE_SECRETS = (SECRET_QUERY, SECRET_SK, SECRET_BEARER, SECRET_EMAIL)


def make_finding(*, title: str = "Generic IDOR finding") -> Finding:
    """Generic product-independent finding (floor-agnostic)."""
    return Finding(
        vuln_type=VulnType.IDOR,
        severity=Severity.MEDIUM,
        title=title,
        description="Product-independent description.",
        target_url="https://target.example/account?id=7",
        evidence=Evidence(
            request_method="GET",
            request_url="https://target.example/account?id=7",
            response_status=200,
            response_body='{"ok": true}',
        ),
        source_agent="api_analyzer",
    )


def make_verdict(
    state: VerdictState,
    *,
    reason: str = "some_reason",
    promise_score: float = 0.33,
) -> HybridVerdict:
    return HybridVerdict(
        state=state,
        reason=reason,
        mechanical_floor=PayoutGradeResult(
            True, "payout_grade_satisfied", ["evidence.request_url"], None
        ),
        ai_judgement=None,
        reproduction=ReproductionOutcome("not_run", "test"),
        evidence_refs=("evidence.request_url",),
        promise_score=promise_score,
    )


def make_records() -> tuple:
    """Three records via the real manager (values masked at build time):
    needs_more / confirmed / parked. Distinct titles -> distinct finding
    ids (ledger keys must not collide)."""
    manager = CandidateLifecycleManager()
    finding_a = make_finding(title="Generic IDOR finding A")
    finding_b = make_finding(title="Generic IDOR finding B")
    finding_c = make_finding(title="Generic IDOR finding C")
    active = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding_a)
    confirmed = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding_b)
    manager.apply_verdict(
        confirmed, make_verdict(VerdictState.CONFIRMED, reason="hybrid_confirmed", promise_score=1.0), finding_b
    )
    parked = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding_c)
    manager.apply_verdict(
        parked,
        make_verdict(VerdictState.INCONCLUSIVE, reason="ai_no_prize_grade"),
        finding_c,
        extra_triggers=[("capability", "new_agent")],
    )
    return active, confirmed, parked


def make_secret_record(finding_id: str = "f-secret") -> CandidateRecord:
    """Record whose strings (incl. nested dict/list values) contain fake
    secrets — the save boundary must mask every one of them."""
    return CandidateRecord(
        finding_id=finding_id,
        state=LifecycleState.INCONCLUSIVE_PARKED,
        reason="budget_exhausted",
        vuln_type="idor",
        title="Generic title with " + SECRET_EMAIL + " and " + SECRET_BEARER,
        target_url_masked=(
            "https://target.example/login?token=" + SECRET_QUERY
            + "&apikey=" + SECRET_SK
        ),
        evidence_summary={
            "refs": ["evidence.request_url"],
            "nested": {"contact": SECRET_EMAIL},
            "items": [
                "https://target.example/api?t=" + SECRET_QUERY,
                SECRET_BEARER,
            ],
            "status": 200,
        },
        first_seen="2026-08-01T00:00:00+00:00",
        last_investigated="2026-08-01T00:00:00+00:00",
        budget_used=3,
        resurrection_count=0,
        promise_score=0.33,
        revisit_triggers=[("endpoint", "https://target.example/api")],
        resurrection_history=[],
    )


class TestRoundTrip:
    """save -> open の完全ラウンドトリップ"""

    def test_round_trip_equality_and_queries(self, tmp_path):
        path = tmp_path / "ledger.json"
        active, confirmed, parked = make_records()
        ledger = CandidateLedger.open(path)
        ledger.put(active)
        ledger.put(confirmed)
        ledger.put(parked)
        ledger.save()

        reopened = CandidateLedger.open(path)

        # 全フィールド等価
        for original in (active, confirmed, parked):
            assert reopened.get(original.finding_id) == original
        assert reopened.get("missing") is None
        # list_by_state（enum と str の両方）
        assert reopened.list_by_state(LifecycleState.NEEDS_MORE) == [active]
        assert reopened.list_by_state("confirmed") == [confirmed]
        assert reopened.list_by_state(LifecycleState.INCONCLUSIVE_PARKED) == [parked]
        # all(): 挿入順・件数
        assert reopened.all() == [active, confirmed, parked]
        assert [r.finding_id for r in reopened.all()] == [
            active.finding_id, confirmed.finding_id, parked.finding_id
        ]

    def test_put_upsert_preserves_order(self, tmp_path):
        path = tmp_path / "ledger.json"
        ledger = CandidateLedger.open(path)
        active, _, _ = make_records()
        ledger.put(active)
        updated = replace(active, reason="updated_reason")
        ledger.put(updated)

        assert ledger.get(active.finding_id) is updated
        assert ledger.all() == [updated]

    def test_empty_string_fields_round_trip(self, tmp_path):
        """空文字列フィールド（マスク早期 return 経路）も round-trip で不変"""
        path = tmp_path / "ledger.json"
        ledger = CandidateLedger.open(path)
        minimal = CandidateRecord(
            finding_id="f-min",
            state=LifecycleState.NEEDS_MORE,
            reason="",
            vuln_type="",
            title="",
            target_url_masked="",
            evidence_summary={"refs": []},
            first_seen="2026-08-01T00:00:00+00:00",
            last_investigated="2026-08-01T00:00:00+00:00",
            budget_used=1,
            resurrection_count=0,
            promise_score=0.0,
            revisit_triggers=[],
            resurrection_history=[],
        )
        ledger.put(minimal)
        ledger.save()

        reopened = CandidateLedger.open(path)

        assert reopened.get("f-min") == minimal

    def test_list_by_state_invalid_string_raises(self, tmp_path):
        ledger = CandidateLedger.open(tmp_path / "ledger.json")
        with pytest.raises(ValueError):
            ledger.list_by_state("no_such_state")


class TestSecretScan:
    """永続化ファイルに生秘密がゼロ（ネスト dict/list 含む）"""

    def test_no_raw_secrets_on_disk(self, tmp_path):
        path = tmp_path / "ledger.json"
        ledger = CandidateLedger.open(path)
        ledger.put(make_secret_record())
        ledger.save()

        text = path.read_text(encoding="utf-8")

        for secret in _FAKE_SECRETS:
            assert secret not in text
        assert "[PII:" in text

    def test_no_raw_arbitrary_secrets_in_free_text(self, tmp_path):
        """SGK-2026-0444 hardening: arbitrary opaque secrets (no PII pattern,
        not in a URL query) after a secret-bearing key in a free-text field
        must still be masked. Regression for the leak the URL/pattern-only
        masking missed."""
        opaque = {
            "pw": "hunter2plainpw",
            "cookieval": "OPAQUESESSION9999",
            "tok": "randomopaquetoken4242",
            "bearerval": "opaqueBearerAAA111",
        }
        rec = CandidateRecord(
            finding_id="f-freetext",
            state=LifecycleState.INCONCLUSIVE_PARKED,
            reason="password=" + opaque["pw"] + " secret=" + opaque["tok"],
            vuln_type="idor",
            title="Cookie: session=" + opaque["cookieval"] + "; theme=dark",
            target_url_masked="https://target.example/x",
            evidence_summary={
                "req": "Authorization: Bearer " + opaque["bearerval"],
                "nested": {"cookie": opaque["cookieval"]},
            },
            first_seen="2026-08-01T00:00:00+00:00",
            last_investigated="2026-08-01T00:00:00+00:00",
            budget_used=1,
            resurrection_count=0,
            promise_score=0.3,
            revisit_triggers=[],
            resurrection_history=[],
        )
        path = tmp_path / "ledger.json"
        ledger = CandidateLedger.open(path)
        ledger.put(rec)
        ledger.save()
        text = path.read_text(encoding="utf-8")
        for secret in opaque.values():
            assert secret not in text, f"raw secret leaked: {secret}"
        assert "[PII:" in text
        # record survives reload (masking did not corrupt the structure).
        assert CandidateLedger.open(path).get("f-freetext") is not None

    def test_masking_is_idempotent_no_drift(self, tmp_path):
        """再保存 → 再ロードで値が完全一致（二重マスクなし・ドリフトなし）"""
        path = tmp_path / "ledger.json"
        ledger = CandidateLedger.open(path)
        ledger.put(make_secret_record())
        ledger.save()

        snapshot = {r.finding_id: r for r in CandidateLedger.open(path).all()}
        # 2 回目の save -> reload
        again = CandidateLedger.open(path)
        again.save()
        reloaded = CandidateLedger.open(path)
        assert {r.finding_id: r for r in reloaded.all()} == snapshot
        # 3 回目でも不変（save のたびに同じ出力）
        reloaded.save()
        final = CandidateLedger.open(path)
        assert {r.finding_id: r for r in final.all()} == snapshot
        # ディスク上の JSON も同一
        assert final.path.read_text(encoding="utf-8") == again.path.read_text(encoding="utf-8")


class TestCorruptionFailSafe:
    """破損ファイルは quarantine して空台帳で続行（fail-safe）"""

    def test_garbage_json_quarantined(self, tmp_path):
        path = tmp_path / "ledger.json"
        path.write_bytes(b"\x00garbage\xff\xfe")

        ledger = CandidateLedger.open(path)

        assert ledger.all() == []
        quarantines = list(tmp_path.glob("ledger.json.corrupt-*"))
        assert len(quarantines) == 1
        assert not path.exists()  # 元ファイルは移動済み

    def test_non_utf8_quarantined(self, tmp_path):
        path = tmp_path / "ledger.json"
        path.write_bytes(b"\xff\xfe\x00\x01")

        ledger = CandidateLedger.open(path)

        assert ledger.all() == []
        assert len(list(tmp_path.glob("ledger.json.corrupt-*"))) == 1

    def test_non_object_payload_quarantined(self, tmp_path):
        path = tmp_path / "ledger.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")

        ledger = CandidateLedger.open(path)

        assert ledger.all() == []
        assert len(list(tmp_path.glob("ledger.json.corrupt-*"))) == 1

    def test_quarantine_rename_failure_continues(self, tmp_path, monkeypatch, caplog):
        path = tmp_path / "ledger.json"
        path.write_bytes(b"garbage")

        def fail_rename(src, dst):
            raise OSError("rename failed")

        monkeypatch.setattr(os, "rename", fail_rename)
        with caplog.at_level(logging.WARNING, logger="src.core.validation.candidate_ledger"):
            ledger = CandidateLedger.open(path)

        assert ledger.all() == []  # 空台帳で継続（fail-safe）
        assert path.exists()       # quarantine 失敗時は元ファイルを残す
        assert any("quarantine" in r.message for r in caplog.records)

    def test_load_oserror_propagates(self, tmp_path):
        """OSError は伝播（fail loud per codingrules）"""
        dir_path = tmp_path / "adir"
        dir_path.mkdir()

        with pytest.raises(OSError):
            CandidateLedger.open(dir_path)


class TestMissingFileAndAtomicSave:
    """欠損ファイル fail-safe + 原子的書込"""

    def test_missing_file_empty_and_save_creates_valid_json(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "ledger.json"  # 親ディレクトリなし

        ledger = CandidateLedger.open(path)
        assert ledger.all() == []  # エラーなしで空台帳

        ledger.save()  # mkdir parents=True で作成

        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["ledger_schema_version"] == LEDGER_SCHEMA_VERSION
        assert data["candidates"] == {}
        assert "updated_at" in data
        # 一時ファイルの残骸なし
        assert not list(tmp_path.glob("**/.candidate_ledger_*"))

    def test_save_failure_cleans_temp_file(self, tmp_path, monkeypatch):
        path = tmp_path / "ledger.json"
        ledger = CandidateLedger.open(path)
        ledger.put(make_secret_record())

        def fail_rename(src, dst):
            raise OSError("rename failed")

        monkeypatch.setattr(os, "rename", fail_rename)
        with pytest.raises(OSError):
            ledger.save()

        assert not list(tmp_path.glob(".candidate_ledger_*"))  # 掃除済み
        assert not path.exists()  # 未完成ファイルは残らない


class TestSchemaAndMalformedRecords:
    """未知 schema は best-effort・不正レコードはスキップ"""

    def _saved_ledger(self, tmp_path) -> "CandidateLedger":
        path = tmp_path / "ledger.json"
        ledger = CandidateLedger.open(path)
        ledger.put(make_secret_record("f-good"))
        ledger.save()
        return ledger

    def test_unknown_schema_version_best_effort(self, tmp_path, caplog):
        ledger = self._saved_ledger(tmp_path)
        data = json.loads(ledger.path.read_text(encoding="utf-8"))
        data["ledger_schema_version"] = 99
        ledger.path.write_text(json.dumps(data), encoding="utf-8")

        with caplog.at_level(logging.WARNING, logger="src.core.validation.candidate_ledger"):
            reopened = CandidateLedger.open(ledger.path)

        assert reopened.get("f-good") is not None  # best-effort で読める
        assert any("schema version" in r.message for r in caplog.records)

    def test_malformed_records_skipped(self, tmp_path, caplog):
        ledger = self._saved_ledger(tmp_path)
        data = json.loads(ledger.path.read_text(encoding="utf-8"))
        good = data["candidates"]["f-good"]
        data["candidates"]["bad_state"] = dict(good, state="not_a_state")
        data["candidates"]["bad_shape"] = "garbage"
        data["candidates"]["bad_triggers"] = dict(
            good, revisit_triggers=[["a", "b", "c"]]
        )
        ledger.path.write_text(json.dumps(data), encoding="utf-8")

        with caplog.at_level(logging.WARNING, logger="src.core.validation.candidate_ledger"):
            reopened = CandidateLedger.open(ledger.path)

        assert reopened.get("f-good") is not None
        assert reopened.get("bad_state") is None
        assert reopened.get("bad_shape") is None
        assert reopened.get("bad_triggers") is None
        assert any("malformed" in r.message for r in caplog.records)


class TestIntegrationAcrossRuns:
    """run 跨ぎの完全ライフサイクル（apply -> save -> reopen -> revisit -> apply）"""

    def test_full_lifecycle_across_runs(self, tmp_path):
        path = tmp_path / "ledger.json"
        manager = CandidateLifecycleManager()
        finding = make_finding()

        # run 1: 調査して棚上げ -> 永続化
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding)
        parked = manager.apply_verdict(
            record,
            make_verdict(VerdictState.INCONCLUSIVE, reason="ai_no_prize_grade"),
            finding,
        )
        ledger = CandidateLedger.open(path)
        ledger.put(parked)
        ledger.save()

        # run 2: 再オープン -> 新情報で復活
        reopened = CandidateLedger.open(path)
        stored = reopened.get(parked.finding_id)
        assert stored is not None
        assert stored.state == LifecycleState.INCONCLUSIVE_PARKED
        token = stored.revisit_triggers[0]
        revived = manager.revisit([stored], [token])[0]
        assert revived.state == LifecycleState.NEEDS_MORE
        assert revived.resurrection_count == 1

        # run 3: 復活後も判定を継続（予算リセット済み）
        active = manager.apply_verdict(
            revived,
            make_verdict(VerdictState.CONFIRMED, reason="hybrid_confirmed", promise_score=1.0),
            finding,
        )
        assert active.state == LifecycleState.CONFIRMED
        assert active.budget_used == 1
        reopened.put(active)
        reopened.save()

        # run 4: 最終確認
        final = CandidateLedger.open(path).get(parked.finding_id)
        assert final is not None
        assert final.state == LifecycleState.CONFIRMED
        assert final.reason == "hybrid_confirmed"
        assert final.resurrection_count == 1
        assert final.budget_used == 1
