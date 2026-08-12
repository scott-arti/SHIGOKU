---
task_id: SGK-2026-0444
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0443_shared-hybrid-confirmation-judge.md
- docs/shigoku/reports/2026-08-12_sgk-2026-0444_candidate-lifecycle-and-parked-store_work_report.md
- docs/shigoku/worklogs/2026-08-12_sgk-2026-0444_candidate-lifecycle-and-parked-store_work_log.md
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/validation,workspace/projects
---

# 実装計画: T2 — 候補ライフサイクル ＋ 棚上げ保管（candidate_ledger）＋ 復活

（親ロードマップ: SGK-2026-0442。設計方針・不変条件・保管仕様はそちらが正本。）

## 背景

- T1（0443）で共有ハイブリッド判定 `validate_finding()` が rich verdict（`VerdictState` 5状態＋reason＋evidence_refs＋promise_score）を返すようになった。
- しかし「証明できない候補が永遠に活動列に残る／溜まる」問題への対処は未実装。棚上げ保管も無い。

## 目的

**候補の一生（ライフサイクル）を管理する仕組みと、棚上げ保管（run 跨ぎ）＋新情報での復活を実装する。**
本タスクは**サービス/ストア単体**（swarm 実行ループへの配線・実確定は T3、Haddix 明記は T4。ここではやらない）。

## スコープ（T2 のみ）

1. **ライフサイクル管理**（T1 verdict を消費）:
   - 状態遷移: `needs_more` は**調査予算**（回数/時間・設定値）内で継続。予算切れ→`inconclusive_parked`。`needs_human`→人間送り。`confirmed`/`refuted`は終端。
   - **証明できないだけでは refute しない**（T1 の契約踏襲）。予算切れは棚上げであって却下ではない。
   - 見込み順（`promise_score`）に予算配分するためのランキング関数。
2. **棚上げ保管ストア（candidate_ledger）**:
   - 場所: `workspace/projects/<target>/candidate_ledger.json`（**run 跨ぎで永続**・`scans/`等と同列）。
   - 鍵: `Finding.id`（12桁 md5・既存）。
   - レコード: `{finding_id → {state, evidence(**マスク済・0439方式**), reason, first_seen, last_investigated, budget_used, promise_score, revisit_triggers}}`。**生の秘密を保存しない。**
   - API: `get(finding_id)` / `put(record)` / `list_by_state(state)` / `all()`。原子的書き込み・破損耐性（不正 JSON はfail-safeで空扱い、既存 recon_state 等の作法に倣う）。
3. **復活（revisit）**:
   - 次 run で **新情報（新 capability / 新アカウント / 新 endpoint 等）が `revisit_triggers` に合致した parked 候補のみ**再活性化（活動列へ戻す）。**盲目的な再試行はしない。**
   - revisit_trigger の生成規則（何を「新情報」とみなすか）を製品非依存に定義。

## 診断先行 ＋ 設計承認関門
実装前に: (a) ライフサイクル状態機械（遷移・予算切れ→棚上げ/人間送りの条件）、(b) ledger スキーマとマスク方針、
(c) revisit_trigger の定義（新情報の判定・盲目再試行防止）、(d) 予算・ランキングのパラメータ — を提示し承認を得てから実装。

**設計承認済み（2026-08-12・ユーザー承認）**: 下記 設計付録 A〜F を実装契約として固定。
決定事項 D1〜D5 は承認済み（D5=マスク済サマリ投影・D1=INCONCLUSIVE 即棚上げ）。

## 不変条件（ロードマップ §不変条件に従う）
- **確定の敷居を下げない**（T1 判定は無変更で利用・ここでは確定を生成しない。状態管理と保管のみ）。
- **証明不足だけで却下しない**（棚上げ＝消さない・取り出せる）。
- 秘密は**マスク保存**（生秘密を ledger に書かない）。カーブフィッティング禁止（preflight exit 0・docs opaque）。
- PCR-P1 無改変・schema additive・**サービス単体（swarm 未配線）で既存挙動 byte-identical**。

## 完了条件（設計承認後）
1. 製品非依存 fixture で self-checking: needs_more→予算内継続→予算切れで inconclusive_parked／needs_human→人間送り／confirmed・refuted は終端／**証明不足だけでは refute しない**／promise_score 順ランキング。
2. **棚上げ round-trip**: put→(別プロセス/再ロード)→get で復元・**マスク保存で生秘密ゼロ**（secret-scan）。破損 JSON でも fail-safe。
3. **revisit**: 新情報合致で parked→活動列復帰・非合致では復帰しない、を実証。
4. 既存挙動 byte-identical（未配線・回帰0）・PCR-P1 diff 0・preflight exit 0・docs opaque・validator 0。

## NOT in scope（T2）
- swarm 実行ループへの配線・実確定の発生（T3）。Haddix レポート明記（T4）。T1 判定ロジックの変更。実VDP外部・状態変更・m3b 以上。

## 参照
- `src/core/validation/finding_validator.py`（T1 verdict 契約）・`src/core/models/finding.py`（安定 id）・0439（マスク）・`recon_state.json` 保存作法（原子的・破損耐性）。

---

# 設計付録（ユーザー承認済み 2026-08-12・実装契約として固定）

## A. 状態機械

**永続ライフサイクル状態（5種）**: `needs_more`（活動・予算内）/ `inconclusive_parked`（棚上げ・復活可能）/
`needs_human`（人間送り・保留）/ `confirmed`（終端）/ `refuted`（終端）

T1 `HybridVerdict` を消費する遷移表:

| # | 現在 | T1 verdict | 条件 | 次状態 | 備考 |
|---|---|---|---|---|---|
| T1 | (新規) | 任意 | 初回評価 | needs_more | レコード作成・budget_used=1 |
| T2 | needs_more | CONFIRMED | — | confirmed | 終端 |
| T3 | needs_more | REFUTED | — | refuted | 終端（反証3種のみ到達可能） |
| T4 | needs_more | NEEDS_HUMAN | — | needs_human | 人間送り |
| T5 | needs_more | NEEDS_MORE | 予算残 | needs_more | 継続（budget_used+1） |
| T6 | needs_more | NEEDS_MORE | 予算切れ ∧ promise < 0.67 | inconclusive_parked | 棚上げ（reason=budget_exhausted）・却下ではない |
| T7 | needs_more | NEEDS_MORE | 予算切れ ∧ promise ≥ 0.67 | needs_human | 見込み高→人間送りへ昇格 |
| T8 | needs_more | INCONCLUSIVE | — | inconclusive_parked | AI「賞金級でない」の軟判断・即棚上げ |
| T9 | inconclusive_parked | — | 新情報 ∩ triggers − 消費済 ≠ ∅ | needs_more | 復活・予算リセット・resurrection_count+1 |
| T10 | needs_human | — | 人間解決 | 変更なし | 人間パスは T4 スコープ・保留 |

決定事項:
- **D1**: T1 `INCONCLUSIVE`（ai_no_prize_grade）は即棚上げ（予算を消費しない）。却下ではない（新情報で復活可能）。
- **D2**: 予算切れ時の人間送りは promise_score ≥ 0.67（機械フロア通過＋AI賞金級 or 再現一致）に限定。
- **D3**: 「却下は反証のみ」を構造的に強制 — lifecycle ロジックは `REFUTED` verdict 以外から `refuted` を生成できない。
- **D4**: 復活時は予算リセット（新たな調査切片）＋ `resurrection_count` 加算（監査用）。
- **invariant**: `apply_verdict()` は needs_more 以外（parked/needs_human/終端）では no-op。棚上げからは `revisit()` のみで復帰（盲目再試行なし）。

## B. Ledger スキーマとマスク方針

- **場所**: `workspace/projects/<target>/candidate_ledger.json`（run 跨ぎ永続・`scans/` と同列）。鍵 = `Finding.id`（12桁 md5・既存）。

```json
{
  "ledger_schema_version": 1,
  "updated_at": "…",
  "candidates": {
    "<finding_id>": {
      "state": "inconclusive_parked",
      "reason": "budget_exhausted",
      "vuln_type": "idor",
      "title": "…",
      "target_url_masked": "https://example.com/api?token=[PII:VALUE:ab12cd34]",
      "evidence_summary": {"refs": ["request_url","response_status"], "request_url_masked": "…", "response_status": 200},
      "first_seen": "…", "last_investigated": "…",
      "budget_used": 3, "resurrection_count": 0,
      "promise_score": 0.67,
      "revisit_triggers": [["endpoint","example.com/api"],["vuln_type","idor"]],
      "resurrection_history": []
    }
  }
}
```

- **D5（承認済み）: evidence はマスク済サマリ投影** — フィールド名（refs）＋マスク済 URL＋ステータス数値のみ。ボディ/ヘッダ値は書かない（pii_masker パターンはボディ内任意トークンを保証マスクできないため、値そのものを書かないことで「生秘密ゼロ」を構造的に満たす）。拡張は将来 additive。
- **マスク境界（最低層 write API・再帰）**: URL は 0439 `mask_url_query_values`（query 値 deny-by-default）。他文字列は `pii_masker.mask()` を dict/list 再帰適用。既マスクトークンは二重マスクされない（冪等）。**token_map は永続化しない**（run スコープ・ロード時 unmask しない・トークンは run 跨ぎで安定プレースホルダ）。
- **トリガートークンの秘密対策**: endpoint は host+path 正規化（query 除去）。account 系は sha256[:12] ハッシュ保存。
- **書込**: `tempfile.mkstemp`（同一ディレクトリ）+ fsync + `os.rename`（recon_state.py と同型・原子的）。
- **破損耐性**: 不正 JSON は load 時に警告＋元ファイルを `.corrupt-<ts>` へ quarantine（次回 save で上書き破壊しない）＋空 ledger で fail-safe。schema_version 未知は警告＋best-effort load。個別レコード不正は警告＋スキップ。OSError は伝播（fail loud）。
- **API**: `CandidateLedger(path)` — `open(path)` / `load()` / `get(finding_id)` / `put(record)`（upsert）/ `list_by_state(state)` / `all()` / `save()`（原子的・バッチ flush）。

## C. 復活条件（何が「新情報」か）

- **型付き世界状態トークン語彙**（製品非依存・固定）: `("vuln_type", value)` / `("endpoint", 正規化host+path)` / `("capability", token)` / `("account", sha256[:12])`
- **棚上げ時の trigger 記録（既定・製品非依存）**: 常に `("vuln_type", …)`。endpoint は target_url＋evidence の request_url から正規化。capability は `source_agent` と各 `tags`（製品自身のエージェント/タグ語彙）。T3 配線側から `extra_triggers` 追加可（例: 「第2アカウント必要」）。
- **復活規則（決定的・盲目再試行を構造的に排除）**: run が「今回観測した新情報トークン集合」を供給 → `(新情報 ∩ triggers) − resurrection_history ≠ ∅` の棚上げ候補のみ復活。**合致トークンは resurrection_history に消費記録** — 同一トークンで再トリガー不可能（復活→再棚上げのフラッピングなし）。非合致は一切評価しない（盲目再試行なし）。
- T2 は `derive_triggers(finding)` と `revisit(new_information)`（復活レコード返却）を提供。swarm からの新情報供給は T3。

## D. 予算・ランキング

- **パラメータ（コンストラクタ既定値・T2 では YAML 配線しない）**:
  - `max_visits = 3`（活動期間中の評価回数・復活時リセット）
  - `max_age_days = 30`（first_seen 起算・超過で強制棚上げ）
  - `human_promise_threshold = 0.67`（予算切れ時 promise ≥ 0.67 → needs_human）
  - `run_budget = 10`（run 毎の調査キャップ）
- **ランキング**: `allocate_investigation_budget(active, run_budget)` — `(promise_score 降順, last_investigated 昇順, first_seen 昇順)` で top-N 選出。promise_score は T1 の値（ゲート充足数/3）を**そのまま使用**・再計算しない（カーブフィッティング禁止）。予算は実際に評価したときだけ `budget_used += 1`。
- YAML 配線（config/shigoku.yaml への反映）は **T3 の deferred_followup** として追跡。

## E. API 契約

- `src/core/validation/candidate_lifecycle.py`: `LifecycleState`（enum・5値）/ `CandidateRecord`（dataclass・§B フィールド）/ `CandidateLifecycleManager`（`apply_verdict` / `derive_triggers` / `revisit` / `allocate_investigation_budget` / `normalize_endpoint` / `hash_account_token`）
- `src/core/validation/candidate_ledger.py`: `CandidateLedger` / `LEDGER_SCHEMA_VERSION = 1`
- `src/core/validation/__init__.py`: 追加 export のみ（additive）。

## F. 必須テスト・検証コマンド

製品非依存 fixture（target.example）・`tests/core/validation/`:

1. 状態機械: 遷移表全行（T1〜T9）・予算継続→切れ→棚上げ／promise 高→人間送り／INCONCLUSIVE→即棚上げ（refute ではない）／refuted は verdict 経由のみ／終端・parked・needs_human は no-op。
2. ledger round-trip: put→save→新規 open→get で全フィールド同一復元・**secret-scan で生秘密ゼロ**（fake secret を fixture に埋め、ファイル内容に生文字列が存在しないこと＋`[PII:` が存在すること）・再 save で冪等（二重マスクなし）。
3. 破損 JSON: fail-safe 空＋quarantine ファイル生成・欠損ファイルは空・原子的書込（temp 残骸なし）。
4. 復活: 新情報合致→needs_more 復帰（予算リセット・count+1・履歴記録）／非合致→復帰しない／**同一トークン再トリガー不可**（盲目再試行防止）。
5. ランキング: promise 降順・キャップ・needs_more のみ対象。
6. 統合: apply→put/save→reopen→revisit→apply の run 跨ぎフロー。

検証コマンド: 対象単体 `pytest tests/core/validation/test_candidate_lifecycle.py tests/core/validation/test_candidate_ledger.py -q` →
T1 回帰 `pytest tests/core/validation/test_finding_validator.py tests/core/validation/test_hybrid_verdict_selfcheck.py -q` →
`git diff --stat` で finding_validator.py / vdp_evidence_validator.py / task_queue.py（PCR-P1）**diff 0** →
`python3 scripts/check_vdp_product_independence.py` **exit 0** → `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー。
