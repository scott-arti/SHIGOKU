---
task_id: SGK-2026-0303
doc_type: plan
status: done
parent_task_id: SGK-2026-0280
related_docs:
- docs/shigoku/subtasks/2026-06-09_masterconductor-seed-helper-priority-split_subtask_plan.md
- docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
- docs/shigoku/reports/2026-06-09_master-conductor-split_work_report.md
- docs/shigoku/reports/2026-06-17_SGK-2026-0303_work_report.md
- docs/shigoku/worklogs/2026-06-17_SGK-2026-0303_work_log.md
title: 'MasterConductor seed target service 追加分割計画: selector/collector cluster'
created_at: '2026-06-17'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/engine/master_conductor_recon_seed_target_service.py
---

# 実装計画書：MasterConductor seed target service 追加分割計画: selector/collector cluster

## 1. 達成したいゴール（ユーザー視点）
- [x] `src/core/engine/master_conductor_recon_seed_target_service.py` の公開 import path を維持したまま、scope / selector / collector の責務を外出しし、service 自体を coordinator へ薄化できること。
- [x] `ReconSeedTargetService` の seed ranking、scope 判定、history replay / scenario probe / CSRF / XSS seed 選定結果を変えず、`master_conductor.py` / `master_conductor_facade.py` からの既存利用を壊さないこと。
- [x] 現在 1,222 行の service を、facade 250-400 行、分割先 200-500 行目安に整理し、後続の MasterConductor 本丸分割に再利用できる境界を作ること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor_recon_seed_target_service.py`: （修正）`ReconSeedTargetService` の公開 import path を維持する facade / coordinator。
  - `src/core/engine/master_conductor_recon_url_scope.py`: （新規）`_UrlScopeResolver` 相当の stateless URL 正規化 / scope 判定 helper を保持する候補。
  - `src/core/engine/master_conductor_recon_seed_selector.py`: （新規）`_SeedTargetSelector` 相当の scorer / refine / phase2-on-empty policy を保持する候補。
  - `src/core/engine/master_conductor_recon_seed_collectors.py`: （新規）history replay / tagged file / scenario probe / CSRF / XSS seed 収集 helper を保持する候補。
  - `src/core/engine/master_conductor.py`: （参照のみ）既存 wrapper / planner 呼び出しが維持されるかの確認対象。
  - `src/core/engine/master_conductor_facade.py`: （参照のみ）`ReconSeedTargetService` の import path 互換確認対象。
  - `tests/core/engine/test_master_conductor_api_candidate_routing.py`: （既存）API candidate routing / seed ranking の代表回帰。
  - `tests/core/engine/test_master_conductor_scenario_probes.py`: （既存）scenario probe / scope 判定 / target 選定の代表回帰。
  - `tests/core/intelligence/test_phase0_risk_clearance_checklist.py`: （既存）policy 系の関連回帰。
- **データの流れ / 依存関係:**
  - `MasterConductor` / `MasterConductorFacade` -> `ReconSeedTargetService` facade -> URL/scope helper + seed selector + collectors -> selected targets / evidence / score reasons を返却。

## 2.1 分割境界の基本方針
- `ReconSeedTargetService` の public class 名と import path は保持し、内部 helper だけを sibling module に平置きで移す。
- `_UrlScopeResolver` は stateless pure helper に限定し、settings や context を持たせない。
- `_SeedTargetSelector` は settings / target / context snapshot を使う scorer と refine policy に限定し、file I/O や JSONL 読み込みは collector へ逃がす。
- collector 側は history replay / tagged file / scenario seed 収集の pure-ish helper 群に寄せ、queue mutation や `MasterConductor` 逆参照は禁止する。
- 既存 tests や wrapper が internal helper 名に依存していなくても、必要なら alias を一時的に残して移行コストを下げる。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `context`, `target`, `settings`, tagged JSONL / history file path、`Task`、scenario probe / CSRF / XSS 候補、budget / scope host 情報
- **出力/結果 (Output):** selected target list、normalized URL / host / scope 判定、evidence map、score reasons、phase2-on-empty policy decision
- **制約・ルール:**
  - `ReconSeedTargetService` は引き続き `src.core.engine.master_conductor_recon_seed_target_service` から import できること。
  - `master_conductor.py` / `master_conductor_facade.py` に大規模な呼び出し側書き換えを要求しないこと。
  - 破損した JSONL 行、存在しない file、URL parse 失敗時の「skip して継続」挙動は変えないこと。
  - score 算出順序、scope 判定基準、phase2-on-empty 判定の既存挙動は first pass で変えないこと。
  - `MasterConductor` instance の逆参照、task queue mutation、global state 直接更新を新規 module へ持ち込まないこと。
  - 目安サイズ:
    - `master_conductor_recon_seed_target_service.py`: 250-400 行
    - `master_conductor_recon_url_scope.py`: 150-250 行
    - `master_conductor_recon_seed_selector.py`: 250-450 行
    - `master_conductor_recon_seed_collectors.py`: 300-500 行

## 3.1 先に固定する回帰観点
- import / integration 回帰:
  - `from src.core.engine.master_conductor_recon_seed_target_service import ReconSeedTargetService`
  - `master_conductor.py` / `master_conductor_facade.py` 経由の service 解決。
- behavior 回帰:
  - scope host 解決と `is_target_url_in_scope` 判定。
  - scenario probe target 選定。
  - CSRF / XSS seed scorer と refine 順序。
  - history replay / tagged path 解決の fallback。
- error tolerance 回帰:
  - 壊れた JSONL、存在しない path、malformed URL を受けても候補 skip で継続すること。

## 3.2 DeepSeek 向け実装ルール
- 既存 service を一気に分解せず、`_UrlScopeResolver` -> `_SeedTargetSelector` -> collector 群の順で外出しする。
- scorer / collector を移す前に、既存テストで selected targets と score reason の代表ケースが固定されているか確認し、不足があればテストを追加する。
- `MasterConductor` 側の wrapper 命名や呼び出し surface は最後まで保持し、service 側の薄化だけで吸収する。
- file I/O と score policy を同じ patch で触らない。1 concern per patch を守る。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `master_conductor_recon_seed_target_service.py` 内の public method 群と内部 cluster を棚卸しし、URL/scope、selector/scorer、collector/file-path の境界を確定する。
- [x] ステップ2: `tests/core/engine/test_master_conductor_api_candidate_routing.py`、`tests/core/engine/test_master_conductor_scenario_probes.py`、`tests/core/intelligence/test_phase0_risk_clearance_checklist.py` を読み、出力 parity が足りない箇所があれば seed ranking / malformed input 用の characterization test を最小追加する。
- [x] ステップ3: `_UrlScopeResolver` 相当を `master_conductor_recon_url_scope.py` へ抽出し、`normalize_url_candidate` / `extract_host_candidate` / `is_target_url_in_scope` / `resolve_task_target` を移す。service からは委譲だけにする。
- [x] ステップ4: `_SeedTargetSelector` 相当を `master_conductor_recon_seed_selector.py` へ抽出し、score / refine / phase2-on-empty policy を移す。settings / target / context 依存はここに閉じ込める。
- [x] ステップ5: history replay、recon file path、scenario probe seed、CSRF / XSS collector 群を `master_conductor_recon_seed_collectors.py` へ抽出し、file I/O と candidate 収集の責務を service から外す。
- [x] ステップ6: `ReconSeedTargetService` を coordinator として薄化し、constructor で helper を束ねるだけの構成に整理する。必要なら internal alias を暫定維持して差分を小さくする。
- [x] ステップ7: `master_conductor.py` / `master_conductor_facade.py` の import と service 利用を再確認し、consumer 側に余計な修正が発生していないことを確認する。

## 4.1 推奨検証コマンド
```bash
.venv/bin/pytest tests/core/engine/test_master_conductor_api_candidate_routing.py tests/core/engine/test_master_conductor_scenario_probes.py tests/core/intelligence/test_phase0_risk_clearance_checklist.py -q
.venv/bin/python -m compileall src/core/engine/master_conductor_recon_seed_target_service.py src/core/engine/master_conductor_recon_url_scope.py src/core/engine/master_conductor_recon_seed_selector.py src/core/engine/master_conductor_recon_seed_collectors.py
```

## 4.2 完了条件
- `ReconSeedTargetService` の公開 import path が維持され、呼び出し側の大規模変更が不要である。
- service 本体が coordinator 中心へ薄化し、1,222 行から 250-400 行程度まで縮小している。
- scope / seed selector / collector の責務が分離され、各ファイルが 200-500 行程度に収まっている。
- targeted tests で selected targets / scope / malformed input tolerance の代表ケースが通る。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:高] seed ranking の微差はテストが粗いと見逃しやすい - parity 観点を先に補強し、selected target と score reason を代表 fixture で固定する。（既存テスト68件が全passしており、selected target / scope / malformed input tolerance の代表ケースが確認済み）
- [ ] [重要度:中] collector 群までまとめて外出しすると、新ファイル側が再び肥大化する可能性がある - file path / history replay / scenario probe で論理分割し、必要なら後続でさらに二段分割する。（`master_conductor_recon_seed_collectors.py` が 827 行に達しており、後続分割タスク SGK-2026-0307 へ委譲）
- [ ] [重要度:中] malformed JSONL / URL の silent skip は設計負債だが、今回混ぜて厳格化すると挙動変更になる - 挙動変更は別 task に分離する。（残リスク: 後続 task 未起票）
- [ ] [重要度:中] MasterConductor 本体の巨大さは残る - 今回は seed target cluster の再整理に留め、dispatch / execution loop は別計画で扱う。（残リスク: SGK-2026-0264 以降の継続タスクとして追跡中）

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0303-D01
    title: "継続監視: MasterConductor seed ranking と malformed input tolerance"
    reason: "分割後も selected target parity と skip 挙動の継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "seed service 周辺の回帰監視 task を active で起票し、dispatch/execution loop 分割の前提条件として扱う"
```
