---
task_id: SGK-2026-0306
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/specs/fix_smart_xss_logic.md
- docs/shigoku/specs/dvwa_medium_bypass_phase1.md
- docs/shigoku/plans/2026-05-24_xss-hunter-enhancement_plan.md
title: '巨大ファイル分割計画: SmartXSS / SmartSQLi 分割'
created_at: '2026-06-17'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/agents/swarm/injection/smart_xss.py, src/core/agents/swarm/injection/smart_sqli.py
---

# 実装計画書：巨大ファイル分割計画: SmartXSS / SmartSQLi 分割

## 1. 達成したいゴール（ユーザー視点）
- [x] `src/core/agents/swarm/injection/smart_xss.py` と `smart_sqli.py` の公開 import path を維持したまま、shared form helper と各 hunter 専用ロジックを外出しできること。
- [x] `SmartXSSHunter` / `SmartSQLiHunter` の public 挙動、`InjectionManagerAgent` からの利用、integration test の monkeypatch points を壊さずに分割できること。
- [x] 現在 1,319 行の `smart_xss.py` と 1,183 行の `smart_sqli.py` を、各 facade 400 行前後、専用 helper 250-700 行目安へ整理し、将来の追加 payload / runtime 対応を入れやすくすること。→ **達成: smart_xss.py=363行, smart_sqli.py=320行 (Phase 2 完了)**

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/smart_xss.py`: （修正）`SmartXSSHunter` の公開 import path を維持する facade / coordinator。
  - `src/core/agents/swarm/injection/smart_sqli.py`: （修正）`SmartSQLiHunter` の公開 import path を維持する facade / coordinator。
  - `src/core/agents/swarm/injection/form_parsing.py`: （新規）`_fetch_and_parse_form` 相当の shared helper を保持する候補。
  - `src/core/agents/swarm/injection/smart_xss_reflection.py`: （新規）reflection / payload injection / context analysis helper を保持する候補。
  - `src/core/agents/swarm/injection/smart_xss_runtime.py`: （新規）stored flow、runtime confirmation、XCTO/runtime-red 系 helper を保持する候補。
  - `src/core/agents/swarm/injection/smart_sqli_payloads.py`: （新規）payload family、encoding、request variation helper を保持する候補。
  - `src/core/agents/swarm/injection/smart_sqli_runtime.py`: （新規）submission、response classification、evidence build helper を保持する候補。
  - `src/core/agents/swarm/injection/manager_internal/specialist_factory.py`: （参照のみ）hunter import path の互換確認対象。
  - `tests/core/agents/swarm/test_smart_xss.py`: （既存）XSS の代表フロー回帰。
  - `tests/core/agents/swarm/injection/test_smart_xss_logic.py`: （既存）request / logic の回帰。
  - `tests/core/agents/swarm/injection/test_smart_xss_xcto10_runtime_red.py`: （既存）runtime-red / X-CTO 周辺の回帰。
  - `tests/integration/test_smart_xss_hunter_integration.py`: （既存）XSS integration 代表。
  - `tests/integration/test_smart_sqli_hunter.py`: （既存）SQLi integration 代表。
  - `tests/unit/test_smart_sqli_post.py`: （既存）POST/JSON path 回帰。
  - `tests/core/agents/swarm/test_injection_manager.py`: （既存）manager 経由の hunter 呼び出し回帰。
- **データの流れ / 依存関係:**
  - `InjectionManagerAgent` / direct hunter call -> `smart_xss.py` or `smart_sqli.py` facade -> shared form parsing + hunter-specific helper -> finding / evidence / runtime result。

## 2.1 分割境界の基本方針
- `smart_xss.py` と `smart_sqli.py` は削除せず、公開 class と monkeypatch point を持つ facade として残す。
- shared 化するのは first pass では `_fetch_and_parse_form` 相当の pure-ish helper を中心に留め、XSS と SQLi の判断ロジックを無理に共通化しない。
- `SmartXSSHunter` と `SmartSQLiHunter` は別 module / 別 class のまま維持し、1つの generic hunter へ寄せない。
- `tests/core/agents/swarm/test_smart_xss.py` が `src.core.agents.swarm.injection.smart_xss._fetch_and_parse_form` を patch しているため、facade 側に同名 alias を残すか、互換 wrapper を維持する。
- 将来 `smart_cmd_ssrf.py` も同じ helper を使える余地は残すが、今回の主スコープには含めない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** target URL、auth headers、request metadata、HTML form、payload 候補、browser/runtime signal、LLM loop input、manager からの config
- **出力/結果 (Output):** finding / description / evidence / verification status、runtime confirmation、POST/JSON submission result、tool runner から観測できる class instance 挙動
- **制約・ルール:**
  - `SmartXSSHunter` は引き続き `src.core.agents.swarm.injection.smart_xss` から、`SmartSQLiHunter` は `smart_sqli` から import できること。
  - `InjectionManagerAgent` と `manager_internal/specialist_factory.py` が期待する import path / class 名を変えないこと。
  - `_fetch_and_parse_form` の monkeypatch point は facade 側で維持すること。
  - async 挙動、HTTP request 順序、payload 試行順、description 生成の既存挙動は first pass で変えないこと。
  - 目安サイズ:
    - `smart_xss.py`: 300-450 行
    - `smart_sqli.py`: 300-450 行
    - `form_parsing.py`: 120-220 行
    - `smart_xss_reflection.py`: 250-500 行
    - `smart_xss_runtime.py`: 250-500 行
    - `smart_sqli_payloads.py`: 250-500 行
    - `smart_sqli_runtime.py`: 250-500 行

## 3.1 先に固定する回帰観点
- import / manager 回帰:
  - `from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter`
  - `from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter`
  - manager_internal からの specialist factory / tool runner。
- XSS behavior 回帰:
  - multiple reflections。
  - POST body flow。
  - stored flow。
  - `test_smart_xss_xcto10_runtime_red.py` の runtime-red 系。
- SQLi behavior 回帰:
  - POST/JSON submission。
  - integration mock flow。
- monkeypatch 回帰:
  - `smart_xss._fetch_and_parse_form` patch。
  - `smart_sqli.SmartSQLiHunter.run_as_tool` patch。

## 3.2 DeepSeek 向け実装ルール
- 最初に shared form parsing helper だけを抽出し、その後 XSS 専用 helper、最後に SQLi 専用 helper を出す。
- `SmartXSSHunter` / `SmartSQLiHunter` の大型 class を一度に完全分解しようとせず、helper 切り出しと facade 薄化の2段で進める。
- test が patch している symbol は facade 側へ alias/wrapper を残し、path 変更で壊さない。
- XSS と SQLi の共通化は pure helper に限定し、判断ロジック・プロンプト・runtime フローまで共通化しない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `smart_xss.py` / `smart_sqli.py` の helper と class 内 cluster を棚卸しし、shared form parsing、XSS reflection/runtime、SQLi payload/runtime の境界を確定する。
- [x] ステップ2: テストファイルを確認し、path patch や representative behavior が固定されていることを確認する。
- [x] ステップ3: `_fetch_and_parse_form` を `form_parsing.py` へ抽出し、`smart_xss.py` / `smart_sqli.py` から同名 alias or wrapper で再公開する。
- [x] ステップ4: `SmartXSSHunter` から reflection / payload build 系 helper を `smart_xss_reflection.py` へ抽出する。runtime confirm 系はまだ元ファイルに残してよい。
- [x] ステップ5: stored flow、runtime confirmation、XCTO/runtime-red 系 helper を `smart_xss_runtime.py` へ抽出し、`smart_xss.py` は facade / class coordinator 中心へ薄化する。
- [x] ステップ6: `SmartSQLiHunter` から payload family、encoding、request variation helper を `smart_sqli_payloads.py` へ抽出する。
- [x] ステップ7: submission / response classification / evidence build helper を `smart_sqli_runtime.py` へ抽出し、`smart_sqli.py` を facade / class coordinator 中心へ薄化する。
- [x] ステップ8: manager / integration path を再確認し、import surface、monkeypatch point、async behavior が保たれていることを確認する。

## 4.1 推奨検証コマンド
```bash
.venv/bin/pytest tests/core/agents/swarm/test_smart_xss.py tests/core/agents/swarm/injection/test_smart_xss_logic.py tests/core/agents/swarm/injection/test_smart_xss_xcto10_runtime_red.py tests/integration/test_smart_xss_hunter_integration.py tests/integration/test_smart_sqli_hunter.py tests/unit/test_smart_sqli_post.py tests/core/agents/swarm/test_injection_manager.py -q
.venv/bin/python -m compileall src/core/agents/swarm/injection
```

## 4.2 完了条件
- `smart_xss.py` / `smart_sqli.py` の公開 import path が維持され、manager 経由利用が壊れていない。
- `_fetch_and_parse_form` の monkeypatch point が互換のまま維持されている。
- XSS / SQLi それぞれの代表テストと integration test が通る（46 passed / 3 pre-existing failures を許容）。
- 両 facade file が 400 行前後まで薄化し、helper 群が専用 module へ分かれている。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:高] test が module path を直接 patch しているため、helper 外出しだけでも簡単に回帰する - facade 側 alias/wrapper を前提に分割する。
- [x] [重要度:中] `smart_xss.py` と `smart_sqli.py` の class 本体は依然として大きく、helper 抽出後も二段分割が必要になる可能性がある - Phase 2 (SGK-2026-0308) で完了。
- [ ] [重要度:中] `smart_cmd_ssrf.py` にも類似 `_fetch_and_parse_form` があり、共通化欲求が強い - 今回は XSS/SQLi のみ対象とし、SSRF まで巻き込まない。
- [x] [重要度:中] prompt / detection heuristic 改善を同時に入れると分割の効果測定が難しくなる - behavior 改善は別 task に切り分ける。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0306-D01
    title: "継続監視: injection hunter の monkeypatch point と helper 共通化"
    reason: "分割後も manager/path patch 互換と SSRF 系への共通化判断を継続監視する必要がある"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "XSS/SQLi 分割後の回帰 task を active で起票し、必要なら smart_cmd_ssrf への展開を別 task で判断する"
```
