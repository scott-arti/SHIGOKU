---
task_id: SGK-2026-0368
doc_type: plan
status: active
parent_task_id: SGK-2026-0122
related_docs:
- docs/shigoku/specs/fix_injection_swarm.md
- docs/shigoku/plans/2026-07-16_injection-task-ownership-normalization-and-no-signal-phase2-suppression_plan.md
- docs/shigoku/plans/done/2026-07-15_sgk-2026-0365_injection-timeout-trace-selection-observability_plan.md
- workspace/projects/localhost:4280/reports/haddix_report_20260715_151429.md
title: DOM XSS latent parameter inference hardening
created_at: '2026-07-16'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/agents/swarm/injection/smart_xss.py, tests/core/agents/swarm, workspace/projects/localhost:4280/tagged_urls/20260715_target_tagged_xss_candidate.jsonl
---

# 実装計画書：DOM XSS latent parameter inference hardening

## 1. 達成したいゴール（ユーザー視点）
- [ ] DVWA の `http://localhost:4280/vulnerabilities/javascript/` のような DOM XSS ページで、本命パラメータが query に露出していなくても `default` のような latent parameter を候補化できること。
- [ ] `SmartXSSHunter` が CSRF 用 hidden input や補助パラメータに引っ張られず、DOM variant にとって意味のあるパラメータを優先して試せること。
- [ ] param inference 強化後も、reflected/stored XSS の既存挙動を壊さず、session 上で「何を候補にし、何を試したか」を説明できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/smart_xss.py`: DOM variant 向けの candidate param 抽出・優先順位付け・ hidden input 除外を強化する主対象。
  - `src/core/agents/swarm/injection/manager.py`: `SmartXSSHunter` へ渡す evidence / discovered params の受け渡し点を確認し、必要なら追加する。
  - `tests/core/agents/swarm/`: DOM XSS regression test と candidate param 優先順位テストを追加する。
  - `workspace/projects/localhost:4280/tagged_urls/20260715_target_tagged_xss_candidate.jsonl`: 実 run で `javascript/` がどう観測されていたかを確認する実データ。
- **データの流れ / 依存関係:**
  - recon / session evidence -> `InjectionManagerAgent` -> `SmartXSSHunter.run_as_tool()` -> `_prioritize_candidate_params()` -> `tested_params`
  - 現在の問題は、DOM variant でも form hidden input の `token` / `phrase` が先に候補化され、query に露出していない `default` を拾えないことにある。
  - `SGK-2026-0367` が evidence preservation を担い、この `SGK-2026-0368` は evidence を使った latent param inference を担う。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `target` URL
  - form inputs / HTML snippet / response body snippet / response headers
  - `discovered_params`, `candidate_params`, `_context.url_evidence_by_url`, `_context.forms_by_url`
  - XSS variant (`stored`, `reflected`, `dom`, `generic`)
- **出力/結果 (Output):**
  - DOM variant で `default`, `lang`, `locale`, `hash`, `fragment` などの latent candidate が適切に候補化される
  - `tested_params` に hidden-only / low-value param が支配的に残らない
  - regression test で DVWA `javascript/` 相当ケースを再現できる
- **制約・ルール:**
  - `0367` の ownership/no-signal Phase2 抑制とは分ける。こちらは `smart_xss.py` の候補推定ロジックに集中する。
  - hardcoded DVWA 専用分岐にはしない。`javascript/` は regression seed であって、一般化可能な DOM heuristic に落とす。
  - CSRF token や submit ボタン名は、DOM XSS candidate としては優先度を下げるか除外する。
  - reflected/stored XSS の既存優先順位は不要に崩さない。variant ごとのルール差分で閉じる。
  - session observability を壊さない。必要なら candidate selection reason を最小追加する。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `SmartXSSHunter.run_as_tool()` と `_prioritize_candidate_params()` の現行入力経路を棚卸しし、DOM variant で `token` / `phrase` が先行する理由をコードとテストで再現する。
- [ ] ステップ2: latent param inference を追加する。HTML/JS 文脈、variant、known DOM names、response snippet から `default` 系候補を補完し、hidden/meta param は優先度を下げる。
- [ ] ステップ3: DOM XSS regression test を追加し、DVWA `javascript/` 相当ケースで `tested_params` の先頭候補が改善されること、既存 reflected/stored ケースが壊れないことを確認する。
- [ ] ステップ4: 可能なら実 session artifact と targeted test の両方で、候補化の説明可能性と副作用範囲を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] evidence preservation が不完全なままだと latent inference の材料が足りない - 先に `SGK-2026-0367` を当てるか、最小限の evidence 受け渡しをこのタスクでも補う。
- [ ] [重要度:中] DOM sink 推定をやり過ぎると heuristic が肥大化する - まずは param candidate 改善に限定し、 sink classification までは広げない。
- [ ] [重要度:中] `default` 以外の framework 固有パターンは別途増える可能性がある - 初回は Next.js/vanilla JS 混在でも共通に使える軽量 heuristic を優先する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0368-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
