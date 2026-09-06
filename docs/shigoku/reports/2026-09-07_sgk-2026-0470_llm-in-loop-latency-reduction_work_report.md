---
task_id: SGK-2026-0470
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-03_sgk-2026-0470_llm-in-loop-latency-reduction.md
- docs/shigoku/worklogs/2026-09-07_sgk-2026-0470_llm-in-loop-latency-reduction_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
created_at: '2026-09-07'
updated_at: '2026-09-07'
tags:
- shigoku
- performance
- llm
- robustness
---

# SGK-2026-0470 作業完了報告 — AI 逐次判断の遅延削減（poc_judge 往復削減）

## 何をしたか / なぜ

フル自律走行が遅い主因を既存テレメトリで測定し、当初仮説（一手ごとの decide ループ）を訂正した。
真因は **poc_judge（候補妥当性判定 AI）の大量呼び出し**（全 AI 往復の 68〜80%）で、似た候補の氾濫を
判定・再判定していたこと。凍結バー・AI 判定基準を一切変えず、呼び出し側（`manager.py`）で
「無駄な AI 判定を減らす」2つのレバーを **新規 settings フラグで既定 OFF** で実装した。

## 結果（確定）

- **測定（事実確定）**: 既存 RunLedger の `llm_called` を run 単位集計。run 04f64975=398回中 poc_judge 269(68%)、
  run 36f88cad=272回中 poc_judge 217(80%)。候補台帳 190件の 79% が CORS の safe-hold で、
  needs_more が毎パス再判定されていた。
- **Lever 2（再判定抑制・cross-pass）**: needs_more 記録の判定用証拠フィンガープリント（poc_judge が実際に
  見る証拠の射影→canonical JSON→sha256→55文字 base-26 英字）が前回と同一なら再判定をスキップ。
  候補を捨てず・判定基準を変えず・確定を動かさない安全設計。台帳マスカで数字列が誤マスクされる問題を
  英字符号化で回避（save→load 往復保持をテストで実証）。
- **Lever 1（判定重複排除・intra-pass・confirm-gated）**: SGK-2026-0464 同型の root-cause 署名で候補をまとめ、
  最強代表を先に判定。**代表が confirmed になったグループのみ残りをスキップ**。確定しなければ同署名の残りも
  判定する（＝確定するはずの候補を判定前に捨てない）。
- **設計是正（重要）**: 制御 A/B で素朴版 Lever 1（代表のみ判定）が confirmed を1件落とすと実証されたため、
  confirm-gated に是正。再検証で **confirmed 消失 0**。
- **制御 A/B（実データ・新規LLM呼び出しゼロ）**: 実走行 04f64975 の本物候補110件＋台帳の実判定結果を固定入力に
  実コードを直接実行。**poc_judge 往復 246→82（66.7%減）・confirmed 消失 0・候補の破棄なし**。
- **検証**: 注入スイート 646 passed（新規 confirm-gated ケース含む・回帰0）。確定バー5ファイル無改変（`git diff --quiet HEAD` exit 0）。
  製品非依存 token 0。両フラグ OFF で byte-identical（OFF 経路は新分岐に入らない）。

## 実装体制

コーディングは DeepSeek に指示（Lever1/2 初版）＋ opencode 経由（Lever1 confirm-gated 是正）。
opencode は本環境では harness バックグラウンドだとメモリ監視で kill されるため `setsid` で切り離して起動。
使用モデルは本家 DeepSeek 社 `deepseek/deepseek-v4-flash` のみ（session export で全数検証・makora/deepinfra/GLM 0件）。
DeepSeek/opencode の完了報告は額面通り信用せず、Claude が差分・凍結・テスト・token・制御A/B を独立検証した。

## deferred_tasks

```yaml
deferred_tasks:
  - summary: "両フラグ ON での実 Juice Shop フル走行 A/B（総所要時間の実削減と confirmed/candidate 非回帰の実走行実証）。制御A/Bで機構は実証済み・実走行での総時間検証は認証寿命(SGK-2026-0469)整備後が効率的。"
    tracking_task_id: SGK-2026-0470
    blocking: false
```

- 上記は非阻害。完了条件（制御A/Bでの poc_judge 削減＋confirmed 非回帰）は達成済みのため親タスクを done とする。
