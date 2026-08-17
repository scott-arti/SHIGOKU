---
task_id: SGK-2026-0453
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-16_sgk-2026-0453_sqli-impact-demonstration-defense-evasion.md
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0452_safe-sqli-impact-demonstration.md
- docs/shigoku/worklogs/2026-08-18_sgk-2026-0453_sqli-impact-demonstration-defense-evasion_work_log.md
created_at: '2026-08-18'
updated_at: '2026-08-18'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
- sealed-run
deferred_tasks:
- id: SGK-2026-0453-D01
  summary: poc_judge の LLM 非決定性（0452-D01 継続）。まっさら台帳からの5回実測で judge accept 4 / reject 1（reject は境界 severity の正当却下・inconclusive_parked）。過去分と合わせ judged 6 回中 accept 5・reject 1（約83%）。判定基準・プロンプトを緩めずに determinism を上げる方策を検討。一貫 reject の可能性もあり得るためその場合は honor する（緩めない）。「確定するまで回す/当たりだけ拾う」は proxy gaming として不採用。
  tracking_task_id: SGK-2026-0442
- id: SGK-2026-0453-D02
  summary: 初回確認 run の計器オン既定化（measurement-only）。確定と最終段階の記録を1本の成果物へ同居させる手順を標準化（今回は手順で担保・B9/本タスク正本で同居実証済み）。バー・判定不変。
  tracking_task_id: SGK-2026-0442
- id: SGK-2026-0453-D03
  summary: 既確定 finding の再判定スキップ（terminal-skip）の run ログ可視化。再実行時に confirmed=0 となる正常挙動を運用者が誤読しないよう計装で可視化。バー・判定不変。
  tracking_task_id: SGK-2026-0442
- id: SGK-2026-0453-D04
  summary: Ver.2（案B・自律型の応答観察→変形の再優先付け）。Ver.1 で用意した拡張点（選択戦略の継ぎ目 TransformSelectionStrategy・勝ち筋凍結→再現手順機構・妨害検知/変形カタログ共有）に AI 戦略を差し込む。判定は独立3条件の門のまま、AI は有限の汎用語彙内での並べ替えのみ（製品非依存を保つ）。
  tracking_task_id: SGK-2026-0442
---

# SGK-2026-0453 作業完了報告書 — SQLi実害実証・防御ありの相手への対応（D02・Ver.1）

## 何を変えたか（What）
0452 の deferred D02 を Ver.1（ユーザー承認済みの案A）として実装した。確定の合否を決める門（バー5点）を1バイトも触らず、入力の絞り込み/遮断がある相手を汎用の変形で越えて確定まで持っていく力を決定的に追加した。

- 妨害の検知（遮断/文字削除/別応答を汎用signalで見分け、fail-closed）
- 汎用すり抜け変形の道具箱（有限集合・決まった順・最初に決定的差を取り戻す変形を採用）
- 読み取り内の抽出フォールバック（真偽1bitずつで非機微1トークン・時間差方式なし・上限あり）
- Ver.2 を差し込む拡張点（選択戦略の継ぎ目・勝ち筋凍結→再現手順機構・妨害検知/変形カタログ共有）

主な追加/変更ファイル:
- `src/core/agents/swarm/injection/sqli_transform_catalog.py`（新規・標準ライブラリのみ・決定的）
- `src/core/agents/swarm/injection/smart_sqli.py`（加算・回避プローブ配線・renderer=None 既定）
- `src/core/agents/swarm/injection/manager_internal/injection_evidence_fields.py`（加算・回避経路の再現手順ラベル）
- `src/core/config/settings.py`（`sqli_evasion_catalog_enabled: bool = False`・既定OFF・バイト等価）
- `tests/fixtures/vdp_filtered_search_app/`（防御つき検証ハーネス・tests配下＝製品非依存）
- `tests/unit/test_sqli_evasion.py` / `tests/unit/test_vdp_filtered_search_app.py`（新規27件）

## なぜ（Why）
現行の実害実証は1種類の固定形式のみで、相手に入力フィルタが1つでもあると実証が成立しない。防御検知＋汎用回避が無いと一流の発見者と同等以上には届かない。カーブフィッティング/製品固有焼き込みをせず、汎用手法で防御を越えて確定する力を、確定バーを緩めずに獲得するため。

## 検証（Validation run・すべて実測）
- 妨害検知→汎用回避（二重符号化 `%2527`）で quote-strip を越え、勝ち筋を凍結（poc_request が回避後の `q=1%2527`）→真偽差分→非機微 `sqlite_version()=3.47.1` 抽出→本物と確定。
- **安定度の正直な実測（まっさら台帳＋計器オン×5回）**: 確定 4/5・回避起動 5/5。未確定1回は最後の審査役の正当却下（`inconclusive_parked`）のみ。反則・回避未起動・途中終了は0。
- 正本（確定＋最終段階記録の同居）: `session_20260818_001905.json` / `haddix_report_20260818_001907.md`（confirmed_count=1・最終段階 F6 到達）。
- 報告書と生データの整合: `verify_report_session_consistency.py` → status=consistent・rerun_required=false・reason_codes 空。
- バー5点 `git diff --quiet HEAD` 個別 exit0（payout_grade / sealed_reproduction_checker / poc_judge / finding_validator / task_queue の PCR-P1）。
- 製品非依存: `check_vdp_product_independence.py` verdict=pass・token 0。
- 新規テスト27件 pass。既存失敗1件（`test_smart_sqli_hunter_post_json_support`）は HEAD でも失敗する既存問題（今回変更と無関係・git stash で確認済み）。
- 診断（STEP 4）で「計器オンが攻撃経路を変える」主仮説はコード＋実データで否定。再実行時の confirmed=0 は既確定 finding の再判定スキップ（正常挙動）と判明。

## リスク / 残課題（Risks）
- 上記 deferred D01〜D04 参照。いずれも現在の完了根拠を無効化しない（judge 非決定性は追跡・計器手順は標準化予定・Ver.2 は拡張点を用意済み）。
- 追加機能はすべて既定OFF・バイト等価のため、既存 run への影響なし。

## 次の一歩（Next step）
- Ver.2（D04）着手時に拡張点へ AI 戦略を差し込み。着手前に別途計画書を採番。

## 完了判定（§19）
固定完了条件8つすべて達成。2つの綻びは実数で「重い欠陥ではない」と確定（片方は正常な仕組み、片方は手順で解消）。`in_scope_blocker` 0件、追跡可能な `deferred_followup` のみ残存につき **done**。
