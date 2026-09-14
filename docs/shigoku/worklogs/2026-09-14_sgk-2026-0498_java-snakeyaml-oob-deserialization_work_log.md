---
task_id: SGK-2026-0498
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0498_java-snakeyaml-oob-deserialization.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0498_java-snakeyaml-oob-deserialization_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- deserialization
- java
- oob
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0498 作業ログ（Java SnakeYAML OOB デシリアライズ・実 SKF ラボ・◎）

## 1. 偵察・真因切り分け（事実優先・実測）
- SKF java-des-yaml（GET /config/{base64}→new Yaml().load()・SnakeYAML 1.25・JDK 8u212・:5000・--network host）。
- 当初コールバック不通で「Java 不通」と誤認。切り分け: canary→:5000 でガジェット発火確認、wget/jrunscript で
  JVM→13337 直接到達（200・受信ログ）確認。真因は LocalOOBListener のルートが単一セグメントのみで、
  ServiceLoader の多段パス /callback/<token>/META-INF/... に一致せず token 配下に未記録だった（我々のバグ）。

## 2. 台帳・計画・承認
- SGK-2026-0498 採番（registry.yaml・DOC-0568）。Java 横展開の選択＝ビルド承認（凍結1 additive 追加）。

## 3. 実装（Claude 直接）
- oob_listener（非凍結）: tail ルート additive 追加（/callback/{token}/{tail:.*}・/{token}/{tail:.*}）。
- oob_payload_builders（非凍結）: builder java_snakeyaml（ScriptEngineManager/URLClassLoader/URL・callback 末尾/）。
- smart_blind_deser（非凍結）: path モード（base64 を URL パス末尾に付け GET）＋ GET 送信＋モード/kind 別
  正確 PoC（実 base64 URL・全インバウンド行・User-Agent）。sent_url/sent_payload を proof に保持。
- oob_provider（非凍結）: poll 戻りに全インバウンド行 interactions を additive 追加。
- sealed_reproduction_checker（凍結・承認）: _check_oob_replay に path(GET) モード additive 追加。
- payout_grade は無改変（汎用マーカー oob_interaction_received が deserialization を既に網羅）。

## 4. 独立検証（Claude・実出力）
- E2E: 手動でリスナー多段パス記録を確認→実ラボで ScriptEngineManager ガジェット発火→
  HEAD/GET /callback/<token>/META-INF/services/... と GET /callback/<token>/OK.class を UA Java/1.8.0_212 で受信。
- GATE1 payout_grade=True/oob_interaction_received。GATE2 sealed matched（新 token 再送→JVM 再コールバック）。
- GATE3 poc_judge: 初回 false（プレースホルダ・生ログ不足）→実 base64 URL＋全行＋UA＋OK.class 取得を提示し
  再送で is_real=True・has_actual_impact=True・counter_evidence=False・needs_human=False。
- テスト: 新規（builder・engine path・sealed path）＋関連 OOB/deser/provider 35 緑。非回帰: 失敗3件は
  HEAD でも失敗の既存（phase_b×2・t3_hybrid budget）=0498 起因の回帰ゼロ（1339 passed）。凍結3 exit0。

## 5. 完了
- 完了条件1〜5充足（条件3 実 poc_judge 承認）。in_scope_blocker 0 → done。
- 能力マップ: デシリアライズ(Java SnakeYAML) ◎ 行を追加・高度化 中(L2)。
- 教訓: (1) OOB の到達不通は標的でなく**受信器のルーティング**を先に疑う（多段パス /META-INF/... は
  単一セグメントルートに不一致）。(2) OOB PoC はプレースホルダ不可＝**実バイト列(base64)＋生受信ログ
  (全行＋User-Agent)** を載せると poc_judge が通る（Java/x.x.x の UA と返したクラス名の .class 取得が
  RCE 級の決定的シグネチャ）。(3) 横展開はマーカー無改変＋builder/mode 追加で最小コスト。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。
- 観測（別件）: PHP unserialize はラボ無し・POP アプリ固有で実装不可（据え置き）。ネイティブ Java シリアライズ
  /JNDI・DNS-only OOB・自前 interactsh・パイプライン統合は deferred。
