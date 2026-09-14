---
task_id: SGK-2026-0496
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0496_oob-deserialization.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0496_oob-deserialization_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0495_blind-ssrf-oob.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- deserialization
- oob
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0496 作業完了報告 — OOB 安全でないデシリアライズ（RCE級）を実対象で本物確定（◎）

## 何をしたか / なぜ

OOB 基盤（SGK-2026-0494/0495）を横展開し、安全でないデシリアライズ（RCE級）を ◎ 化。逆シリアライズ時に
外向き HTTP コールバックするガジェットを送り、受信器への一意 token 到達で確定（応答は無反射でも）。
（OOB SQLi は実対象＝SKF sqli が SQLite でネットワーク関数を持たず OOB 不可のため据え置き＝ユーザー判断。
本タスクへ切替。）

## 事実（偵察で実測）

- **SKF ラボ `des-pickle`**（Flask・`--network host`）：`POST /sync` の form `data_obj`＝hex(pickle) を
  `pickle.load` で逆シリアライズ＝RCE（ラボ内サンプルは `__reduce__`→`os.system('sleep 5')`）。
- 実測で `__reduce__`→`os.system(python3 urllib で受信器へコールバック)` の pickle を hex 送信すると、
  標的が逆シリアライズし一意 token が受信器へ到達＝OOB デシリアライズ成立。

## 実装（新設2＋承認済み凍結2）

- **detection/oob_payload_builders.py（非凍結・新規）**: `build_oob_payload(kind, callback_url)->bytes`＋
  `encode_payload(raw, encoding)`。`python_pickle` は `__reduce__`→`os.system(curl→wget→python3→python の
  フォールバックで callback)` を生成。エンジンと封印再現（builder パス）で共有し fresh callback から
  作り直せる。コールバックは良性（HTTP GET のみ・破壊的動作なし）。
- **injection/smart_blind_deser.py（非凍結・新規）**: `SmartOOBDeserHunter`。OOB provider から一意
  コールバックを発行→ビルダでガジェット生成→エンコード（hex）→候補 sink パラメータ（data_obj/data/…）へ
  送信→poll で token 到達を確認して確定。`self._client`／`self._oob` seam。`oob_evidence`（payload＝token を
  含む callback 記述）＋`oob_replay`（builder/encoding/mode/param）＋生 OOB inbound の poc。製品固有
  ハードコードなし。
- **payout_grade.py（凍結・承認）**: `_MARKER_CATEGORIES["deserialization"]="oob_interaction_received"` を
  追加（vuln_type を既知カテゴリにし、汎用 OOB 分岐 `oob_interaction_received` を発火可能に。in-band 専用
  ブランチは無し＝OOB が唯一の発火経路）。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_oob_replay` に **builder パス**を追加
  （`oob_replay.builder` があれば fresh callback から `build_oob_payload`＋`encode_payload` で作り直して
  再送＝バイナリ pickle を正しく再生成。{OOB} 文字列置換の代替）。

## 結果（独立検証・Claude が実測）

- **実 SKF des-pickle ラボ**で実 `SmartOOBDeserHunter.execute` が OOB で自走検出（python_pickle・hex・
  form data_obj・標的が逆シリアライズし `GET /callback/<token>` で受信器へ到達・in-band は空）→
  `payout_grade=True/oob_interaction_received`→**実 `SealedReproductionChecker`（oob_provider 注入）が
  builder パスで新 token のガジェットを再送し受信器で再観測→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・counter=False）。審査理由は
  「送信した pickle ガジェット（data_obj）にのみ埋め込んだ一意 token が標的から我々の受信器へ実リクエスト
  `GET /callback/<token>` として観測＝逆シリアライズ・ガジェット実行の実測」。**完全3ゲート達成＝◎**。
- テスト: 新規15テスト（builder バイト検査＝unpickle せず os.system/callback 含有・hex/base64/raw・fresh で
  別ペイロード／engine OOB 確定・非到達で不確定・hex 送出・builder replay 記述子／sealed OOB builder モード
  matched）緑。非回帰: 失敗3件は本変更前でも失敗する既存（phase_b×2・t3_hybrid budget）＝**0496 起因の
  回帰ゼロ**（1313 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。承認済凍結2は承認範囲の追加のみ。
  製品非依存 token 0・trailing whitespace 0・秘密値非露出。

## 秘密情報・安全性の扱い（監査）

- 生成物は pickle RCE ペイロード（攻撃成果物）だが、**実行されるコマンドは受信器への良性 HTTP GET に限定**
  （破壊的動作なし・非破壊確認）。テストでは生成 pickle を**一切 unpickle しない**（バイト列検査のみ）で
  実行を回避。os.system 実行は標的（意図的脆弱ラボ）側のデシリアライズ経路でのみ発生。

## 確度の結論（正直な格付け）

- **安全でないデシリアライズ（RCE級）＝実害あり**で実 poc_judge も通り **◎（完全3ゲート）**。curve-fit なし
  （汎用 OOB マーカーは fail-closed・乱数 token 相関・エンジンは製品固有ハードコードなし）。**高度化 低(L1)**
  （Python pickle 単一形態・SKF 単一・Java/PHP ビルダと in-band 確認は別途）。
- **戦略的意義**: OOB 基盤の再利用性をさらに実証（builder パス追加で任意のデシリアライズ言語へ拡張可能）。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`、`rules/codingrules.md`、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- in-band デシリアライズ確認・Java/PHP/.NET ビルダ・DNS-only OOB・公開受信器・パイプライン統合は本タスク
  対象外（`deferred_followup`）。OOB SQLi は実対象無しで据え置き。
