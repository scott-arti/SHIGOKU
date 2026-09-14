---
task_id: SGK-2026-0496
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0496_oob-deserialization_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0496_oob-deserialization_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0495_blind-ssrf-oob.md
tags:
- shigoku
- detection
- deserialization
- oob
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0496 計画 — OOB 安全でないデシリアライズ（RCE級）を実対象で本物確定（◎）

## 背景・方針

OOB 基盤（SGK-2026-0494/0495）を横展開し、安全でないデシリアライズ（RCE級）を ◎ 化。応答に何も
返らなくても、逆シリアライズ時に**外向き HTTP コールバック**するガジェットを送り、受信器への
token 到達で確定する。OOB SQLi は実対象（SQLite=OOB 不可）が無く据え置き（ユーザー判断）→本タスクへ。

## 事実（偵察で実測）

- **SKF ラボ `des-pickle`**（Flask）を `--network host` で起動。`POST /sync` の form `data_obj`＝
  hex(pickle) を `pickle.load` で逆シリアライズ＝RCE（ラボ内サンプルは `__reduce__`→`os.system('sleep 5')`）。
- 実測で `__reduce__`→`os.system(python3 urllib で受信器へコールバック)` の pickle を hex 送信すると、
  標的が逆シリアライズし一意 token が受信器へ到達＝OOB デシリアライズ成立。

## 対象（完了契約）

SKF des-pickle の安全でないデシリアライズを実対象で **機械フロア＋実再現＋実 poc_judge の完全3ゲート**
で ◎。確定は「一意 token を含むコールバックガジェットを送り、標的が逆シリアライズ時に受信器へ token で
到達」で行う（汎用 OOB マーカー流用）。非破壊（ガジェットは良性 HTTP コールバックのみ）。

## 実装方針（新設2＋承認済み凍結2）

1. **`detection/oob_payload_builders.py`（非凍結・新規）**: `build_oob_payload(kind, callback_url)->bytes`＋
   `encode_payload(raw, encoding)`。`python_pickle` ビルダは `__reduce__`→`os.system(curl/wget/python3 で
   callback)` を生成。エンジン（検出）と封印再現（builder パス）で共有し fresh callback から作り直せる。
2. **`injection/smart_blind_deser.py`（非凍結・新規）**: `SmartOOBDeserHunter`。OOB provider から一意
   コールバックを発行→ビルダでガジェット生成→エンコード（hex 等）→候補 sink パラメータへ送信→poll で
   token 到達を確認→確定。`self._client`／`self._oob` seam。`oob_evidence`（payload=token を含む callback
   記述）＋`oob_replay`（builder/encoding/mode/param）＋生 OOB inbound の poc。製品固有ハードコードなし。
3. **`payout_grade.py`（凍結・承認）**: `_MARKER_CATEGORIES["deserialization"]="oob_interaction_received"`
   を追加（vuln_type を既知カテゴリにし汎用 OOB 分岐を発火可能に。in-band 専用ブランチは無し）。
4. **`sealed_reproduction_checker.py`（凍結・承認）**: `_check_oob_replay` に **builder パス**を追加
   （`oob_replay.builder` があれば fresh callback から `build_oob_payload`＋`encode_payload` で作り直して
   再送。{OOB} 文字列置換の代替＝バイナリ pickle を正しく再生成）。

## 完了条件

1. 実 SKF des-pickle で実 `SmartOOBDeserHunter.execute` が OOB で自走検出→payout_grade=True/
   oob_interaction_received。
2. 実 `SealedReproductionChecker`（oob_provider 注入）が builder パスで新 token のガジェットを再送し受信器
   再観測→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認（生の OOB inbound リクエスト＋token 相関を提示）。
4. 製品非依存 fixture の新規テスト緑（builder バイト検査＝unpickle しない／engine OOB 確定・非到達で
   不確定・hex 送出・builder replay 記述子／sealed OOB builder モード matched）。
5. 凍結3 exit 0。製品トークン 0・秘密値非露出・回帰ゼロ。

## NOT in scope

- in-band デシリアライズ確認（ガジェット出力の in-band 反映）・Java/PHP/.NET ビルダ・DNS-only OOB・
  公開受信器（別タスク・builder/OOBProvider は拡張可能に設計）。OOB SQLi は実対象無しで据え置き。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・一ファイルの挙動を仕様と
しない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。
