---
task_id: SGK-2026-0159
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Spec: Response Comparison Heuristics (IDOR 成立判定エンジン)

## 概要

IDOR テストにおける最大のボトルネックは「リクエストが成功したかどうか」の判定精度にある。
現状は `status == 200` やボディサイズ ±10% といった粗い判定しかなく、False Positive の温床になっている。

本仕様は、**Baseline Response と Test Response を多角的に比較し、Confidence Score を算出する `ResponseComparator` モジュール**を定義する。

## 現状の問題分析

| テスト種別                   | 現在の判定ロジック                               | 問題点                              |
| ---------------------------- | ------------------------------------------------ | ----------------------------------- |
| `_run_unauth_check`          | `status==200` + ボディサイズ ±10% + SecretFinder | エラーページが200を返すAPIで大量FP  |
| `_run_id_manipulation_check` | `status==200` のみ                               | **あらゆる200応答をIDORとして報告** |
| `_test_cross_session_access` | `status==200` + SecretFinder                     | SecretFinderが無検出時もMEDIUM報告  |

共通の根本原因: **Baseline（正規レスポンス）との構造比較が行われていない**。

## 設計

### 新規モジュール: `ResponseComparator`

```
src/core/agents/swarm/logic/response_comparator.py  [NEW]
```

#### 入力

```python
@dataclass
class ComparisonInput:
    baseline_status: int
    baseline_body: str
    baseline_headers: Dict[str, str]
    test_status: int
    test_body: str
    test_headers: Dict[str, str]
    original_id: str          # 元のID (比較用)
    test_id: str              # 差し替えたID
```

#### 出力

```python
@dataclass
class ComparisonResult:
    is_vulnerable: bool       # 閾値を超えたか
    confidence: float         # 0.0 〜 1.0
    signals: List[str]        # 判定根拠の一覧
    severity_hint: Severity   # 推奨Severity
```

### 判定シグナルと重み付け

| #   | シグナル名             | 条件                                                     | 重み  | 説明                                               |
| --- | ---------------------- | -------------------------------------------------------- | ----- | -------------------------------------------------- |
| S1  | `status_match`         | Test も Baseline と同じステータスコード                  | +0.15 | 最低限の前提条件                                   |
| S2  | `body_size_similar`    | ボディサイズ差が ±20% 以内                               | +0.10 | エラーページは通常短い                             |
| S3  | `json_structure_match` | JSON キー構造の一致率 ≥ 80%                              | +0.25 | **最重要**: 同じ構造 ＝ 同種のリソースが返っている |
| S4  | `id_reflection`        | テスト用IDがレスポンスボディに含まれる                   | +0.20 | 差し替えたIDが反映されている証拠                   |
| S5  | `secret_detected`      | SecretFinder がヒット                                    | +0.20 | 機密データの漏洩                                   |
| S6  | `different_data`       | Baseline と Test でデータ値が異なる（構造は同じ）        | +0.10 | 別ユーザーのデータを取得している可能性             |
| N1  | `error_body_detected`  | "error", "forbidden", "not found" 等のエラーキーワード   | −0.40 | 200でもボディがエラーメッセージ                    |
| N2  | `empty_body`           | テストレスポンスのボディが空 or 極端に短い（< 20 bytes） | −0.30 | データが返っていない                               |
| N3  | `redirect_detected`    | 3xx ステータスまたは meta refresh                        | −0.20 | ログインページ等へのリダイレクト                   |

### Confidence → Severity マッピング

| Confidence   | is_vulnerable | severity_hint                          |
| ------------ | ------------- | -------------------------------------- |
| ≥ 0.80       | `True`        | `CRITICAL` (secret_detected) or `HIGH` |
| 0.60 〜 0.79 | `True`        | `MEDIUM`                               |
| 0.40 〜 0.59 | `False`       | — (ログのみ、Finding非生成)            |
| < 0.40       | `False`       | — (無視)                               |

### エラーパターン辞書

```python
ERROR_INDICATORS = [
    "error", "message", "unauthorized", "forbidden", "not found",
    "invalid", "denied", "expired", "login required",
    '"status":"error"', '"success":false', '"ok":false',
]
```

## 変更範囲

### [NEW] `response_comparator.py`

`src/core/agents/swarm/logic/response_comparator.py`

- `ResponseComparator` クラスを新設
- `compare(baseline, test, original_id, test_id) -> ComparisonResult`
- `_check_json_structure(baseline_body, test_body) -> float` (構造一致率)
- `_detect_error_body(body) -> bool`
- `_check_id_reflection(body, test_id) -> bool`

### [MODIFY] `idor.py`

`src/core/agents/swarm/logic/idor.py`

#### `_run_unauth_check`

- Baseline レスポンスを取得済みなので、Test レスポンスとの比較を `ResponseComparator.compare()` に委譲
- 現在のボディサイズ ±10% ロジックを削除

#### `_run_id_manipulation_check`

- **Baseline の取得を追加**: ID操作前にオリジナルURLで正規レスポンスを取得
- 各ID差し替えテストの結果を `ResponseComparator.compare()` で判定
- `is_vulnerable == True` の場合のみ Finding を生成

#### `_test_cross_session_access`

- オリジナルヘッダでの Baseline を取得（既に `_run_unauth_check` で取得済みの場合はキャッシュ利用）
- 代替セッションでの結果を `ResponseComparator.compare()` で判定

### [MODIFY] `shared_workspace.py`（任意拡張）

- Baseline レスポンスのキャッシュ機能（同一URL・同一セッションの Baseline を重複取得しない）

## 制約

- **EthicsGuard**: 変更なし。比較ロジックは受動的（既に受信したレスポンスの分析のみ）
- **PII Masker**: Finding の evidence に出力する際は引き続きマスキング適用
- **パフォーマンス**: JSON構造比較は `O(n)` で高速。大きなレスポンス（> 1MB）はサイズ比較のみにフォールバック

## Human-in-the-Loop 診断レポート

> [!IMPORTANT]
> 自動判定はあくまで「推奨」。最終判断は人間が行う。
> そのために、**判断に必要な情報を全て `evidence` フィールドに構造的に出力**する。

### Finding.evidence の出力フォーマット

各 Finding の `evidence` に以下の診断レポートを付与する:

```
=== IDOR Diagnostic Report ===
Target: GET https://api.example.com/api/users/456
Original ID: 123 → Test ID: 456

--- Baseline Response ---
Status: 200 | Size: 1,247 bytes | Content-Type: application/json

--- Test Response ---
Status: 200 | Size: 1,312 bytes | Content-Type: application/json

--- Signal Analysis ---
[+0.15] status_match: Both returned 200
[+0.25] json_structure_match: Key structure 92% match (18/20 keys)
[+0.20] id_reflection: Test ID "456" found in response body
[+0.10] different_data: Values differ (name: "Alice" → "Bob")
[-0.00] (no negative signals)

--- Confidence ---
Score: 0.70 / 1.00 → MEDIUM severity
Verdict: LIKELY VULNERABLE (human review recommended)

--- Response Snippets ---
Baseline (first 500 chars):
{"id":123,"name":"Alice","email":"a]***@example.com"...}

Test (first 500 chars):
{"id":456,"name":"Bob","email":"b***@example.com"...}
```

### 設計原則

1. **95%自律**: Score ≥ 0.80 は自動で `HIGH/CRITICAL` として報告。人間は確認のみ。
2. **グレーゾーンは情報提供**: 0.40〜0.79 は判断材料を全て出力し、人間が確定。
3. **PII マスク適用**: Response Snippets 内のメールアドレス等は `PIIMasker` でマスク済み。
4. **レスポンスボディは先頭500文字のみ**: 長大なレスポンスでもログが爆発しない。

### 手動検証

- 実際のAPIに対して実行し、FP率が従来比で減少することを確認
