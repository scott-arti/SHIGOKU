---
task_id: SGK-2026-0123
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Katana Target Generation Fix

## 概要

`ReconPipeline` の `step3b_hybrid_url_discovery` において、`Katana` に渡すターゲットURLの生成ロジックを改善します。
現状、`live_subs`（ホスト名のみ）に対して一律 `http://` を付与しているため、非標準ポート（例: `localhost:4280`）やHTTPSのみのサイトに対して適切なスキャンが行われない（`http://localhost:80` にアクセスしてしまう）問題があります。

## 変更範囲

- `src/recon/pipeline.py`

## 変更内容

### Before

```python
katana_targets = [f"http://{sub}" for sub in live_subs if not sub.startswith("http")]
```

### After

1. `Step 3` で保存された `httpx.json` を読み込みます。
2. `httpx.json` に含まれる `url` フィールド（Full URL）を `Katana` のターゲットとして使用します。
3. `httpx.json` が存在しない、または検証できない場合は、既存の `live_subs` ロジックにフォールバックします。

## 挙動の変化

- **Input**: `target="http://localhost:4280/"`
- **Before**: `Katana` scans `http://localhost` (Port 80) → Connection Refused or Wrong Target.
- **After**: `Katana` scans `http://localhost:4280/` (Correct Target).

## 制約

- `httpx.json` のロードに失敗してもパイプラインを停止させないこと（フォールバックの実装）。
- `httpx` の結果が空の場合は実行をスキップ、または `live_subs` を使用する。
