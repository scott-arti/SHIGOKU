---
task_id: SGK-2026-0154
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Recon Pipeline 最適化評価レポート

## 1. 概要

`src/recon/pipeline.py` における Step 1〜8 の実行フローを分析し、並列化によるパフォーマンス改善の妥当性、メリット、リスクを評価しました。

## 2. 現状分析 (Current Status)

- **ファイル**: `src/recon/pipeline.py`
- **対象メソッド**: `run()` (L1636〜1746)
- **確認結果**:
  - 全ステップ (`await step1`, `await step2`, ...) が `await` によって **完全な直列実行** となっています。
  - 特に **Step 1 (Subdomain Discovery)** と **Step 2 (Historical Discovery)** は、互いの結果に依存せず（最後にマージするだけ）、同時に実行可能です。
  - **対応状況**: 未対応 (Not Implemented)

## 3. 評価 (Evaluation)

**総合評価: S (即効性あり・対応推奨)**

### 3.1 妥当性 (Validity)

- **高 (High)**: Step 1 (Subdomain) と Step 2 (Historical) は、それぞれ異なるデータソース（DNS/API vs アーカイブ/Wayback）を使用するため、リソース競合が少なく、並列化による純粋な時短効果が見込めます。
- **中 (Medium)**: Step 3b, 4, 5 は同一ターゲット (`live_subs`) に対するアクティブスキャンであるため、並列化は可能ですが、ネットワーク負荷とWAF検知のリスクが高まります。

### 3.2 メリット (Benefits)

- **時間短縮**:
  - Step 1 (例: 10分) と Step 2 (例: 5分) を並列化 → **完了まで 10分** (5分短縮)。
  - Step 3b, 4, 5 を並列化 → 合計時間の 30〜50% 程度削減可能。
- **リソース効率**: CPUバウンドな処理（パース等）とI/Oバウンドな処理（通信）が混在するため、並列化によりリソース待ち時間を有効活用できます。

### 3.3 リスク (Risks)

- **WAF検知 / ブロック**: 単純に全タスクを並列化すると、ターゲットに対する同時リクエスト数が急増し、攻撃とみなされてIPブロックされるリスクがあります。
- **レート制限**: 外部API（Step 1, 2）のレート制限に引っかかる可能性があります。

## 4. 改善案 (Proposal)

### Phase 1: 安全な並列化 (Subdomain & Historical)

Step 1 と Step 2 を `asyncio.gather` で並列化し、結果をマージします。

```python
# Before
self.state.all_subs = await self.step1_subdomain_discovery()
self.state.all_subs = await self.step2_historical_discovery(self.state.all_subs)

# After
result_1, result_2 = await asyncio.gather(
    self.step1_subdomain_discovery(),
    self.step2_historical_discovery([])  # 独立実行なら空リストでOK
)
self.state.all_subs = sorted(list(set(result_1) | set(result_2)))
```

### Phase 2: 制御付き並列化 (Active Scan)

Step 3b, 4, 5 を `asyncio.Semaphore` または `ParallelOrchestrator` を通して並列化します。

```python
# Example with Semaphore
sem = asyncio.Semaphore(2)  # 同時実行数を2に制限

async def run_step(step_func, *args):
    async with sem:
        return await step_func(*args)

await asyncio.gather(
    run_step(self.step3b_hybrid_url_discovery, ...),
    run_step(self.step4_waf_detection, ...),
    run_step(self.step5_port_scan_phase1, ...)
)
```

## 5. 結論

**改善の必要度: 極めて高い (Critical/S)**

今回の改修により、特に大規模なターゲット（`*.example.com` など）に対する初期Reconの所要時間を大幅に短縮できます。ただし、WAF回避のため、Active Scanフェーズの並列化には慎重なレート制御が必要です。
