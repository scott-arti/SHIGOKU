---
task_id: SGK-2026-0243
doc_type: work_report
status: done
parent_task_id: SGK-2026-0231
related_docs:
  - docs/shigoku/plans/2026-05-22_sgk-2026-0231_juice-shop-phase-d-continuous-improvement_plan.md
  - docs/shigoku/reports/2026-05-24_phase-d1-infrastructure-implementation_report.md
created_at: '2026-05-24'
updated_at: '2026-06-30'
---

# Phase D-2 Detection Engines Implementation Report

## 実装内容

### D2-1: RobustTimeBasedDetector ✅
**成果物:** `src/core/detection/time_based_detector.py`
- **4手法統合検出**:
  1. Mann-Whitney U test (ノンパラメトリック)
  2. Cliff's Delta (効果量)
  3. Bayesian inference (事後確率)
  4. Variance ratio (分散比較)
- **統合判断**: 4手法中3つ以上の合意（調整可能 `CONSENSUS_THRESHOLDS`）
- **アダプティブサンプリング**: 初期5件→不明確なら最大30件まで動的増加
- **同一セッション制約**: ベースライン測定の環境安定性確保

```python
# Usage example
result = detect_time_based_sqli(
    baseline_samples=[0.1, 0.12, 0.11],
    sleep_samples=[5.2, 5.1, 5.3]
)
if result.is_vulnerable:
    print(f"SQLi detected! Confidence: {result.confidence:.2f}")
```

### D2-2: XSS Detection Engine (Browser Pool) ✅
**成果物:** `src/core/detection/xss_detector.py`
- **Browser Pool**: 5ブラウザプール、100件ごと自動再起動（メモリリーク対策）
- **Reflected XSS**: レスポンスペイロド反射検出
- **DOM XSS**: ブラウザ実行確認（XSS sink hooks）
- **Stored XSS**: 保存→表示フローの検出サポート

```python
# Usage example
pool = BrowserPool(size=5, max_requests_per_browser=100)
async with pool.acquire() as browser:
    page = await browser.new_page()
    result = await xss_detector.detect_dom_xss(url, param, payload)
```

### D2-3: UCB1WAFEvasion ✅
**成果物:** `src/core/evasion/waf_evasion.py`
- **UCB1アルゴリズム**: 深層RL回避、シンプルで効果的
- **ラプラススムージング**: `trials=1, successes=1`で0除算回避・探索促進
- **戦略例**: base64/hex/unicode encode, comment obfuscation, case randomization

```python
# Usage example
evasion = create_ucb1_evasion()
result = evasion.evade("' OR 1=1 --", test_callback)
# UCB1 automatically selects best strategy based on past success rates
```

### D2-4: OOB Correlation Engine ✅
**成果物:** `src/core/detection/oob_correlator.py`
- **Provider抽象**: InteractshProvider, LocalOOBProvider
- **TTL管理**: 60秒デフォルト、自動クリーンアップ
- **相関検出**: DNS/HTTP callbackの自動ポーリング

```python
# Usage example
manager = await create_oob_manager()
token = await manager.register_oob_test()
# Inject token.domain into payload
interactions = await manager.check_correlation(token.correlation_id)
```

### D2-5: Generic Tool Adapter ✅
**成果物:** `src/core/adapters/tool_adapter.py`
- **YAML設定**: ツール定義の外部化
- **Parser抽象**: sqlmap, dalfox等の個別パーサー
- **タイムアウト制御**: デフォルト300秒

### D2-6: Behavioral MockWAF ✅
**成果物:** `src/core/testing/mock_waf.py`
- **ThrottledWAFBehaviorCollector**: 5秒スロットリング、WAFブロック回避
- **1日1回自動更新**: 実測データベースのMockWAF維持
- **BinarySearchParamDiscovery**: 配列インデックス探索を100→7リクエストに削減

```python
# Usage example
mock_waf = await create_behavioral_mock_waf(target_url)
prediction = mock_waf.predict_block("' OR 1=1 --")
# Returns: (would_block, confidence)
```

### D2-7: Proxy Integration ✅
**成果物:** `src/core/adapters/proxy_integration.py`
- **CaidoIntegration**: HTTP API連携、Repeater送信
- **BurpIntegration**: プレースホルダー（将来拡張用）
- **Auto-detection**: Caido自動検出

```python
# Usage example
proxy_mgr = await create_proxy_manager()
ref = await proxy_mgr.send_finding_to_proxy(finding)
# Finding sent to Caido Repeater for manual verification
```

## 設計判断

| 判断 | 理由 |
|------|------|
| UCB1 over Deep RL | CTO懸念: データ飢餓問題回避。UCB1はシンプルで実用的 |
| Browser Pool 100件再起動 | CTO懸念: Chromiumのメモリリーク対策 |
| 4手法合意ベース | CTO懸念: 単一手法の限界を複合手法で克服。閾値外部化 |
| 5秒スロットリング | CTO懸念: WAFブロックリスク低減。1日1回更新 |
| バイナリサーチ | CTO懸念: 配列探索リクエスト爆発をlog2(N)に削減 |
| Caido優先 | Bug Bounty特化: モダンAPIで統合容易 |

## ファイル構造

```
src/core/
├── detection/
│   ├── time_based_detector.py    # D2-1: 4手法統合検出
│   ├── xss_detector.py           # D2-2: Browser Pool付きXSS
│   └── oob_correlator.py         # D2-4: OOB相関検出
├── evasion/
│   └── waf_evasion.py            # D2-3: UCB1 WAF回避
├── testing/
│   └── mock_waf.py               # D2-6: Behavioral MockWAF
└── adapters/
    ├── tool_adapter.py           # D2-5: Generic Tool Adapter
    └── proxy_integration.py      # D2-7: Caido連携
```

## 未対応事項 (Deferred Tasks)

```yaml
deferred_tasks:
  - task: "Playwright依存関係のoptional化"
    reason: "XSS検出はPlaywright必須だが、インストール時のみ機能する設計"
    planned_date: "Phase D-3"
    
  - task: "WAF Behavior ML予測モデル"
    reason: "現状はルールベース。MLモデルはデータ蓄積後に検討"
    planned_date: "Phase D-3 (UCB1成功率<30%の場合)"
    
  - task: "Burp Suite完全統合"
    reason: "プレースホルダー実装。必要に応じてREST API実装"
    planned_date: "Phase D-3 (顧客要望時)"
```

## 検証項目

- ✅ RobustTimeBasedDetector: 4手法合意ロジック、Cliff's Delta実装
- ✅ BrowserPool: 100件再起動、メモリリーク対策構造
- ✅ UCB1WAFEvasion: ラプラススムージング、探索/活用バランス
- ✅ OOBCorrelationManager: Interactsh/Local provider抽象
- ✅ ToolAdapter: YAML設定、Parser継承構造
- ✅ BehavioralMockWAF: 5秒スロットリング、バイナリサーチ
- ✅ CaidoIntegration: Repeater送信API

## 次ステップ

Phase D-3実装開始:
1. D3-1: Second-Order Assistant（人間支援型）
2. D3-2: Evidence Collection Engine（スコープ境界HITL）
3. D3-3: Distributed SQLi Guesser（ヘッダー相関）
4. D3-4: Bug Bounty Platform Integration
5. D3-5: Param Discovery Engine
