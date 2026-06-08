---
task_id: SGK-2026-0041
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# ProgressiveScanner - 段階的スキャンモジュール

## 概要

**ProgressiveScanner** は、ワードリストを段階的に使用してスキャンを実行し、
十分な結果が得られた時点で早期終了することで、時間とリソースを節約するモジュールです。

---

## 主要機能

### 1. 段階的スキャン

- small → medium → high の順で実行
- 各ステージで結果評価

### 2. 早期終了判定

- 発見数閾値
- 発見率閾値
- 収穫逓減検知

### 3. 進捗レポート

- 各ステージの結果記録
- 終了理由の明示

---

## アーキテクチャ

```
┌─────────────────────────────────────────────────┐
│              ProgressiveScanner                  │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────────────────────────────────────┐    │
│  │ Stage: SMALL                            │    │
│  │ → subdomains-top1million-5000.txt       │    │
│  └─────────────────────────────────────────┘    │
│         │                                       │
│         ▼ 評価                                  │
│         │ 発見率 < 閾値?                        │
│         │ YES → 続行                            │
│         │ NO  → 早期終了                        │
│         ▼                                       │
│  ┌─────────────────────────────────────────┐    │
│  │ Stage: MEDIUM                           │    │
│  │ → subdomains-top1million-20000.txt      │    │
│  └─────────────────────────────────────────┘    │
│         │                                       │
│         ▼ 評価                                  │
│         │ 収穫逓減?                             │
│         │ YES → 早期終了                        │
│         │ NO  → 続行                            │
│         ▼                                       │
│  ┌─────────────────────────────────────────┐    │
│  │ Stage: HIGH                             │    │
│  │ → subdomains-top1million-110000.txt     │    │
│  └─────────────────────────────────────────┘    │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## 使用方法

### 基本的な使用

```python
from src.core.wordlist.progressive_scanner import create_progressive_scanner

scanner = create_progressive_scanner()

# 段階的スキャン実行
results = scanner.scan(
    target="https://example.com",
    purpose="subdomain",
    mode="bugbounty"
)

# サマリー取得
summary = scanner.get_summary()
print(f"Stages: {summary['stages_completed']}")
print(f"Discoveries: {summary['total_discoveries']}")
print(f"Reason: {summary['termination_reason']}")
```

### コールバック使用

```python
def on_stage_complete(result):
    print(f"Stage {result.wordlist_size}: {len(result.discovered)} found")

results = scanner.scan(
    target="https://example.com",
    purpose="directory",
    callback=on_stage_complete
)
```

---

## 設定

### ProgressiveScanConfig

```python
from src.core.wordlist.progressive_scanner import ProgressiveScanConfig

config = ProgressiveScanConfig(
    min_discoveries=10,              # 最低発見数
    target_discovery_rate=0.05,      # 目標発見率 (5%)
    diminishing_returns_threshold=0.5,  # 収穫逓減閾値
    stages=["small", "medium", "high"],
    timeout_per_stage=300,           # ステージタイムアウト
)

scanner = create_progressive_scanner(config)
```

---

## 早期終了条件

### 1. 十分な発見数

```python
if len(discovered) >= min_discoveries:
    if discovery_rate >= target_discovery_rate:
        return "Sufficient discoveries"
```

### 2. 収穫逓減

```python
if current_rate / previous_rate < diminishing_returns_threshold:
    return "Diminishing returns detected"
```

### 3. 発見ゼロ

```python
if stage != "small" and len(discovered) == 0:
    return "No discoveries in this stage"
```

---

## 結果例

### 早期終了ケース

```
Stage: small (5000 lines)
  → Found: 25 subdomains
  → Discovery rate: 0.5%
  → Continue: YES

Stage: medium (20000 lines)
  → Found: 30 subdomains (5 new)
  → Discovery rate: 0.15%
  → Diminishing returns: YES (0.15/0.5 = 0.3 < 0.5)
  → EARLY TERMINATION

Total: 30 discoveries in 2 stages
Time saved: ~3 stages skipped
```

### 完走ケース

```
Stage: small → 5 found
Stage: medium → 15 found
Stage: high → 40 found

Total: 40 discoveries in 3 stages
Reason: All stages completed
```

---

## ツール連携

現在はプレースホルダー実装。以下のツールと連携予定：

| ツール      | 用途                 |
| ----------- | -------------------- |
| `ffuf`      | ディレクトリスキャン |
| `gobuster`  | ディレクトリスキャン |
| `subfinder` | サブドメイン列挙     |
| `amass`     | サブドメイン列挙     |

---

## ベストプラクティス

1. **モード選択**

   - BugBounty: 深掘り重視（段階的に進む）
   - CTF: 速度重視（small で十分なら終了）

2. **閾値調整**

   - ターゲットに応じて発見率閾値を調整
   - 大規模サイト: 低い閾値
   - 小規模サイト: 高い閾値

3. **コールバック活用**
   - リアルタイム進捗表示
   - 中間結果の保存

---

## 関連モジュール

| モジュール                             | 連携             |
| -------------------------------------- | ---------------- |
| [WordlistManager](WORDLIST_MANAGER.md) | ワードリスト選択 |
| [GAUIntegrator](GAU_INTEGRATOR.md)     | パターン分析     |
| [HeadlessCrawler](HEADLESS_CRAWLER.md) | 動的 URL 取得    |
