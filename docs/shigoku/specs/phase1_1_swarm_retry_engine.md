---
task_id: SGK-2026-0142
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Phase 1.1: Swarm Retry Engine 仕様書

## 概要

**機能名**: `SwarmRetryEngine`

**目的**: 現在の Swarm は「1回実行 → 終了」の前提で動作しているが、これを「複数回試行 → 成功するまでループ」に変更する。WAF Blocking 検出時に自動的にペイロードをミューテーションして再試行する機構を実装する。

**背景**:

- 現在の `Specialist.execute()` は1回実行で終了し、WAF によるブロックがあっても諦める
- `src/core/attack/waf_mutator.py` は実装済みだが、Swarm から全く使われていない（デッドコード化）
- Time-based 攻撃での複数回確認（統計的検証）ができない

---

## 変更範囲

| ファイル                                  | 変更内容                                  |
| ----------------------------------------- | ----------------------------------------- |
| `src/core/agents/swarm/retry_engine.py`   | 🆕 新規作成 - リトライロジックの中核      |
| `src/core/agents/swarm/error_detector.py` | 🆕 新規作成 - WAF/エラー検出ロジック      |
| `src/core/agents/swarm/base.py`           | 📝 修正 - `Specialist` にリトライ機構統合 |
| `tests/unit/swarm/test_retry_engine.py`   | 🆕 新規作成 - ユニットテスト              |
| `tests/unit/swarm/test_error_detector.py` | 🆕 新規作成 - ユニットテスト              |

**影響を受ける既存コード**:

- 全 `Specialist` サブクラス（ただし修正不要、自動でリトライ対応）
- `SwarmManager.dispatch()` - `execute_with_retry()` 呼び出しに変更

---

## 挙動

### Input

`RetryConfig` を通じて以下のパラメータを受け取る:

```python
@dataclass
class RetryConfig:
    max_attempts: int = 3              # 最大試行回数
    enable_mutation: bool = True       # ミューテーション有効化
    mutation_rate: float = 0.3         # ミューテーション確率
    detect_waf: bool = True            # WAF検出有効化
    backoff_factor: float = 1.0        # リトライ間隔の係数（秒）
```

### Output

従来の `List[Finding]` をそのまま返す。追加で以下のメタデータを `Finding.evidence` に含める:

```python
{
    "retry_attempts": 2,           # 実際の試行回数
    "waf_detected": True,          # WAF検出フラグ
    "mutation_applied": True,      # ミューテーション適用フラグ
    "successful_mutation": "encode",  # 成功したミューテーションタイプ
}
```

### 処理フロー

```
┌─────────────────────────────────────────────────────────────────┐
│                    SwarmRetryEngine.execute_with_retry()        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Loop: attempt = 1 to max_attempts                         │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │                                                            │ │
│  │  1. specialist.execute(task)                               │ │
│  │             ↓                                              │ │
│  │  2. findings が見つかった?                                  │ │
│  │     ├─ Yes → return findings ✅                            │ │
│  │     └─ No  ↓                                               │ │
│  │                                                            │ │
│  │  3. error_detector.analyze(response)                       │ │
│  │             ↓                                              │ │
│  │  4. WAF Blocking 検出?                                     │ │
│  │     ├─ Yes → Hybrid Mutation Strategy:                     │ │
│  │     │        ├─ Retry 1-2: ランダム選択（高速）            │ │
│  │     │        └─ Retry 3:   遺伝的アルゴリズム（最適化）    │ │
│  │     │        → task を変異させて次のループへ 🔄             │ │
│  │     │                                                      │ │
│  │     └─ No  → break (リトライ不要)                          │ │
│  │                                                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  return findings (空リストの可能性あり)                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 制約

### EthicsGuard との整合性

- リトライによるリクエスト増加は `AdaptiveRateLimiter` の制約内で行う
- `max_attempts` は設定可能だがデフォルト3回に制限
- 攻撃的なミューテーション（null byte injection 等）は Aggression Level を確認

### 既存アーキテクチャとの整合性

- `Specialist` の既存 `execute()` メソッドはそのまま維持（後方互換性）
- 新規追加の `execute_with_retry()` は `SwarmManager.dispatch()` から呼び出し
- `WAFPayloadMutator` は既存実装をそのまま活用

### パフォーマンス考慮

- リトライ間に `backoff_factor` 秒の待機を入れる
- タイムアウトは既存の `Specialist.timeout_seconds` を尊重
- 合計タイムアウト = `timeout_seconds * max_attempts`

---

## API 設計

### RetryEngine

```python
class SwarmRetryEngine:
    def __init__(self, config: RetryConfig):
        self.config = config
        self.mutator = WAFPayloadMutator() if config.enable_mutation else None
        self.detector = ErrorDetector()
        self.failed_payloads: List[str] = []  # 失敗したペイロードを記録

    async def execute_with_retry(
        self,
        specialist_execute: Callable[[Task], Awaitable[List[Finding]]],
        task: Task,
    ) -> Tuple[List[Finding], RetryMetadata]:
        """
        Specialist の execute をリトライロジックでラップ
        """
        pass
```

### ErrorDetector

```python
@dataclass
class DetectionResult:
    is_blocked: bool           # ブロックされたか
    block_type: str            # "waf", "rate_limit", "auth", "unknown"
    waf_signature: Optional[str]  # 検出されたWAFシグネチャ
    confidence: float          # 確信度 (0-1)

class ErrorDetector:
    # 検出パターン
    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "akamai": ["akamaized", "akamai"],
        "aws_waf": ["awswaf", "x-amzn-requestid"],
        "modsecurity": ["mod_security", "NAXSI"],
        "incapsula": ["incap_ses", "visid_incap", "incapsula"],
        "azure_appgw": ["x-azure-ref", "azure application gateway"],
        "f5_bigip": ["bigipserver", "f5-ltm", "ts="],
    }

    STATUS_PATTERNS = {
        403: "possible_waf",
        429: "rate_limit",
        503: "service_unavailable",
    }

    def analyze(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> DetectionResult:
        """レスポンスを解析してブロック状態を検出"""
        pass
```

---

## Specialist 統合方法

### base.py 修正

```python
# 既存
class Specialist(ABC):
    async def execute(self, task: Task) -> List[Finding]:
        raise NotImplementedError

# 追加
class Specialist(ABC):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        # RetryEngine 統合
        retry_config = RetryConfig(
            max_attempts=self.config.get("max_attempts", 3),
            enable_mutation=self.config.get("enable_mutation", True),
        )
        self.retry_engine = SwarmRetryEngine(retry_config)

    async def execute_with_retry(self, task: Task) -> List[Finding]:
        """リトライロジック付きで実行"""
        findings, metadata = await self.retry_engine.execute_with_retry(
            self.execute,
            task
        )
        # メタデータを findings に付加
        for f in findings:
            f.evidence["retry_metadata"] = asdict(metadata)
        return findings
```

### SwarmManager.dispatch() 修正

```python
# 修正前
findings = await specialist.run_with_timeout(task)

# 修正後
findings = await specialist.execute_with_retry(task)
```

---

## テスト計画

### ユニットテスト

1. **test_retry_engine.py**
   - `test_no_retry_on_success`: 成功時にリトライしないことを確認
   - `test_retry_on_waf_detection`: WAF検出時にリトライすることを確認
   - `test_max_attempts_limit`: max_attempts で停止することを確認
   - `test_mutation_applied`: ミューテーションが適用されることを確認
   - `test_backoff_delay`: リトライ間隔が正しいことを確認

2. **test_error_detector.py**
   - `test_detect_cloudflare`: Cloudflare シグネチャ検出
   - `test_detect_rate_limit`: 429 レスポンス検出
   - `test_no_false_positive`: 正常レスポンスで誤検知しないことを確認

### E2E テスト（手動）

```bash
# Mock WAF サーバーを使用
python -m src.main --target http://mock-waf.local --mode bugbounty --dry-run
```

---

## 工数見積もり

| タスク                   | 工数                |
| ------------------------ | ------------------- |
| `retry_engine.py` 実装   | 4時間               |
| `error_detector.py` 実装 | 2時間               |
| `base.py` 修正           | 1時間               |
| テスト作成               | 3時間               |
| E2E 検証                 | 1時間               |
| **合計**                 | **11時間（約2日）** |

---

## 実装順序

1. `src/core/agents/swarm/error_detector.py` - 依存なし、単体テスト可能
2. `src/core/agents/swarm/retry_engine.py` - ErrorDetector + WAFMutator を使用
3. `src/core/agents/swarm/base.py` - RetryEngine を統合
4. テスト作成・実行
5. E2E 検証
