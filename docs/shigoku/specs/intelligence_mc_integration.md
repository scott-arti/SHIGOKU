---
task_id: SGK-2026-0130
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Intelligence → MasterConductor 統合仕様書

## 概要

`src/core/intelligence/` 配下に完成済みの4つの意思決定モジュールを、
`MasterConductor` (MC) のメインパイプラインに結合し、
**「状況判断して戦略を動的に変えるシステム」** を実現する。

現状:

- RiskPredictor / SelfReflection / ErrorAnalyzer / PriorityBooster は個別に完成済み
- しかし MC の `execute_with_replan` や `_execute_single_task_full_flow` と **一切接続されていない**

## 変更範囲

### 変更ファイル

- `src/core/engine/master_conductor.py` — Intelligence モジュールの初期化と4箇所のフック追加
- `tests/core/engine/test_mc_intelligence_integration.py` — 統合テスト（新規）

### 参照のみ（変更なし）

- `src/core/intelligence/risk_predictor.py`
- `src/core/intelligence/self_reflection.py`
- `src/core/intelligence/error_analyzer.py`
- `src/core/intelligence/priority_booster.py`

---

## 設計

### 統合アーキテクチャ

```
┌─────────────────────────────────────────────┐
│           MasterConductor                    │
│                                              │
│ __init__()                                   │
│   ├── self.risk_predictor = get_risk_predictor()      │
│   ├── self.self_reflection = get_self_reflection()    │
│   ├── self.error_analyzer = get_error_analyzer()      │
│   └── self.priority_booster = get_priority_booster()  │
│                                              │
│ _execute_single_task_full_flow(task)          │
│   ├── [HOOK 1] 実行前リスク評価               │
│   │    → RiskPredictor.assess()              │
│   │    → should_proceed=False なら skip       │
│   │    → recommended_delay を適用             │
│   │                                          │
│   ├── [HOOK 2] 成功時: 実行記録 + 自動ブースト │
│   │    → SelfReflection.record(SUCCESS)      │
│   │    → PriorityBooster.auto_detect_boost() │
│   │                                          │
│   └── [HOOK 3] 失敗時: エラー分析 + 記録      │
│        → ErrorAnalyzer.analyze()             │
│        → SelfReflection.record(FAILURE)      │
│        → analysis.retry_recommended → replan │
│        → analysis.wait_seconds → delay       │
│                                              │
│ execute_with_replan() [メインループ]          │
│   └── [HOOK 4] 定期省察 (N タスクごと)        │
│        → SelfReflection.reflect()            │
│        → insights → 戦略調整                 │
└─────────────────────────────────────────────┘
```

### HOOK 1: 実行前リスク評価（`_execute_single_task_full_flow` 内、dispatch 前）

タスク実行前に `RiskPredictor.assess()` を呼び、リスクが CRITICAL な場合はスキップ。
推奨遅延がある場合は `time.sleep()` で適用。

```python
# _execute_single_task_full_flow 内、dispatch 前に挿入
from src.core.intelligence import ActionRiskProfile, ActionType

action_type = self._map_agent_to_action_type(task.agent_type, task.action)
profile = ActionRiskProfile(
    action_type=action_type,
    target_url=task.params.get("target", ""),
    has_waf="waf" in str(self.context.target_info).lower(),
    consecutive_failures=task.replan_depth,
)
assessment = self.risk_predictor.assess(profile)

if not assessment.should_proceed:
    logger.warning("RiskPredictor blocked task %s (risk=%s)", task.id, assessment.risk_level)
    task.state = TaskState.SKIPPED
    return {"success": False, "error": "Blocked by RiskPredictor", "risk": assessment.to_dict()}

if assessment.recommended_delay > 0:
    time.sleep(assessment.recommended_delay)
```

### HOOK 2: 成功時フィードバック（成功ブロック内）

タスク成功時に実行記録を `SelfReflection` に保存し、
レスポンス内容を `PriorityBooster` に通して自動的に関連タスクの優先度を上げる。

```python
# 成功ブロック内に追加
from src.core.intelligence import ExecutionRecord, ExecutionOutcome

self.self_reflection.record(ExecutionRecord(
    task_id=task.id,
    action_type=task.agent_type or "unknown",
    target=task.params.get("target", ""),
    outcome=ExecutionOutcome.SUCCESS,
    duration_seconds=exec_record.duration_seconds,
    findings=[f.title for f in result.get("findings", []) if hasattr(f, 'title')],
))

# PriorityBooster: レスポンス内容からブースト検出
response_body = result.get("output", "") or result.get("data", {}).get("response_body", "")
if response_body:
    boost_event = self.priority_booster.auto_detect_boost(
        target=task.params.get("target", ""),
        content=str(response_body),
    )
    if boost_event:
        self.priority_booster.boost_on_discovery(boost_event)
```

### HOOK 3: 失敗時分析（失敗ブロック内、replan 前）

`ErrorAnalyzer` でエラーの根本原因を分析し、`replan()` に分析結果を渡す。
`retry_recommended=False` なら再試行を抑制。

```python
# 失敗ブロック内、replan 前に挿入
from src.core.intelligence import ErrorRecord

error_record = ErrorRecord(
    error_message=result.get("error", "Unknown"),
    status_code=result.get("data", {}).get("status_code"),
    target_url=task.params.get("target", ""),
    action_type=task.agent_type,
)
root_cause = self.error_analyzer.analyze(error_record)

# SelfReflection にも失敗記録
outcome = ExecutionOutcome.BLOCKED if root_cause.category.value in ["waf_blocked", "ip_blocked", "rate_limited"] else ExecutionOutcome.FAILURE
self.self_reflection.record(ExecutionRecord(
    task_id=task.id,
    action_type=task.agent_type or "unknown",
    target=task.params.get("target", ""),
    outcome=outcome,
    duration_seconds=exec_record.duration_seconds,
    error_message=result.get("error"),
    response_code=result.get("data", {}).get("status_code"),
))

# ErrorAnalyzer がリトライ非推奨ならスキップ
if root_cause.retry_recommended and task.replan_depth < self.max_replan_depth:
    if root_cause.wait_seconds:
        time.sleep(min(root_cause.wait_seconds, 10.0))  # 最大10秒
    failure_replan = self.replan(task, result.get("error", "Unknown"), root_cause=root_cause)
    # ... 既存の replan 後続処理
else:
    logger.info("ErrorAnalyzer: retry not recommended for %s (%s)", task.id, root_cause.category.value)
```

### HOOK 4: 定期省察（`execute_with_replan` メインループ内）

一定数のタスク実行後に `SelfReflection.reflect()` を呼び、
全体的な成功率が低い場合や frequent block がある場合にログ出力と戦略調整。

```python
# execute_with_replan のメインループ内、バッチ実行後に追加
REFLECTION_INTERVAL = 20  # 20タスクごとに省察

if executed > 0 and executed % REFLECTION_INTERVAL == 0:
    insights = self.self_reflection.reflect()
    for insight in insights:
        if insight.actionable:
            logger.info("🧠 SelfReflection insight: %s → %s", insight.insight, insight.suggested_action)
            self.decision_tracer.trace(
                decision="reflection_insight",
                reason=insight.insight,
                context={"suggested_action": insight.suggested_action, "confidence": insight.confidence}
            )
```

### ヘルパーメソッド: `_map_agent_to_action_type`

`task.agent_type` を `ActionType` enum にマッピングする関数。

```python
def _map_agent_to_action_type(self, agent_type: str, action: str = "") -> ActionType:
    """エージェントタイプをリスク評価用のActionTypeにマッピング"""
    mapping = {
        "recon": ActionType.PASSIVE_RECON,
        "discovery": ActionType.READ_ONLY,
        "auth": ActionType.AUTH_TESTING,
        "idor": ActionType.PARAM_FUZZING,
        "injection": ActionType.INJECTION_TESTING,
        "scanner": ActionType.PARAM_FUZZING,
        "fuzzing": ActionType.PARAM_FUZZING,
        "file_upload": ActionType.FILE_UPLOAD,
        "exploit": ActionType.EXPLOIT_ATTEMPT,
    }
    for key, action_type in mapping.items():
        if key in (agent_type or "").lower():
            return action_type
    return ActionType.PARAM_FUZZING  # デフォルト
```

---

## 制約

- **Intelligence モジュールのコードは一切変更しない** — 既存のAPIをそのまま使用
- **既存のタスク実行フローを壊さない** — HOOK はすべて `try/except` で囲み、Intelligence障害時もタスクは実行される
- **パフォーマンス影響最小化** — `assess()`, `record()`, `analyze()` は同期関数で軽量（<1ms）。`reflect()` のみ定期的（20タスクごと）に呼ぶ
- **replan 署名変更** — `replan()` に `root_cause` オプショナル引数を追加（後方互換）

---

## テストシナリオ

### テスト1: RiskPredictor が CRITICAL リスクのタスクをブロック

```
入力: agent_type="exploit", target="https://waf.example.com", replan_depth=3
期待: RiskPredictor が CRITICAL 判定 → タスクはスキップされる
確認: task.state == SKIPPED, 結果に "Blocked by RiskPredictor" を含む
```

### テスト2: ErrorAnalyzer が 429 を正しく分類し wait_seconds を返す

```
入力: タスク失敗、error="429 Too Many Requests"
期待: ErrorAnalyzer が RATE_LIMITED に分類、retry_recommended=True, wait_seconds=60
確認: replan が呼ばれる（ErrorAnalyzer の wait 後に）
```

### テスト3: SelfReflection が低成功率を検出して insight を生成

```
入力: 20タスク実行後、成功率 < 30%
期待: reflect() → "Overall success rate is low" insight
確認: DecisionTracer に insight が記録される
```

### テスト4: PriorityBooster が管理画面発見時にブースト

```
入力: 成功タスク、target に "admin" を含む
期待: auto_detect_boost() → HIGH_VALUE_ASSET BoostEvent 生成
確認: PriorityBooster にブーストが記録される
```

### テスト5: Intelligence 障害時にフォールバック（グレースフルデグレード）

```
入力: RiskPredictor.assess() が例外を投げる
期待: タスクは通常通り実行される（Intelligence は無視される）
確認: ログに警告が出力、タスク結果は正常
```
