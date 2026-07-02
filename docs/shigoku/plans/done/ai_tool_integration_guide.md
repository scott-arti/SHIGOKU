---
task_id: SGK-2026-0231-S02
doc_type: plan
status: done
parent_task_id: SGK-2026-0231
related_docs:
- docs/shigoku/plans/phase_e2_next_action_plan.md
- docs/shigoku/reports/phase_e2_cto_review.md
- docs/shigoku/subtasks/2026-05-23_sgk-2026-0231-s02_ai-integration-and-adapter-expansion.md
created_at: '2026-05-23'
updated_at: '2026-07-02'
---

# AIツール統合ガイド: 新外部ツール基盤 ↔ AIエージェント接続

## 現状の問題

新外部ツール統合基盤（DalFoxAdapter, NucleiAdapter）は**AIエージェントから直接使用できません**。

```
【使えない例】
AIエージェントが "nuclei_scan" を呼び出そうとしても...
→ BaseExternalAdapterはToolRegistryに登録されていない
→ AIは検出できない
→ 呼び出されない
```

## 解決策: AIToolBridge

`ai_tool_bridge.py` が橋渡しを担当します。

```
【新アーキテクチャ】
AIエージェント (BaseManagerAgent)
    ↓ register_tool()
AIToolBridge (BaseTool互換)
    ↓ execute()
ExternalToolExecutor
    ↓ run_with_validation()
NucleiAdapter / DalFoxAdapter
    ↓
BinaryManager (セキュア実行)
```

## 実装手順

### Step 1: Managerへの登録

```python
from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.adapters.external.ai_tool_bridge import register_external_tools_with_manager

class VulnScanManager(BaseManagerAgent):
    def __init__(self, config=None):
        super().__init__(config)
        
        # 新外部ツールをAIに登録
        register_external_tools_with_manager(self)
        
        # これでAIは "nuclei_scan" と "dalfox_scan" を使える
```

### Step 2: AIプロンプトでの使用

AIは自動的に新ツールを選択・実行できます:

```
【AIの思考プロセス】
Target: https://example.com

Thought: まずNucleiで脆弱性スキャンを実行する必要がある。

Action: nuclei_scan({
    "target": "https://example.com",
    "options": {"tags": "cve", "severity": "critical,high"},
    "timeout_seconds": 120
})

Observation: {"success": true, "findings": [...]}

Thought: 次にXSSをチェックする。

Action: dalfox_scan({
    "target": "https://example.com",
    "timeout_seconds": 60
})
```

### Step 3: 結果の取得

```python
# AIが実行した結果は自動的にObservationとして返却
result = await self._execute_tool("nuclei_scan", args)
# → {"success": True, "findings": [...], "execution_time_ms": 5000}
```

## 新旧比較

| 機能 | 旧システム (NucleiTool) | 新システム (NucleiAdapter+Bridge) |
|------|-------------------------|-----------------------------------|
| セキュリティ | ベーシック | 4層防御 + 検証前chmod禁止 |
| バイナリ管理 | 手動/非統一 | BinaryManager自動管理 |
| 並行実行 | 制御なし | セマフォ制御 + 統計 |
| ロギング | ツール別実装 | ExternalToolLogger統合 |
| AI統合 | ✅ 直接登録 | ✅ Bridge経由で可能 |

## 移行ロードマップ

### Phase E-1: Bridge基盤整備（完了）
- [x] `ai_tool_bridge.py` 作成
- [x] Nuclei/DalFox Bridge実装

### Phase E-2: Manager統合（完了）
- [x] `VulnScanManager` でBridge登録テスト
- [x] 既存Specialistとの比較テスト
- [x] パフォーマンス評価

### Phase E-3: 全面移行（完了）
- [x] 旧Wrapper非推奨化
- [x] 全ManagerでのBridge採用
- [x] ドキュメント更新

## テスト方法

```python
# test_ai_tool_bridge.py
import pytest
from src.core.adapters.external.ai_tool_bridge import create_nuclei_bridge

@pytest.mark.asyncio
async def test_nuclei_bridge_basic():
    bridge = create_nuclei_bridge()
    
    # スキーマ確認
    schema = bridge.to_schema()
    assert schema["function"]["name"] == "nuclei_scan"
    
    # 実行テスト（モック化）
    result = await bridge.run(
        target="https://example.com",
        options={"tags": "cve"}
    )
    
    assert "success" in result
    assert "findings" in result
```

## 注意事項

1. **非同期実行**: Bridge.run()はasyncのため、Manager側でawaitが必要
2. **タイムアウト**: デフォルト60-120秒。長いスキャンは適切に設定
3. **結果形式**: AI向けに簡略化された形式。詳細はraw_outputで確認

## トラブルシューティング

### Q: AIがツールを選択しない
A: システムプロンプトにツール説明が含まれているか確認

```python
# Managerのシステムプロンプト構築時
tool_descriptions = [
    f"- {name}: {info['description']}" 
    for name, info in self.available_tools.items()
]
```

### Q: ツール実行がタイムアウト
A: timeout_secondsを増やすか、スコープを絞る（tags, severity）

### Q: バイナリが見つからない
A: BinaryManagerが自動ダウンロードするか確認
```python
# ヘルスチェックで事前確認
healthy = await adapter.health_check()
```
