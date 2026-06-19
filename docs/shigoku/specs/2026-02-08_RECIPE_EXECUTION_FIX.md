---
task_id: SGK-2026-0078
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-08'
updated_at: '2026-05-19'
---

# Phase 7: Tool Executor Agent & 環境最適化

## Target (Roadmapへの対応)

`docs/IMPLEMENTATION_ROADMAP.md` の **Phase 7** に対応。

**対象項目:**

- 7.1 ToolExecutorAgent 新規作成 (Critical)
- 7.2 NaabuTool 引数統一 (High)
- 7.3 Wordlist Path Resolver & Docker Mount (High)

---

## 背景と問題分析

### 現状のレシピ実行フロー (問題あり)

```
Recipe (YAML)
    ↓ steps[0].tool = "reconbot"
CommandAgent (LLM Agent)
    ↓ LLMが instruction を解釈
    ↓ LLMがツール選択・引数生成
Tool実行 (Nuclei, ffuf等)
    ↓ ❌ 引数エラー多発 (Nucleiテンプレートパスミス、未定義引数など)
失敗
```

### アーキテクチャ判断

LLMの推測ミスを防ぐため、**「LLMを使わず、指定されたツールを確定的引数（Deterministic Args）で実行する専用エージェント」** (`ToolExecutorAgent`) を導入する。

---

## Changes (変更ファイル一覧)

### 1. `src/core/agents/general/tool_executor.py` [NEW]

**概要**: LLMを使用せず、直接ツールを実行するエージェント

```python
class ToolExecutorAgent(BaseAgent):
    """
    LLMバイパスエージェント。
    レシピから指定されたツールを直接実行する。
    """

    async def process(self, input_message: str) -> str:
        # このエージェントは通常 process() 経由ではなく、run() で直接制御されることを想定
        return "Direct execution mode only."

    async def run(self, task: dict) -> dict:
        """
        タスクパラメータに基づいてツールを直接実行

        task.params: {
            "tool_name": "nuclei",  # 必須
            "target": "http://...",
            "args": { ... }         # ツール引数
        }
        """
        tool_name = task.get("params", {}).get("tool_name")
        tool = ToolRegistry.get(tool_name)

        # 実行ロジック (引数結合、Auth注入など)
        ...
```

### 2. `src/core/factory.py` & `src/core/engine/agent_registry.py` [MODIFY]

**概要**: `ToolExecutorAgent` をシステムに登録

- `AgentRegistry` に `tool_executor` を登録
- `AgentFactory` でインスタンス化可能にする

### 3. `docker-compose.yml` [MODIFY]

**概要**: ホストのワードリストをDocker内にマウント

```yaml
services:
  shigoku:
    volumes:
      - /home/bbb/Documents/tools/wordlists:/wordlists:ro # Read-onlyマウント
```

### 4. `src/tools/custom/ffuf.py` [MODIFY]

**概要**: Wordlist自動解決ロジックを追加

- パスが `/usr/share/wordlists/...` で来た場合、マウントされた `/wordlists/...` や プロジェクト内 `/app/wordlists/...` を探す `_resolve_wordlist_path` を実装。

### 5. `src/tools/custom/naabu.py` [MODIFY]

**概要**: `extra_args`パラメータを追加

---

## Verification (完了条件)

### 自動テスト

```bash
# ToolExecutor単体テスト
pytest tests/core/agents/test_tool_executor.py -v

# ツール修正テスト
pytest tests/tools/test_naabu.py -v
pytest tests/tools/test_ffuf_wordlist.py -v
```

### E2E機能検証

```bash
# DVWAに対する再スキャン
python -m src.main --target http://localhost:4280/ --mode bugbounty

# 確認項目:
# ✅ レシピからのNuclei呼び出しが成功すること
# ✅ Wordlistが見つかり、ffufが実行されること
```

---

## 実装順序

1. **Docker設定修正** (環境基盤)
2. **ツール修正 (Naabu/Ffuf)** (独立コンポーネント)
3. **ToolExecutorAgent 作成 & 登録** (新エージェント)
4. **テスト作成・実行**
