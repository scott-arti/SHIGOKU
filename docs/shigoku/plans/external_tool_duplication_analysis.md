---
task_id: SGK-2026-0238
doc_type: plan
status: done
parent_task_id: SGK-2026-0231
related_docs:
  - docs/shigoku/plans/external_tool_migration_plan.md
created_at: '2026-05-22'
updated_at: '2026-05-30'
---

# 外部ツール重複実装分析と統合計画

## 概要

Phase E（外部ツール統合）における重複実装の整理と移行計画。

## 重複ツール一覧

### 1. Nuclei（3実装）

| 実装 | パス | 用途 | 統合優先度 |
|------|------|------|------------|
| NucleiTool | `src/tools/custom/nuclei.py` | ToolRegistry登録 | ✅ 新基盤へ |
| NucleiWrapper | `src/tools/scanners/nuclei_wrapper.py` | Swarm Scanner用 | ✅ 新基盤へ |
| NucleiIntegrator | `src/core/tools/nuclei_integrator.py` | テンプレート/結果統合 | ✅ 新基盤へ |

**呼び出し元:**
- `src/tools/custom/__init__.py` - ToolRegistry経由
- `src/core/agents/swarm/scanner/manager.py` - VulnScanSpecialistで直接使用
- `src/core/project/project_manager.py` - knowledge ingestor経由
- `tests/e2e_full_flow_test.py` - E2Eテスト

---

### 2. Ffuf（2実装）

| 実装 | パス | 用途 | 統合優先度 |
|------|------|------|------------|
| FfufTool | `src/tools/custom/ffuf.py` | ToolRegistry登録 | ✅ 新基盤へ |
| FFufWrapper | `src/core/tools/ffuf_wrapper.py` | Swarm Fuzzing用 | ✅ 新基盤へ |

**呼び出し元:**
- `src/tools/custom/__init__.py` - ToolRegistry経由
- `src/core/agents/swarm/fuzzing/manager.py` - DirBruteSpecialistで直接使用
- `src/core/attack/native_fuzzer.py` - FuzzResult型を使用

---

### 3. Nmap（2実装）

| 実装 | パス | 用途 | 統合優先度 |
|------|------|------|------------|
| NmapTool | `src/tools/custom/nmap.py` | ToolRegistry登録 | ✅ 新基盤へ |
| NmapWrapper | `src/tools/scanners/nmap_wrapper.py` | Swarm Scanner用 | ✅ 新基盤へ |

**呼び出し元:**
- `src/tools/custom/__init__.py` - ToolRegistry経由
- `src/core/agents/swarm/scanner/manager.py` - PortScanSpecialistで直接使用

---

### 4. Arjun（2実装）

| 実装 | パス | 用途 | 統合優先度 |
|------|------|------|------------|
| ArjunTool | `src/tools/custom/arjun.py` | ToolRegistry登録 | ✅ 新基盤へ |
| ArjunWrapper | `src/tools/fuzzing/arjun_wrapper.py` | パラメータ発見用 | ✅ 新基盤へ |

**呼び出し元:**
- `src/tools/custom/__init__.py` - ToolRegistry経由
- 現在のWrapper呼び出し元は未確認（要調査）

---

### 5. Httpx（2実装）

| 実装 | パス | 用途 | 統合優先度 |
|------|------|------|------------|
| HttpxTool | `src/tools/custom/httpx.py` | ToolRegistry登録 | ✅ 新基盤へ |
| HttpxWrapper | `src/tools/wrappers/httpx_wrapper.py` | 直接HTTPプローブ用 | ⚠️ 別物かも |

**注意:** `httpx_wrapper.py`はPythonのhttpxライブラリを使用（Goツールのhttpxとは別物）

---

### 6. Gau（2実装）

| 実装 | パス | 用途 | 統合優先度 |
|------|------|------|------------|
| GAUTool | `src/tools/custom/gau.py` | ToolRegistry登録 | ✅ 新基盤へ |
| GAUIntegrator | `src/core/wordlist/gau_integrator.py` | URL収集統合 | ✅ 新基盤へ |

**呼び出し元:**
- `src/tools/custom/__init__.py` - ToolRegistry経由
- `src/core/wordlist/__init__.py` - GAUIntegratorエクスポート

---

## 統合戦略

### 優先順位

1. **Phase E-1**: Nuclei, Ffuf, Nmap（使用頻度が高い）
2. **Phase E-2**: Arjun, Gau（使用頻度が中程度）
3. **Phase E-3**: Httpx（Goツールと区別が必要）

### 移行パターン

```python
# 現在の呼び出し（Wrapper）
self.nuclei = NucleiWrapper()
results = await self.nuclei.scan(target)

# 移行後（新基盤）
from src.core.adapters.external.nuclei_adapter import NucleiAdapter
from src.core.adapters.external.external_tool_executor import get_global_executor

adapter = NucleiAdapter()
executor = get_global_executor()
result = await executor.execute(adapter, ToolInput(target=target))
```

### 後方互換性維持

```python
# wrapper.py は Adapter へのラッパーとして維持
class NucleiWrapper:
    """[DEPRECATED] Use NucleiAdapter with ExternalToolExecutor instead."""
    
    async def scan(self, target, ...):
        # 内部で新基盤を使用
        adapter = NucleiAdapter()
        result = await self._executor.execute(adapter, ToolInput(target=target))
        return self._convert_result(result)  # 旧形式に変換
```

## 修正が必要なファイル一覧

### Phase E-1（Nuclei, Ffuf, Nmap）

#### Nuclei
- [x] `src/core/adapters/external/nuclei_adapter.py` (新規作成)
- [x] `src/tools/scanners/nuclei_wrapper.py` (非推奨化 + ラッパー化後に削除完了)
- [x] `src/core/tools/nuclei_integrator.py` (現状維持。並行利用のため存続)
- [x] `src/core/agents/swarm/scanner/manager.py` (移行)
- [x] `src/core/project/project_manager.py` (移行対象外を確認)
- [x] `src/tools/custom/__init__.py` (エイリアス維持)

#### Ffuf
- [x] `src/core/adapters/external/ffuf_adapter.py` (新規作成)
- [x] `src/core/tools/ffuf_wrapper.py` (非推奨化 + ラッパー化後に削除完了)
- [x] `src/core/agents/swarm/fuzzing/manager.py` (移行)
- [x] `src/core/attack/native_fuzzer.py` (移行不要を確認。fallback実装として維持)

#### Nmap
- [x] `src/core/adapters/external/nmap_adapter.py` (新規作成)
- [x] `src/tools/scanners/nmap_wrapper.py` (非推奨化 + ラッパー化後に削除完了)
- [x] `src/core/agents/swarm/scanner/manager.py` (移行)

### Phase E-2（Arjun, Gau）

- [x] `src/core/adapters/external/arjun_adapter.py` (新規作成)
- [x] `src/tools/fuzzing/arjun_wrapper.py` (参照切替完了後に削除)
- [x] `src/core/adapters/external/gau_adapter.py` (新規作成)
- [x] `src/core/wordlist/gau_integrator.py` (分析責務維持 + 実行責務を統合)

### Phase E-3（Httpx）

- [x] Python httpx vs Go httpx の明確な区別
- [x] `src/tools/custom/httpx.py` (Goツール用) - 新基盤で運用
- [x] `src/tools/wrappers/httpx_wrapper.py` (Pythonライブラリ) - 別物として維持

## 影響リスク評価

| ツール | リスクレベル | 理由 |
|--------|--------------|------|
| Nuclei | 中 | 多くのテストファイルで使用 |
| Ffuf | 中 | fuzzingマネージャーで直接使用 |
| Nmap | 低 | scannerマネージャーのみ |
| Arjun | 低 | 使用箇所が少ない |
| Gau | 低 | wordlistパッケージのみ |
| Httpx | 低 | Go/Python区別で対応 |

## テスト戦略

1. 新Adapter実装時に統合テスト作成（DalFoxパターンで）
2. Wrapperの後方互換テスト
3. E2Eテストの段階的移行
