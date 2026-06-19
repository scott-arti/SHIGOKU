---
task_id: SGK-2026-0151
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Phase 3.2: Fuzzing Swarm (Active Reconnaissance)

## 概要

Fuzzing Swarm は、能動的な総当たり攻撃（ディレクトリ探索、パラメータ探索など）を担当するエージェント群である。
他の Swarm と異なり、サーバーリソースへの負荷が高いため、**「デフォルトでは実行しない (Pending Queue に入れる)」** という厳格なポリシーを持つ。

## コンポーネント

### 1. FuzzingSwarm (Manager)

- タグ (`dir_brute`, `param_fuzz`) に基づき、適切なスペシャリストにディスパッチする。
- **Routing**:
  - `fuzz`, `dir_brute` -> `DirBruteSpecialist`
  - `api_endpoint` -> `DirBruteSpecialist` (ただし Default OFF)

### 2. DirBruteSpecialist

- ディレクトリ/ファイル探索を行う。
- **Action Policy**:
  - `force_fuzz` タグがある場合: **即時実行**。
  - `force_fuzz` タグがない場合: **実行スキップ**し、GraphDB (Neo4j) の `PendingTask` に保存する。
- **Engine**:
  - `ffuf`: 推奨。高速。JSONモードで実行。
  - `NativeFuzzer`: Python実装のフォールバック。低速だが依存なし。
- **Wordlist**: `assets/wordlists/common.txt` (なければ自動生成)。

### 3. Knowledge Graph Integration

Neo4j に Pending Task を保存・管理する。

```cypher
MERGE (p:Page {url: $url})
MERGE (t:PendingTask {url: $url, category: 'fuzzing'})
SET t.status = 'PENDING', t.reason = 'Default OFF Policy'
MERGE (p)-[:HAS_PENDING_TASK]->(t)
```

## CLI 拡張 (Re-scan)

Pending されたタスクを一括実行するためのコマンド。

```bash
python -m src.main --target pending_fuzz
```

内部的に `KnowledgeGraph.get_pending_tasks()` を呼び出し、取得したURLに対して `force_fuzz` タグを付与したタスクを一括生成する。

## データフロー

1. `MasterConductor` -> `SwarmDispatcher` -> `FuzzingSwarm`
2. `FuzzingSwarm` checks tags.
   - If `force_fuzz`: Run ffuf -> Findings
   - If no `force_fuzz`: Save to Neo4j -> Info Finding ("Added to Pending Queue")
3. User runs `python -m src.main --target pending_fuzz`
4. `MasterConductor` loads URLs from Neo4j -> Creates tasks with `force_fuzz`.
5. `FuzzingSwarm` executes ffuf.
