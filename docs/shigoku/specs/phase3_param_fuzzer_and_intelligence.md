---
task_id: SGK-2026-0153
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Phase 3: ParamFuzzer & Intelligence Implementation

## 1. Param Fuzzer (Fuzzing Swarm)

**Target**: `docs/IMPLEMENTATION_ROADMAP.md` Section 3.2.1

### Overview

隠しパラメータ（Hidden Parameters）を発見し、IDORやMass Assignmentの攻撃面を広げる機能。
既存の `ParamFuzzerSpecialist` (Placeholder) を実体化する。

### Implementation Details

#### Core Logic: `ArjunWrapper`

- **Path**: `src/tools/fuzzing/arjun_wrapper.py`
- **Function**: CLIツール `arjun` を `subprocess` で呼び出し、JSON出力をパースする。
- **Constraint**: `shutil.which("arjun")` で存在確認。なければ Falback。

#### Fallback: `NativeParamFuzzer`

- **Path**: `src/core/attack/native_param_fuzzer.py` (New)
- **Logic**:
  - Reflection Detection: パラメータ値がレスポンスに反射するかチェック。
  - Status Code Change: パラメータ有無でステータスやコンテンツ長が変わるかチェック。
  - Heuristics: `admin`, `debug`, `test` などの頻出パラメータ辞書を使用。

#### Swarm Integration

- **Path**: `src/core/agents/swarm/fuzzing/manager.py`
- **Class**: `ParamFuzzerSpecialist`
  - `execute(task)` 内で、Arjun -> Native の順に試行。
  - 結果を `Finding` (Severity: INFO/LOW) として返す。タグ `has_params` を付与。

---

## 2. Intelligence Swarm (OSINT)

**Target**: `docs/IMPLEMENTATION_ROADMAP.md` Section 3.3.1

### Overview

ターゲット組織の GitHub リポジトリを特定し、コードおよびコミュニケーション（Issue/PR）から機密情報を発見する。

### Implementation Details

#### GitHub API Client

- **Path**: `src/tools/osint/github_recon.py`
- **Function**:
  - `search_org_repos(org_name)`: リポジトリ一覧取得。
  - `get_issue_comments(repo)`: コメント取得。
  - **Note**: `GITHUB_TOKEN` 環境変数を使用。Rate Limit待機ロジックを含む。

#### Leak Detector

- **Path**: `src/tools/osint/leak_detector.py`
- **Function**:
  - `run_gitleaks(repo_path)`: `gitleaks detect` を実行。
  - `scan_comments(comments)`: 正規表現による「文脈依存漏洩」検知。
    - Keywords: `password`, `secret`, `key`, `credential` + Assignment (`=`, `:`)

#### Swarm Integration

- **Path**: `src/core/agents/swarm/intelligence/manager.py`
- **Class**: `IntelligenceSwarm`
  - `GitHubReconSpecialist`: 上記ツールをオーケストレーション。
  - `MasterConductor` から `intelligence` モードで呼び出される。

---

## 3. Verification Plan

### Automated Tests

1. **Unit Test (ParamFuzzer)**:
   - `ArjunWrapper` の Mock テスト（外部コマンド呼び出しの模倣）。
   - `NativeParamFuzzer` のロジックテスト（反射検知）。
2. **Unit Test (Intelligence)**:
   - `GitHubRecon` の Mock テスト（APIレスポンスの模倣）。
   - `LeakDetector` の正規表現テスト。

### Manual Verification

1. `python -m src.main --target http://localhost:8000 --tags has_params` で ParamFuzzer が動作するか確認。
2. `python -m src.main --target github.com/test-org --mode intelligence` で GitHub Recon が動作するか確認。
