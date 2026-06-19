---
task_id: SGK-2026-0080
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-09'
updated_at: '2026-05-19'
---

# Specification: Fix File Storage & Findings Persistence

## 1. 概要

現在、Reconツールの出力ファイルがプロジェクトディレクトリ (`workspace/projects/{target}/`) ではなくルートディレクトリに散乱する問題と、攻撃成功時のFindings（脆弱性情報）がJSONファイルとして永続化されていない問題を修正する。
これにより、Artifactsの散逸を防ぎ、レポート機能やダッシュボード機能が正しく動作する基盤を整える。

## 2. 変更範囲

### Target 1: Recon出力先の適正化 (Phase 4.1)

- **現状**: `ReconPipeline` がデフォルトで `cwd` をワークスペースとして使用している。
- **変更**:
  - `InteractiveBridge` から `ReconPipeline` を初期化する際、必ず `ProjectManager.project_dir` を `workspace_root` として渡す。
  - `ReconPipeline` 内で `ProjectManager` が渡されている場合、そのパスを優先的に使用するロジックを強化。
  - `ParallelTasks` も同様にプロジェクトディレクトリに出力するように修正。

### Target 2: Findingの永続化 (Phase 4.1)

- **現状**: `MasterConductor.handle_finding` で通知は送られるが、`ProjectManager.save_finding` が呼ばれていない。
- **変更**:
  - `MasterConductor.handle_finding` 内で、`self.project_manager.save_finding(finding)` を呼び出し、`workspace/projects/{target}/findings/*.json` として保存する。

## 3. 挙動 (Input/Output)

### Recon

- **Input**: `python -m src.main --recon example.com`
- **Output**:
  - `workspace/projects/example.com/scans/raw/YYYYMMDD_recon_subfinder.txt` (ルート直下ではない)
  - `workspace/projects/example.com/scans/raw/YYYYMMDD_recon_httpx.json`

### Finding

- **Input**: 脆弱性が発見され、`handle_finding` が呼ばれる。
- **Output**:
  - `workspace/projects/example.com/findings/{ID}_sqli.json`

## 4. 制約

- 既存の `ProjectManager` の構造に従うこと。
- `MasterConductor` は `ProjectManager` が設定されていない場合（単発実行など）のエラーハンドリングを行うこと。

## 5. 検証計画

1. **Recon Path Verification**:
   - `ReconPipeline` をテストモードで初期化し、ダミーファイルを作成させる。
   - ファイルが `workspace/projects/test_target/...` に作成されることを確認。
2. **Finding Persistence Verification**:
   - `MasterConductor` にダミーの `Finding` オブジェクトを渡し、`handle_finding` を実行。
   - `workspace/projects/test_target/findings/` にJSONが保存されることを確認。
