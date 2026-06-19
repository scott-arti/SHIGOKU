---
task_id: SGK-2026-0066
doc_type: roadmap
doc_usage: reference_roadmap
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# SHIGOKU Bug Bounty Optimization Roadmap

**Date**: 2026-03-03
**Status**: Draft

## 目標 (Objective)

SHIGOKUエンジンをBug Bounty（バグ報奨金プログラム）に特化させ、報酬に直結しやすい高価値な脆弱性を効率的に発見できる体制を構築する。同時に、プログラムのScope外となる可能性が高い危険な攻撃を自動的に抑制する仕組みを導入する。

## フェーズ 1: Scope制御と安全性の強化 (Core Safety)

Bug Bountyの基本ルールを遵守するための基盤改修。

1.  **Scope判定の高度化**:
    - `src/core/domain/scope/scope_manager.py` および関連するパーサーを拡張し、インプットされたScope情報から「Post-Exploitation（侵害後調査）の可否」を自動判定するロジックを追加。
2.  **PostExploit実行制御**:
    - `MasterConductor` もしくは `SwarmDispatcher` において、`--mode bugbounty` かつ Scope判定で不許可な場合、`secret_looter`, `internal_recon`, `pivot_scan` などの活動をブロック、あるいはフェイルセーフでOFFにする。

## フェーズ 2: 既存機能のブラッシュアップ (Refinement)

不要なモックの排除と、中途半端な機能の整理。

1.  **LLMCryptoAnalyzerの削除**:
    - バウンティにおいて価値が低いため、`src/core/agents/swarm/scanner/llm_specialists.py` からTLS/SSL検査モジュールを削除。
2.  **CloudMisconfigCheckerの本実装**:
    - `src/core/agents/swarm/secret/manager.py` 内のTODOを解消し、S3バケット等の公開設定ミスを検査するロジックを実装。
3.  **Recon Pipeline Mockの整理**:
    - `src/recon/tool_runner.py` や `pipeline.py` に点在する `DEV_MODE` のハードコードMock出力を、本番環境で誤動作しないようにテスト専用の仕組みとして分離・整理。

## フェーズ 3: 高価値Specialistの新規実装 (High-Value Targets)

Bug Bountyでクリティカルになりやすい領域に特化した新しいSpecialistの作成。

1.  **Subdomain Takeover Specialist**:
    - 既存の `subjack` ラッパー (`src/tools/custom/subjack.py`) を活用し、Reconで得たデッドサブドメインに対してテイクオーバー検証を自動実行するSpecialistを実装。必要に応じて `Nuclei` も併用。
2.  **Web Cache Deception Specialist**:
    - 認証エンドポイントに対して、静的ファイルの拡張子（`.css`, `.js`等）を付与してアクセスし、非認証状態でキャッシュがヒットするか（個人情報が漏洩するか）を判定するSpecialistを実装。
3.  **Source Map & JS Secrets Specialist**:
    - 発見された `.js` ファイルに対して `.js.map` の存在を確認し、ソースコードを復元して未公開APIやクラウドクレデンシャルを抽出するSpecialistを実装。

## フェーズ 4: E2E検証 (Verification)

実装した全フェーズを結合し、安全かつ正確に動作することを証明する。

1.  **ユニットテスト拡充**:
    - 新規作成したモジュールに対する `pytest` の作成。
2.  **Bug Bounty Dry-Run 結合テスト**:
    - `python -m src.main --target example.com --mode bugbounty --dry-run` を実行し、PostExploitがブロックされ、新しいSpecialistがReconフェーズ後に正しくディスパッチされることを確認。
