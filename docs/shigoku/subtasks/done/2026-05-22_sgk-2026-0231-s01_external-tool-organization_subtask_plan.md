---
task_id: SGK-2026-0231-S01
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0231
related_docs:
  - docs/shigoku/plans/done/2026-05-22_sgk-2026-0231_juice-shop-phase-d-continuous-improvement_plan.md
  - docs/shigoku/plans/phase_e2_next_action_plan.md
  - docs/shigoku/reports/phase_e2_cto_review.md
created_at: '2026-05-22'
updated_at: '2026-06-30'
---

# 外部ツール配置整理サブタスク (SGK-2026-0231-S01)

## 概要

Phase D実装に先立ち、外部ツール（FOSSツールラッパー）の配置を整理する。
現在バラバラに配置されている外部ツールを統一的な構造に再編成し、DalFox統合の前提条件を整備する。

## 親タスク

- [SGK-2026-0231: Phase D 継続的改善計画](../../plans/done/2026-05-22_sgk-2026-0231_juice-shop-phase-d-continuous-improvement_plan.md)

## 現状分析

### 現在の外部ツール配置

| ディレクトリ | ツール | 分類の問題 |
|-------------|--------|-----------|
| `src/tools/wrappers/` | `httpx_wrapper.py` | 命名規則不統一（`_wrapper`接尾辞） |
| `src/tools/scanners/` | `nmap_wrapper.py`, `nuclei_wrapper.py` | `nuclei`が`custom/`にも存在（重複） |
| `src/tools/custom/` | `hydra.py`, `nuclei.py`, `xxeinjector.py` | 外部ツールとカスタムツールが混在 |
| `src/tools/fuzzing/` | `arjun_wrapper.py` | 分類基準不明確 |
| `src/tools/oob/` | `interactsh_client.py` | 良好（機能別分類） |

### 問題点

1. **命名規則の不統一**: `_wrapper`接尾辞の有無がバラバラ
2. **重複配置**: `nuclei`が`scanners/`と`custom/`に両方存在
3. **分類基準の曖昧性**: 外部FOSSツールと内部カスタムツールの区別が不明確
4. **DalFoxの配置未決定**: Phase Dで統合予定だが配置場所が未定

## 目標構造

### 案C（推奨）: 統合アダプター層

```
src/core/adapters/external/
├── __init__.py
├── base_external_adapter.py    # 共通基底クラス
├── dalfox_adapter.py           # DalFox（Phase D新規）
├── nuclei_adapter.py           # Nuclei（移行予定）
├── nmap_adapter.py             # Nmap（移行予定）
├── httpx_adapter.py            # httpx（移行予定）
└── hydra_adapter.py            # Hydra（移行予定）
```

### Phase D実装範囲

- ✅ **新規作成**: `dalfox_adapter.py`（本サブタスク完了後に実装）
- ⚠️ **移行**: 既存ツールの移行はPhase Eで対応（本タスクでは設計のみ）

## タスク分解

### Step 1: 現状分析と技術的課題特定

- [ ] 外部ツール実装の詳細インベントリ作成
- [ ] 各ツールの依存関係・実行環境の技術的分析
- [ ] **[技術課題]** バイナリ管理方式の統一性欠如問題の特定
- [ ] **[技術課題]** インターフェース不統一によるテスト困難性の分析
- [ ] **[技術課題]** CI/CD環境での外部ツール実行未整備の影響評価
- [ ] **[技術課題]** 監視・ロギング不足による運用性問題の分析

### Step 2: 統一アダプター基盤の技術設計

- [ ] `src/core/adapters/external/` の技術的設計
- [ ] `BaseExternalAdapter` 抽象基底クラスの実装設計
- [ ] **[技術実装]** ToolResultデータクラスによる戻り値統一
- [ ] **[技術実装]** BinaryManagerクラスによるバイナリ管理統一
- [ ] **[技術実装]** ExternalToolLoggerによる監視・ロギング統合
- [ ] **[技術実装]** 設定管理統合（external_tools.yamlスキーマ設計）
- [ ] **[技術実装]** 依存性注入によるテスタビリティ確保
- [ ] **[技術実装]** セキュリティ検証設計（チェックサム検証、サプライチェーン対策）
- [ ] **[技術実装]** インターフェース型定義の詳細設計（Input/Output型、例外戦略）
  - **選定基準**: 非同期フローとの親和性、パフォーマンス影響を考慮して例外戦略を文書化
- [ ] **[技術実装]** デバッグロギング詳細度の定義と実装方針
  - **制限定義**: デバッグモード時のパフォーマンス影響閾値（5倍以上遅延時の警告基準）を設定

### Step 3: DalFox統合の技術的実装

- [ ] DalFox Goバイナリの自動ダウンロード・バージョン管理実装
- [ ] `dalfox_adapter.py` のBaseExternalAdapter継承実装
- [ ] **[技術実装]** ヘルスチェック機構（バイナリ存在確認・基本実行テスト）
- [ ] **[技術実装]** 実行結果のToolResult標準化
- [ ] **[技術実装]** エラーハンドリングとフォールバック戦略
- [ ] **[技術実装]** パフォーマンス監視と実行時間計測

### Step 4: CI/CD統合と移行検証の技術実装

- [ ] GitHub Actionsでの外部ツール実行環境自動構築
- [ ] **[技術実装]** MigrationValidatorによる機能等価性検証
- [ ] **[技術実装]** 自動回帰テストスイートの実装
- [ ] **[技術実装]** パフォーマンスベンチマークの実装
- [ ] **[技術実装]** 互換性チェックツールの実装
- [ ] **[技術実装]** CI/CDでの外部ツールバージョン管理戦略

### Step 5: 運用監視とドキュメントの技術実装

- [ ] 外部ツール統合ガイドの技術的ドキュメント化
- [ ] **[技術実装]** リアルタイム監視ダッシュボードの実装
- [ ] **[技術実装]** トラブルシューティング自動化ツールの実装
- [ ] **[技術実装]** パフォーマンス監視とアラート機構の実装
- [ ] **[技術実装]** AGENTS.md/Windsurf Rulesへの自動反映プロセス実装
- [ ] **[技術実装]** 運用マニュアルの自動生成システム実装


## 完了ステータス更新（2026-05-25）

- 本サブタスクの主要成果物（`src/core/adapters/external/` 基盤、`dalfox_adapter.py`、関連設計ドキュメント）がリポジトリ上で確認できたため、台帳ステータスを `done` に更新。
- 残課題（MigrationValidator/運用監視等）は SGK-2026-0231-S02 側の継続タスクとして扱う。

## 成果物

| 成果物 | パス | 技術的内容 |
|--------|------|-----------|
| 技術課題分析レポート | `docs/shigoku/specs/external_tools_analysis.md` | 現状分析＋技術的課題特定 |
| 統一アダプター基盤実装 | `src/core/adapters/external/` | BaseExternalAdapter＋BinaryManager＋Logger |
| DalFox統合実装 | `src/core/adapters/external/dalfox_adapter.py` | 新基盤準拠のDalFoxアダプター |
| CI/CD統合実装 | `.github/workflows/external-tools-test.yml` | 外部ツール自動テスト環境 |
| 移行検証フレームワーク | `tests/core/adapters/test_migration_validator.py` | MigrationValidator＋回帰テスト |
| 監視ダッシュボード | `src/core/monitoring/external_tools_dashboard.py` | リアルタイム監視＋パフォーマンス計測 |
| 自動ドキュメント生成 | `scripts/generate_external_tools_docs.py` | 技術ドキュメント自動生成 |

## タイムライン

| Step | 内容 | 技術的完了基準 |
|------|------|----------------|
| Step 1 | 現状分析と課題特定 | 技術課題レポート＋インベントリ＋影響評価 |
| Step 2 | 統一アダプター基盤設計 | BaseExternalAdapter実装＋BinaryManager＋Logger統合 |
| Step 3 | DalFox統合実装 | dalfox_adapter.py実装＋ヘルスチェック＋監視統合 |
| Step 4 | CI/CD統合と移行検証 | CI/CD実装＋MigrationValidator＋回帰テスト |
| Step 5 | 運用監視とドキュメント | 監視ダッシュボード＋自動ドキュメント生成 |

## 完了基準

- [ ] 外部ツールの技術的課題が特定・文書化されている
- [ ] BaseExternalAdapterを継承した統一アダプター基盤が実装されている
- [ ] DalFoxアダプターが新基盤に準拠して実装されている
- [ ] CI/CD環境での外部ツール自動テストが実装されている
- [ ] **[技術実装]** MigrationValidatorによる機能等価性検証が完了している
- [ ] **[技術実装]** リアルタイム監視とパフォーマンス監視が実装されている
- [ ] **[技術実装]** 自動ドキュメント生成とルール反映プロセスが実装されている
- [ ] **[技術実装]** 全ての新規実装に対する単体テスト・統合テストが完了している

## 依存関係

- 本サブタスク完了後 → DalFox統合実装（Phase D Day 3）
- Phase E → 既存ツールの一括移行

## 技術的根拠と実装方針

### バイナリ管理統一の技術的必要性
**問題**: 現在の`shutil.which()`のみのチェックではバージョン管理、実行権限、パス管理が不統一
**解決策**: BinaryManagerクラスによる統一的バイナリライフサイクル管理
- 自動ダウンロード・バージョン固定・実行権限管理
- `~/.shigoku/binaries/` 配下での一元管理
- ヘルスチェックと自動修復機能

### インターフェース標準化の技術的必要性
**問題**: 各Wrapperクラスの戻り値形式、エラーハンドリング、非同期処理がバラバラ
**解決策**: BaseExternalAdapter抽象クラスによる強制インターフェース
- ToolResultデータクラスによる戻り値統一
- validate_inputs()による入力検証の強制
- 依存性注入によるテスト容易性確保

### CI/CD統合の技術的必要性
**問題**: 外部ツールの実行環境未整備、バージョンアップでCI失敗リスク
**解決策**: GitHub Actionsでの外部ツール実行環境自動構築
- DalFox、Nuclei等の自動インストール
- MigrationValidatorによる機能等価性自動検証
- パフォーマンス回帰テストの自動実行

### 監視・ロギング統合の技術的必要性
**問題**: 外部ツール実行のパフォーマンス監視不足、エラートレース不十分
**解決策**: ShigokuLogger拡張による外部ツール専用監視
- 実行時間、成功/失敗率、リソース使用量の計測
- コンテキスト情報付きログ出力
- リアルタイム監視ダッシュボード

## リスク

| 技術的リスク | 影響 | 技術的対策 |
|-------------|------|-----------|
| 外部ツール依存の複雑性 | 高 | BinaryManagerによる自動管理・コンテナ化検討 |
| インターフェース移行の互換性 | 中 | MigrationValidatorによる自動検証・段階的移行 |
| CI/CD実行時間増大 | 中 | キャッシュ戦略・並列実行・必要時のみ実行 |
| 監視データの増大 | 低 | ログローテーション・サンプリング戦略 |

## 実装優先順位と段階的アプローチ

### Phase D Day 3前に必須（技術的ブロッカー）
1. **型安全なBaseExternalAdapter実装** - 全アダプターの基底となる型安全なインターフェース
   - **要注意**: 過度な抽象化を避け、`**kwargs`による柔軟な拡張ポイントを確保
   - **抽象メソッド**: `execute`, `validate_inputs`, `health_check`のみ最小限に
2. **BinaryManagerのセキュリティ検証機能** - サプライチェーン攻撃対策の必須機能
   - **要注意（4層防御）**:
     - 層1: PRテンプレートに「検証前chmod禁止」チェックリスト
     - 層2: カスタムlinterルールで`chmod`前の検証関数呼び出しを強制
     - 層3: BinaryManager内で検証済みフラグによる状態管理
     - 層4: 一時ディレクトリで検証→成功後に移動→権限付与のアトミックプロセス
   - **絶対禁止**: 検証前の`binary_path.chmod(0o755)`はセキュリティインシデントにつながる
3. **ToolResult統一フォーマット** - 全ツール共通の戻り値形式標準化

### Phase D（本サブタスク）: 基盤構築とDalFox統合
1. **最優先**: BaseExternalAdapterとBinaryManagerの実装
   - **実装方針**: 4層防御のセキュリティ検証フローを厳密に実装
2. **次優先**: DalFoxアダプターの新基盤準拠実装
   - **実装方針**: BaseExternalAdapter継承、例外戦略はtry-exceptブロックで統一
3. **並行**: 監視・ロギング統合の基本実装
4. **並行実装推奨**: セマフォによる非同期制御（並行度管理）
   - **要注意**: 理想はリソース連動だが、まずは単純な`asyncio.Semaphore(5)`で開始
   - **再検討タイミング**: 外部ツール実行でリソース枯渇が発生した場合に最適化
5. **並行実装推奨**: external_tools.yamlスキーマ定義（設定管理統合）
   - **選定基準**: 非同期フローとの親和性、パフォーマンス影響を考慮して例外戦略を文書化
6. **並行実装推奨**: ロギング詳細度制御（DEBUG/INFOレベル使い分け）
   - **制限定義**: デバッグモード時のパフォーマンス影響閾値（5倍以上遅延時の警告基準）を設定

### Phase E: 既存ツール移行
1. **高優先度**: NucleiAdapter、NmapAdapter（使用頻度高）
2. **中優先度**: HttpxAdapter、ArjunAdapter
3. **低優先度**: HydraAdapter（使用頻度低）
4. **追加検討**: Dockerコンテナ化評価（環境依存解消のためPhase Eで技術検証）

**優先順位選定基準**:
- 使用頻度: 過去30日の実行ログ分析（`logs/tools/`配下のログ解析）
- 影響度: 検出する脆弱性の重要度（CVSSスコア関連性）
- 工数: 既存Wrapperの複雑性評価（コード行数・依存関係数）

**優先順位選定基準**:
- 使用頻度: 過去30日の実行ログ分析（`logs/tools/`配下のログ解析）
- 影響度: 検出する脆弱性の重要度（CVSSスコア関連性）
- 工数: 既存Wrapperの複雑性評価（コード行数・依存関係数）

### Phase E移行時に活用
- **ExecutionSnapshotによる再現性確保** - 移行時の回帰バグ再現・検証用
  - **セキュリティ考慮**: APIキー・パスワード等の機密情報マスキング処理を必須実装
  - **実装方針**: 既存の`PIIMasker`（`src/core/security/pii_masker.py`）を流用
    ```python
    from src.core.security.pii_masker import PIIMasker
    
    class SecureExecutionSnapshot:
        def __init__(self):
            self.masker = PIIMasker()
        def create_snapshot(self, environment: Dict[str, str]) -> Dict[str, str]:
            masked_env = {}
            for key, value in environment.items():
                result = self.masker.mask(value)
                masked_env[key] = result.masked
            return masked_env
    ```
  - **必須対策**: `sk-*`, `AKIA*`, `ghp_*`, `private_key`パターン等を自動検出・マスキング
  - **注意**: トークンマップはメモリ上のみ保持、スナップショットには保存しない
- **MigrationValidator実装** - 既存 vs 新規アダプターの機能等価性自動検証
- **CI/CDキャッシュ戦略** - 外部ツールの効率的なCI環境構築
  - **見送り推奨**: 現時点ではキャッシュなしで実装
  - **再検討タイミング**: CI実行時間が10分以上に悪化した場合に最適化実施

### 技術的実装の段階的検証
1. **単体テスト**: 各アダプターの個別機能検証
2. **統合テスト**: 既存システムとの連携検証
3. **回帰テスト**: MigrationValidatorによる機能等価性検証
4. **負荷テスト**: パフォーマンスベンチマークによる影響評価

## 成功指標と検証基準

### 技術的成功指標
- **バイナリ管理自動化率**: 95%以上のツールで自動ダウンロード・バージョン管理成功
- **インターフェース統一率**: 100%の新規アダプターがBaseExternalAdapterを継承
- **CI/CD統合成功率**: 外部ツール関連テストのCI成功率98%以上
- **監視カバレッジ**: 全ての外部ツール実行の監視データ取得率100%

### 運用的成功指標
- **移行互換性**: 既存ツールとの機能等価性99%以上
- **パフォーマンス**: 新基盤での実行時間が既存実装の±10%以内
- **信頼性**: 外部ツール実行のエラーハンドリング成功率95%以上
- **保守性**: 新規外部ツール追加工数が50%削減

## メモ

- 本サブタスクは**技術的基盤構築**が主目的。実装はPhase D Day 3で本格実施。
- 全ての技術実装は具体的なコードレベルでの設計を完了させること。
- 各Stepの完了は技術的実装と単体テストの成功を必須条件とする。
