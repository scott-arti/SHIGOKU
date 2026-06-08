---
task_id: SGK-2026-0231-S02
doc_type: plan
status: done
parent_task_id: SGK-2026-0231
related_docs:
- docs/shigoku/plans/ai_tool_integration_guide.md
- docs/shigoku/reports/phase_e2_cto_review.md
- docs/shigoku/subtasks/2026-05-23_sgk-2026-0231-s02_ai-integration-and-adapter-expansion.md
- docs/shigoku/plans/2026-05-23_toolregistry-phase-e-3_plan.md
created_at: '2026-05-23'
updated_at: '2026-05-25'
---

# Phase E-2: 次のアクションプラン

## Sprint 1判定ステータス（2026-05-25）
- 判定: **GO（Sprint 2継続可）**
- 判定根拠:
  - 機能一致率 `100%`（3ターゲット）
  - FN率/FP率 `0% / 0%`（3ターゲット）
  - 性能劣化ゲート（+10%超）違反なし
- 参照: `docs/shigoku/reports/phase_e2_cto_review.md` 追補セクション

## 現在の状況

### 完了済み (Phase E-1)
- ✅ `BaseExternalAdapter` 抽象基底クラス
- ✅ `BinaryManager` 4層防御セキュリティ実装
- ✅ `ExternalToolExecutor` セマフォ並行制御
- ✅ `ExternalToolLogger` 統合監視
- ✅ `DalFoxAdapter` + CLIコマンド
- ✅ `NucleiAdapter` + CLIコマンド
- ✅ `AIToolBridge` AIエージェント接続層

### 未完了の課題
- ⚠️ AIエージェントは一部新ツールのみ使用可（`nuclei_scan`/`dalfox_scan`）。残り4ツール公開は未完了
- ✅ Ffuf/Nmap/Arjun/Gau Adapterは実装済み（AI公開・移行検証は未完了）
- ✅ 実運用経路の旧Wrapper依存は解消（残存は互換維持/検証用途のみ）

### 直近アップデート（2026-05-25）
- `PortScanSpecialist`/`VulnScanSpecialist`/`DirBruteSpecialist` は `Adapter + ExternalToolExecutor` 直結へ移行済み。
- `MigrationValidator` は `NucleiWrapper` 依存を廃止し、`Adapter direct` と `Adapter+Executor` の新基盤内比較へ更新済み。

---

## 次のアクションプラン

### Sprint 1: AI統合検証（2-3日）

#### 1.1 Manager統合テスト
```
タスク: ScannerSwarmにAIToolBridge統合
├── 実装: scanner/manager.pyにregister_external_tools_with_manager()呼び出し
├── テスト: AIが"nuclei_scan"アクションを選択・実行できるか検証
├── 検証: 旧VulnScanSpecialist vs 新Bridge統合の結果比較
└── 成果物: 動作確認レポート + パフォーマンス比較データ
```

#### 1.2 新旧比較テスト
```
タスク: 機能等価性自動検証
├── 実装: MigrationValidatorプロトタイプ
│   └── 旧Wrapper実行結果と新Adapter実行結果の比較
├── テストケース:
│   ├── 同一ターゲットでのスキャン結果比較
│   ├── エラーハンドリング動作比較
│   └── パフォーマンス比較（実行時間、リソース使用）
└── 合格基準: 結果の95%以上一致、パフォーマンス±10%以内
```

#### 1.3 段階的ロールアウト設計
```
タスク: 本番移行計画
├── フィーチャーフラグ実装（config/features.yaml）
│   ├── use_new_nuclei: false（デフォルト）
│   └── use_new_dalfox: false（デフォルト）
├── A/Bテスト設計
│   ├── 旧実装50% + 新実装50%の並行運用
│   └── エラー率・成功率の比較監視
└── ロールバック手順書作成
```

### Sprint 2: Phase E-2 Adapter AI公開・統合検証（3-5日）

#### 2.1 FfufAdapter AI公開
```
優先度: 高（fuzzingマネージャーで高頻度使用）
実施内容:
├── AIToolBridgeにffuf_scanを登録
├── 特殊要件: FUZZキーワード置換がAI経由入力でも破綻しないことを検証
├── 結果形式: status, length, words, linesを既存利用側と整合確認
└── テスト: fuzzing/manager統合テスト（AI経由）
```

#### 2.2 NmapAdapter AI公開
```
優先度: 高（scannerマネージャーで使用）
実施内容:
├── AIToolBridgeにnmap_scanを登録
├── オプション: port range, scan typeの入力バリデーションを確認
├── 結果形式: port, service, state, versionを既存出力契約と照合
└── テスト: scanner/manager経由のport scan統合テスト
```

#### 2.3 ArjunAdapter AI公開
```
優先度: 中（param fuzzing用）
実施内容:
├── AIToolBridgeにarjun_scanを登録
├── GET/POSTの入力スキーマと実行時オプションの整合確認
├── 結果形式: discovered parametersの下流互換確認
└── 統合: ParamFuzzerSpecialistの呼び出し経路検証
```

#### 2.4 GauAdapter AI公開
```
優先度: 中（URL収集用）
実施内容:
├── AIToolBridgeにgau_collectを登録
├── 複数プロバイダ指定（wayback, otx, commoncrawl）入力の検証
├── 結果形式: URLリストの正規化ルール確認
└── 統合: wordlist/gau_integrator呼び出し経路検証
```

### Sprint 3: 後方互換性整備（2-3日）

#### 3.1 Wrapper非推奨化
```
タスク: 旧Wrapperに非推奨マーキング
├── nuclei_wrapper.py:
│   └── class docstring: [DEPRECATED] Use NucleiAdapter
├── ffuf_wrapper.py:
│   └── class docstring: [DEPRECATED] Use FfufAdapter
├── nmap_wrapper.py:
│   └── class docstring: [DEPRECATED] Use NmapAdapter
└── logging.warning()追加（初回呼び出し時に警告）
```

#### 3.2 移行ラッパー実装
```
タスク: 旧Wrapper内部で新Adapter使用
実装パターン:
├── __init__()でNucleiAdapterインスタンス化
├── run()メソッドでToolInput構築
├── ExternalToolExecutor経由で実行
├── 結果を旧形式に変換して返却
└── 完全移行後に削除予定（3ヶ月後）
```

#### 3.3 テスト互換性維持
```
タスク: 既存テストの段階的移行
├── 方針: 旧テストは当面維持（後方互換確認用）
├── 新テスト: test_nuclei_integration.pyパターンで追加
└── 移行完了後: 旧テストを削除
```

### Sprint 4: 運用監視整備（2-3日）

#### 4.1 ログ監視ダッシュボード
```
実装: logs/監視スクリプト
├── リアルタイムログパーサー
├── セマフォ統計表示（並行度最適化用）
├── エラー集計（ツール別失敗率）
└── パフォーマンス推移グラフ
```

#### 4.2 アラート設定
```
閾値設定:
├── 並行実行待ち時間 > 500ms: 警告（セマフォ増加検討）
├── エラー率 > 5%: 警告（バイナリ問題調査）
├── 実行時間 > 基準値2倍: 警告（ターゲット問題調査）
└── バイナリ未検出: 即時通知（インストール失敗）
```

#### 4.3 セマフォ最適化
```
タスク: 並行度チューニング
├── デフォルト値: 5（現状維持）
├── 環境変数で上書き可能に: SHIGOKU_EXTERNAL_TOOL_CONCURRENCY
├── 監視データに基づく動的調整検討
└── チューニングガイドライン作成
```

---

## タイムライン

| Sprint | 期間 | 主要成果物 |
|--------|------|-----------|
| Sprint 1 | 2-3日 | AI統合検証レポート、フィーチャーフラグ実装 |
| Sprint 2 | 3-5日 | 4 AdapterのAI公開 + Manager統合テスト |
| Sprint 3 | 2-3日 | 後方互換ラッパー、移行手順書 |
| Sprint 4 | 2-3日 | 監視ダッシュボード、チューニングガイド |
| **合計** | **9-14日** | Phase E-2完了 |

---

## 成功基準

### 機能的基準
- [x] AIエージェントが新ツールを選択・実行できる
- [x] 新旧実装の結果一致率95%以上
- [x] FN/FPを分離記録し、重大な検出漏れが許容閾値内
- [x] パフォーマンス劣化10%以内
- [x] 全テストパス（既存+新規）

### 運用的基準
- [x] セマフォ統計がリアルタイムで監視可能
- [x] エラー検出時に即座に原因特定可能
- [x] 並行度調整が運用中に変更可能

### 移行基準
- [x] フィーチャーフラグで新旧切り替え可能
- [x] ロールバック手順が文書化・検証済み
- [x] 旧Wrapper使用時に非推奨警告を表示
- [x] 切替前後のヘルスチェックで復旧容易性を確認済み

### Wrapper削除判定基準（CTO承認ゲート）
- [x] `DirBruteSpecialist` 等の実運用経路が `FFufWrapper` 直呼びを解消し、`FfufAdapter + ExternalToolExecutor` を直接利用
- [x] `phase_e2_minimal` に含まれる後方互換テストと監視テストが連続で安定パス
- [x] 監視メトリクスの正規キーを `avg_waiting_time_ms` に統一し、旧キー `avg_wait_ms` の参照を期限付き互換に限定
- [x] 旧Wrapper利用ログ（DeprecationWarning / warning）が新規セッションで発生しないことを確認
- [x] 上記4項目を満たした時点で、旧Wrapper削除タスク（E-3）を起票して段階廃止

---

## 観点別レビュー統合（要件・懸念・解消策・実装方針）

### SRE/インフラエンジニア観点

#### 要件
- 最低4指標（成功率・待機時間・タイムアウト率・バイナリ未検出率）を常時計測できること。
- 並行度が環境に応じて安全に調整できること。
- 新旧切替時に運用側が即時に健全性判定できること。

#### 懸念点
- 監視指標が不足すると、障害検知が遅れ原因切り分けが長引く。
- `SHIGOKU_EXTERNAL_TOOL_CONCURRENCY` の異常値入力で過負荷またはスループット劣化が起きる。
- 切替手順が文書のみだと、実運用で判定が担当者依存になる。

#### 解消方法
- `ExternalToolLogger`/`ExternalToolExecutor` の統計出力に4指標を固定追加する。
- 並行度設定に範囲検証（例: `1..20`）と安全側フォールバックを入れる。
- ロールバック手順に「切替前」「切替後」のヘルスチェック項目を追加し、合否条件を明文化する。

#### 必要性・重要性
- 必要性: 本番での障害初動時間短縮に直結するため必須。
- 重要性: 高。AI統合の品質より先に運用不能リスクを抑える基盤要件。

#### 実装方針（E-2反映）
- Sprint 4で4指標の収集/表示を必須成果物に格上げ。
- Sprint 4.3で環境変数バリデーションとフォールバックを必須化。
- Sprint 1.3のロールバック手順へヘルスチェック表を追加。

### ソフトウェアアーキテクト観点

#### 要件
- E-2の責務を「AI公開と統合検証」に限定し、スコープを明確化すること。
- ToolRegistry整理はE-3（SGK-2026-0241）へ責務分離し、E-2完了条件から外すこと。
- `AIToolBridge` の非同期実行契約を呼び出し側で統一すること。

#### 懸念点
- スコープ混在で計画・実装・評価軸がぶれる。
- Registry統合をE-2で同時進行すると、変更面積が過大になる。
- 同期/非同期の呼び出し不整合でランタイム障害が発生する。

#### 解消方法
- Sprint 2を「AI公開・統合検証」に一本化し、再実装タスクを排除する。
- E-3参照を明示し、技術的負債は連携管理に切り替える。
- Manager層で `await` 契約を統一し、暫定的な同期ラッパー乱立を禁止する。

#### 必要性・重要性
- 必要性: 変更の独立性とレビュー容易性を確保するため必須。
- 重要性: 高。設計崩れがE-2全体の遅延・品質低下を誘発する。

#### 実装方針（E-2反映）
- Sprint 2の全項目をAI公開・統合検証タスクとして運用。
- 技術的負債章は「E-3参照」の位置づけを維持し、E-2成果物に混在させない。
- Sprint 1.1で `scanner/manager.py` を起点に非同期呼び出し契約を確認/統一する。

### バグハンター観点

#### 要件
- 新旧比較で一致率に加えてFN/FPを分離記録すること。
- 壊れやすい入力群を標準回帰セットとして固定化すること。
- 旧Wrapper互換を「戻り値スキーマ」「失敗意味」の2軸で検証すること。

#### 懸念点
- 一致率のみでは重大な検出漏れを見落とす可能性がある。
- 正常系中心テストでは実運用の異常入力で破綻しやすい。
- 互換性検証が曖昧だと、移行後に下流が静かに壊れる。

#### 解消方法
- MigrationValidator結果を `一致率/FN率/FP率` の3軸で記録する。
- 空URL、無効ポート、巨大入力、異常文字列を回帰ケースとして固定追加する。
- Wrapper移行テストで、成功時スキーマと失敗時エラーコード/メッセージ整合を別判定にする。

#### 必要性・重要性
- 必要性: セキュリティ製品として検出品質保証に不可欠。
- 重要性: 高。FN増加は利用者被害に直結し、FP増加は運用コストを増やす。

#### 実装方針（E-2反映）
- Sprint 1.2の合格判定を「一致率95%以上 + FN/FPの閾値内」に変更。
- Sprint 2各項目で壊れやすい入力の回帰検証を必須化。
- Sprint 3.3でWrapper互換テストを2軸判定に更新。

### CTO観点

#### 要件
- E-2の意思決定を「AI統合継続可否」「旧Wrapper維持方針」の2論点で明確化すること。
- 成功基準に運用復旧容易性（切戻し速度・原因切り分け速度）を含めること。
- 技術的負債（Registry二重化）の進捗監視を継続すること。

#### 懸念点
- 意思決定軸が増えると、Go/No-Go判定が主観化しやすい。
- KPI達成のみでは、障害時に復旧不能な計画となる恐れがある。
- 負債を別タスクへ分離しても追跡が切れる可能性がある。

#### 解消方法
- Sprint 1完了時の判定会で2論点のみを評価するフォーマットを用意する。
- 成功基準に復旧観点の検証項目を追加する。
- E-2進捗報告でE-3（SGK-2026-0241）ステータス確認を定例化する。

#### 必要性・重要性
- 必要性: 経営判断と技術判断を一致させるため必須。
- 重要性: 高。品質と運用可能性の両立を保証する最終ゲート。

#### 実装方針（E-2反映）
- Sprint 1成果物に「継続可否判定シート」を追加する。
- 成功基準へ「復旧容易性」の評価項目を追記する。
- 週次報告テンプレートへE-3進捗確認欄を追加する。

### 統合実装ポリシー（E-2）
- 優先順は `運用安全性` → `統合正確性` → `互換維持` → `負債追跡` とする。
- Go/No-Goは Sprint 1終了時点で判定し、Sprint 2以降はその判定に従って継続/修正する。
- E-2内で新規の大規模設計変更（Registry再設計など）は実施せず、E-3連携で管理する。

---

## 技術的負債対応: ToolRegistry統合（Phase E-3 / SGK-2026-0241参照）

### 現状の問題

```
⚠️ 2系統のToolRegistry（未解決の技術的負債）

src/tools/__init__.py       (ToolRegistry)      → 外部FOSSツール
src/core/tool_registry.py   (CoreToolRegistry)  → 内部ツール
```

**影響**:
- 開発者がどちらを使うべきか混乱
- ツール登録が分散（一貫性の欠如）
- ドキュメントメンテナンスが複雑

### 統合計画（Phase E-3）

#### 目標
- 単一のToolRegistryに統合
- 外部ツール・内部ツールを透過的に管理
- BaseTool継承で型安全を維持

#### タスク分解

```
タスク E-3.1: 統合Registry設計
├── 設計: UnifiedToolRegistryクラス
│   ├── 外部ツール登録（BaseExternalAdapter経由）
│   ├── 内部ツール登録（既存CoreToolRegistry機能）
│   └── カテゴリ・タグによる分類管理
├── 互換性: 既存APIの維持
│   ├── src/tools/__init__.pyは移行期間中ラッパーとして維持
│   └── src/core/tool_registry.pyも同様
└── 期間: 2週間

タスク E-3.2: 段階的移行
├── Phase 1: UnifiedToolRegistry実装（並行運用）
├── Phase 2: 内部ツール移行（CoreToolRegistry→Unified）
├── Phase 3: 外部ツール移行（ToolRegistry→Unified）
├── Phase 4: 旧Registry非推奨化
└── Phase 5: 旧Registry削除（3ヶ月後）

タスク E-3.3: 移行検証
├── 全ツール登録テスト
├── AI統合テスト（AIToolBridge経由）
└── パフォーマンス比較
```

#### インターフェース案

```python
# UnifiedToolRegistry（案）
class UnifiedToolRegistry:
    """統一ツールレジストリ
    
    外部ツール・内部ツールを透過的に管理
    """
    
    def register(self, tool: BaseTool, category: str = "internal") -> None:
        """ツール登録
        
        Args:
            tool: BaseTool継承のツール（内部・外部両方）
            category: "internal" | "external" | "custom"
        """
        pass
    
    def get_by_name(self, name: str) -> Optional[BaseTool]:
        """名前でツール取得（統一インターフェース）"""
        pass
    
    def get_by_category(self, category: str) -> List[BaseTool]:
        """カテゴリ別ツール一覧"""
        pass
    
    def get_by_tags(self, tags: List[str]) -> List[BaseTool]:
        """タグ一致でツール検索"""
        pass
```

#### 優先度

- **優先度**: 中（混乱を招いているが、機能的に問題なし）
- **着手時期**: Phase E-2移行完了後（1-2ヶ月後）
- **影響範囲**: 広範囲（慎重な移行計画が必要）

#### 成功基準

- [ ] 単一のRegistryで全ツール管理可能
- [ ] 開発者が迷わず正しいRegistryを使用できる
- [ ] 既存コードの変更なしで互換性維持
- [ ] ドキュメントがシンプルになる
