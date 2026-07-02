---
task_id: SGK-2026-0239
doc_type: plan
status: done
parent_task_id: SGK-2026-0231
related_docs:
  - docs/shigoku/plans/external_tool_duplication_analysis.md
  - docs/shigoku/reports/2026-05-25_sgk-2026-0239_external-tool-final-migration_work_report.md
  - docs/shigoku/worklogs/2026-05-25_sgk-2026-0239_external-tool-final-migration_work_log.md
  - docs/shigoku/reports/2026-05-26_sgk-2026-0239_async-gau-and-arjun-metrics_work_report.md
  - docs/shigoku/worklogs/2026-05-26_sgk-2026-0239_async-gau-and-arjun-metrics_work_log.md
created_at: '2026-05-22'
updated_at: '2026-07-02'
---

# Phase E: 外部ツール統合移行計画

## 実行済み修正

### 1. 移行準備コメントを追加したファイル

| ファイル | 修正内容 | 優先度 |
|---------|---------|--------|
| `src/core/agents/swarm/scanner/manager.py` | TODO(Phase E)コメント + 新基盤インポート準備 | 高 |
| `src/core/agents/swarm/fuzzing/manager.py` | TODO(Phase E)コメント + 新基盤インポート準備 | 高 |
| `src/core/attack/native_fuzzer.py` | TODO(Phase E)コメント | 中 |

### 2. 重複実装分析ドキュメント

`docs/shigoku/plans/external_tool_duplication_analysis.md` を作成:
- 6ツールの重複実装一覧
- 呼び出し元マッピング
- 統合戦略
- 移行パターン

## Phase E 実装タスク（実績反映）

### Phase E-1: Nuclei, Ffuf, Nmap 統合（優先度: 高）

**新規作成:**
- [x] `src/core/adapters/external/nuclei_adapter.py`
- [x] `src/core/adapters/external/ffuf_adapter.py`
- [x] `src/core/adapters/external/nmap_adapter.py`
- [x] 各Adapterの統合テスト

**修正:**
- [x] `src/tools/scanners/nuclei_wrapper.py` - 非推奨化 + ラッパー化（実施後、削除完了）
- [x] `src/core/tools/ffuf_wrapper.py` - 非推奨化 + ラッパー化（実施後、削除完了）
- [x] `src/tools/scanners/nmap_wrapper.py` - 非推奨化 + ラッパー化（実施後、削除完了）
- [x] `src/core/tools/nuclei_integrator.py` - 機能統合または非推奨化

**移行:**
- [x] `src/core/agents/swarm/scanner/manager.py` - コメント解除 + 実装切替
- [x] `src/core/agents/swarm/fuzzing/manager.py` - コメント解除 + 実装切替

### Phase E-2: Arjun, Gau 統合（優先度: 中）

**新規作成:**
- [x] `src/core/adapters/external/arjun_adapter.py`
- [x] `src/core/adapters/external/gau_adapter.py`

**修正:**
- [x] `src/tools/fuzzing/arjun_wrapper.py` - 参照切替完了後に削除（2026-05-25）
- [x] `src/core/wordlist/gau_integrator.py` - 分析責務維持 + 実行責務を `GauAdapter` へ統合（2026-05-25）

### Phase E-3: 後方互換性維持（優先度: 低）

- [x] `src/tools/custom/__init__.py` - エイリアス維持
- [x] 既存テストの段階的移行（`phase_e2_minimal` へ回帰編入）
- [x] ドキュメント更新（現行運用ドキュメント）

## 重要: 統合時の注意点

### NucleiIngestor は統合対象外

`src/core/knowledge/ingestors/nuclei.py` は **統合対象外**:
- 役割: Nuclei JSON出力 → Knowledge Graph 取り込み
- 新基盤との関係: Adapterが実行 → Ingestorが結果処理（補完関係）
- 修正不要: 継続使用

### 後方互換性維持パターン（履歴）

```python
# Wrapperクラスを当面維持し、内部で新基盤を使用（当時の移行パターン）
class NucleiWrapper:
    """[DEPRECATED] Use NucleiAdapter with ExternalToolExecutor"""
    
    def __init__(self):
        # 新基盤を内部で使用
        self._adapter = NucleiAdapter()
        self._executor = get_global_executor()
    
    async def scan(self, target, ...):
        # 旧インターフェースを維持しつつ、新基盤で実行
        result = await self._executor.execute(
            self._adapter, 
            ToolInput(target=target, ...)
        )
        return self._convert_to_legacy_format(result)
```

> 2026-05-25更新: 上記移行期間は終了し、`nuclei_wrapper.py` / `nmap_wrapper.py` / `ffuf_wrapper.py` は削除済み。

## リスク評価

| リスク | 対策 |
|--------|------|
| 既存テスト破壊 | Wrapper後方互換性で段階的移行 |
| パフォーマンス劣化 | セマフォ制御で逆に改善可能性 |
| セキュリティ設定漏れ | `prohibit_pre_verification_chmod`強制適用 |

## 次のアクション

1. E-3運用レビューで追加Adapter要否を判定
2. 回帰スイートの維持（`phase_e2_minimal`）
3. 将来追加ツールの境界ルールを `ExternalToolProvider` 起点で固定化

## CTOゲート（最終切替時）

- Go条件:
  - `ParamFuzzerSpecialist` から `ArjunWrapper` 参照を除去し、`ExternalToolProvider(arjun_scan)` 経由へ移行
  - `GAUIntegrator` の実行責務を `GauAdapter + ExternalToolExecutor` へ移行
  - 旧実装 `src/tools/fuzzing/arjun_wrapper.py` を削除
- ロールバック方針:
  - 不具合時は `SGK-2026-0239` 変更差分を一括revertし旧経路へ復帰
  - `NativeParamFuzzer` fallback を常時維持し、Arjun失敗時の探索停止を回避
- 責務境界:
  - Swarm層: 実行オーケストレーションのみ
  - Adapter層: 外部ツール実行
  - GAUIntegrator: 分析サマリー生成
- 監視観点:
  - `arjun_scan` status失敗率
  - Native fallback発動率
  - GAU URL取得件数の急減監視

## 追加実装（2026-05-26）

- `GAUIntegrator` を async-only 契約へ変更:
  - `fetch_urls()` を `async def` 化
  - `get_summary_for_ai()` を `async def` 化
  - 同期ブリッジ（スレッド経由実行）を撤去
- `ParamFuzzerSpecialist` に固定分類メトリクスを追加:
  - `arjun_scan_total`
  - `arjun_scan_failure_total.reason.{timeout|validation_error|tool_error|provider_error}`
  - `arjun_scan_empty_success_total`
  - `native_fallback_total`
  - `native_fallback_total.trigger_reason.{arjun_failure|arjun_empty_success|arjun_unavailable}`
- 1リクエスト1加算の二重加算防止を実装（実行コンテキストで一度だけ加算）。

## ステータス判定（2026-05-25）

- 判定: `done`
- 根拠:
  - 残タスク2件（`arjun_wrapper.py`, `gau_integrator.py`）を完了
  - コード切替・旧経路削除・回帰テスト通過を確認
