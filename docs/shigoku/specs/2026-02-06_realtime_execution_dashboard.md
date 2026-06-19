---
task_id: SGK-2026-0077
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-06'
updated_at: '2026-05-19'
---

# リアルタイム実行ダッシュボード仕様書

## 概要

**Target Roadmap**: Phase 5 - リアルタイム実行モニタリング

CLI実行中に以下の情報をリアルタイム（10秒以内の遅延）でターミナルに表示するダッシュボード機能を実装する。

### 表示すべき情報

1. **Reconフェーズ**: 各ステップ（Step 1~8）の開始/終了/結果サマリー
2. **タスク管理**: MasterConductorが生成したタスクと割当判断
3. **攻撃実行**: Swarm/Specialistが実行した攻撃とその結果
4. **LLM状態**: LLMコール状況とエラー（Rate Limit等）
5. **発見物**: 脆弱性発見時の即時通知

---

## 変更ファイル一覧

### [MODIFY] `src/core/infra/event_bus.py`

**変更内容**:

- `EventType` に新しいタイプを追加:
  - `LLM_CALL_START` - LLMコール開始
  - `LLM_CALL_END` - LLMコール終了
  - `LLM_ERROR` - LLMエラー発生
  - `DECISION_MADE` - 意思決定（タスク割当判断等）
  - `RECON_STEP_START` - Reconステップ開始
  - `RECON_STEP_END` - Reconステップ終了
  - `SPECIALIST_EXECUTE` - Specialist実行

---

### [NEW] `src/core/ui/live_dashboard.py`

**変更内容**:

- `LiveDashboard` クラスを新規作成
- Rich `Live` コンポーネントを使用したレイアウト:
  - 上部: 現在実行中のタスク
  - 中部: 最近のアクティビティログ（最大20件）
  - 下部: LLMステータス + エラー表示
- EventBusを購読し、イベント受信時にUIを更新
- スレッドセーフな実装（asyncioとRichの連携）

---

### [MODIFY] `src/core/engine/master_conductor.py`

**変更内容**:

- `_dispatch()` メソッドにイベント発火を追加:
  - タスク開始時: `TASK_STARTED`（既存EventType）
  - タスク完了時: `TASK_COMPLETED`（既存EventType）
  - 割当判断時: `DECISION_MADE`（新規）
- `execute_with_replan()` ループ内でイベント発火

---

### [MODIFY] `src/recon/pipeline.py`

**変更内容**:

- 各 `step*` メソッドの開始/終了時にイベント発火:
  - 開始: `RECON_STEP_START` + ステップ番号/名前
  - 終了: `RECON_STEP_END` + 結果サマリー

---

### [MODIFY] `src/core/agents/swarm/base.py`

**変更内容**:

- `Specialist.execute_with_retry()` にイベント発火を追加:
  - 実行開始: `SPECIALIST_EXECUTE` + specialist名 + target

---

### [MODIFY] `src/core/llm/provider.py` （または該当するLLMプロバイダー）

**変更内容**:

- LLMコール時にイベント発火:
  - 開始: `LLM_CALL_START` + model名
  - 終了: `LLM_CALL_END` + レスポンスサマリー
  - エラー: `LLM_ERROR` + エラー種別

---

### [MODIFY] `src/main.py`

**変更内容**:

- `--live-dashboard` CLIオプションを追加
- オプション有効時、`LiveDashboard` を起動しEventBusに接続

---

### [NEW] `src/core/ui/__init__.py`

**変更内容**:

- 空のinit（パッケージ化用）

---

## 検証計画

### 自動テスト

#### 1. EventBus拡張テスト

**ファイル**: `tests/core/infra/test_event_bus.py`（既存を拡張）

**追加テストケース**:

- `test_new_event_types_exist`: 新規EventTypeが定義されていることを確認
- `test_llm_event_handling`: LLM関連イベントの発行・購読テスト

**実行コマンド**:

```bash
docker compose run --rm shigoku pytest tests/core/infra/test_event_bus.py -v
```

#### 2. LiveDashboard単体テスト

**ファイル**: `tests/core/ui/test_live_dashboard.py`（新規）

**テストケース**:

- `test_dashboard_initialization`: ダッシュボード初期化
- `test_event_subscription`: イベント購読が正しく設定される
- `test_layout_rendering`: Richレイアウトが正しく生成される

**実行コマンド**:

```bash
docker compose run --rm shigoku pytest tests/core/ui/test_live_dashboard.py -v
```

### E2E検証（手動）

#### シナリオ: ライブダッシュボード付き実行

1. 以下のコマンドを実行:

   ```bash
   docker compose run --rm shigoku python3 -m src.main \
     --target http://localhost:4280/ \
     --cookie "PHPSESSID=xxx; security=low" \
     --mode bugbounty \
     --live-dashboard
   ```

2. **確認ポイント**:
   - [ ] ターミナルにダッシュボードUIが表示される
   - [ ] Reconステップ進行がリアルタイムで表示される
   - [ ] タスク割当が表示される
   - [ ] LLMエラー発生時に赤色で警告が表示される
   - [ ] Ctrl+Cで正常終了する

---

## 制約事項

1. **EthicsGuard**: 既存のセキュリティガードに影響を与えない
2. **パフォーマンス**: イベント発火によるオーバーヘッドを最小限に抑える
3. **後方互換性**: `--live-dashboard` オプションなしでは従来通りの動作
