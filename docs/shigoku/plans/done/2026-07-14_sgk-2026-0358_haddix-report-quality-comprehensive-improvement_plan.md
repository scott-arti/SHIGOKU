---
task_id: SGK-2026-0358
doc_type: plan
status: done
parent_task_id: SGK-2026-0347
related_docs:
- docs/shigoku/plans/2026-07-07_haddix-report-bugbounty-quality-optimization_plan.md
- docs/shigoku/plans/2026-07-07_sgk-2026-0346_evidence-enforcement-p2-detection-expansion_plan.md
- workspace/projects/localhost:4280/reports/haddix_report_20260713_234334.md
- src/reporting/haddix_formatter.py
- src/reporting/haddix_submission_internal_formatter.py
- src/reporting/haddix_evidence_quality.py
- src/reporting/initial_release_gate.py
- src/reporting/finding_extractor.py
- src/core/agents/swarm/injection/manager.py
- scripts/check_initial_release_gate.py
- scripts/verify_report_session_consistency.py
created_at: '2026-07-14'
updated_at: '2026-07-21'
tags:
- shigoku
- haddix
- bug-bounty
- evidence-quality
- gate
target: src/reporting/, src/core/agents/swarm/, scripts/, tests/unit/reporting/
---

# 修正計画書：HADDIXレポート品質包括改善 (SGK-2026-0358)

## 0. 背景とスコープ

本計画書は、SHIGOKUのHADDIXレポートに対する第三者指摘事項（25項目）を体系的に改善するための修正計画である。

前身タスク SGK-2026-0347 では提出品質の初期最適化を実施済みであり、本タスクはその残課題および新たに指摘された構造的課題を包括的に解決する。

### 0.1 前提

- **Findings個別修正は完了済み**: 本指示書のうち、個別Finding（C1〜C8相当）に関する修正は既に実施済みである。本計画書では該当箇所を「修正確認」として扱い、修正が適用されていることを検証するのみとする。
- **構造的改善は新規実装**: Evidence型システム、Gate分離、Coverage指標分離、出力構造分離など、システム全体にわたる改善は新規実装として計画する。
- **共通原則の遵守**: 本指示書「2. 実装時の共通原則」に記載された7原則をすべての作業で適用する。

### 0.2 対象レポート

- 最新レポート: `workspace/projects/localhost:4280/reports/haddix_report_20260713_234334.md`
- 整合性チェック・ゲートチェックは実装後に当該レポート（または新規生成レポート）に対して実施する。

### 0.3 Phase一覧

| Phase | 名称 | 対応Section | 主な作業種別 | 優先度 |
|---|---|---|---|---|
| Phase 1 | Evidence基盤と型分離 | §3, §4, §5, §6 | 新規実装 + 修正確認 | P0 |
| Phase 2 | CORS分類とクラステンプレート | §7, §8 | 修正確認 + 新規実装 | P0 |
| Phase 3 | Gate分離と回帰検知 | §9, §10 | 新規実装 | P0 |
| Phase 4 | 脆弱性クラス別成立判定 | §11, §12, §13, §14, §15, §16, §17 | 修正確認 + 新規実装 | P1 |
| Phase 5 | Severity・Coverage・品質指標 | §18, §19, §20, §21, §22 | 新規実装 | P1 |
| Phase 6 | 出力構造と運用性 | §23, §24, §25 | 新規実装 | P2 |

### 0.4 作業種別の定義

- **修正確認**: Finding個別の修正は完了済み。修正がコードベースに適用されていることをテスト・実artifactで検証する。新規ロジックの実装は含まない。
- **新規実装**: システム構造の改善・新機能の実装を行う。設計・実装・テストを含む。
- **修正確認 + 新規実装**: Finding個別の修正確認に加え、再発防止のための構造的改善も実装する。

---

## Phase 1: Evidence基盤と型分離 (P0)

> **対象Section**: §4 実HTTPトランザクション保存 / §5 HTTP/1.1 0とSynthetic Evidence廃止 / §3 提出用Finding再現手順 / §6 Execution NotesとProbe追跡
>
> **目標**: 検出器の推論と実通信を混同しないEvidence基盤を構築する。HTTP/1.1 0を廃止し、Evidence Type別に分離保存する。再現手順のプレースホルダーを排除し、Execution Notesの状態表現を構造化する。

### P1-1. 実HTTPトランザクション保存 (§4) — 新規実装

#### 課題

C1〜C6のCommand Injection候補などで、検出器がペイロードを認識している一方、レポートには通常リクエスト（`GET /vulnerabilities/exec/ HTTP/1.1`）しか保存されていない。PoCを検出器の説明文から再構成してはならない。

#### 実装内容

1. **HTTPクライアントが実際に送信したトランザクションをEvidenceとして保存する**

   保存するRequest情報:
   - method, scheme, host, port, path, query
   - headers, cookies, body, content_type
   - timestamp, payload, payload_parameter, payload_location

   保存するResponse情報:
   - status_code, reason, headers, body
   - elapsed_ms, redirect_history, timestamp, transport_error

   関連情報:
   - evidence_id, finding_id, detector_id, session_id
   - baseline_request_id, attack_request_id, negative_control_request_id, browser_trace_id

2. **payload_location の区別**
   - `path`, `query`, `body`, `header`, `cookie`, `browser_fragment`, `stored_value`

   DOM XSSのURLフラグメントはHTTPサーバーへ送信されないため、ブラウザ遷移URLとBrowser Evidenceで照合する。`payload_request_mismatch`の誤判定を防ぐ。

3. **秘密情報のマスキング**
   - 内部ストレージには生データを保存
   - Markdown出力時にCookie, Authorization, トークン, PIIをマスキング
   - `payload_request_mismatch`が解消されていないFindingは提出用に昇格しない

#### 完了条件

- [ ] PoCに実際に送信したHTTPメソッド、パラメータ、ペイロードが含まれる
- [ ] POST検査ではbodyとContent-Typeを復元できる
- [ ] Query Stringを使用した検査では完全なURLを復元できる
- [ ] DOMフラグメントをHTTPリクエスト欠落として誤判定しない
- [ ] EvidenceとFindingが`evidence_id`で追跡できる
- [ ] 秘密情報が提出用Markdownへ平文出力されない
- [ ] `payload_request_mismatch`が解消されていないFindingは提出用に昇格しない

#### 対象ファイル

- `src/reporting/haddix_evidence_quality.py` — Evidence保存ロジック
- `src/reporting/haddix_formatter.py` — Evidence表示
- `src/core/agents/swarm/injection/manager.py` — Probe送信時のEvidence保存
- `tests/unit/reporting/test_haddix_evidence_quality_gate.py`

### P1-2. HTTP/1.1 0とSynthetic Evidenceの廃止 (§5) — 修正確認 + 新規実装

#### 課題

Evidenceに `HTTP/1.1 0` および検出器の観測文がHTTPレスポンス本文として表示されている。実通信と合成Evidenceの保存・表示が混同されている。

#### 修正確認（Finding個別）

- [ ] 既存のHADDIXレポートで `HTTP/1.1 0` が出力されていないことを確認
- [ ] 検出器の説明文がHTTPレスポンス本文として出力されていないことを確認
- [ ] SGK-2026-0347 の Q-03 修正が適用されていることを確認

#### 新規実装（構造的改善）

1. **Evidence Type の分離**

   | Evidence Type | 用途 |
   |---|---|
   | `real_http_transaction` | 実HTTP通信のRequest/Response |
   | `timing_measurement` | 遅延測定結果 |
   | `browser_execution` | ブラウザ実行検証 |
   | `out_of_band_callback` | OOBコールバック |
   | `detector_observation` | 検出器の内部観測 |
   | `model_inference` | LLM推論結果 |
   | `manual_observation` | 人間による観測 |
   | `transport_error` | 通信エラー |

2. **出力ルール**
   - `detector_observation` と `model_inference` をHTTPコードブロックへ出力しない
   - 実レスポンスが保存されていない場合は明示的に「実HTTPレスポンスは保存されていません」と表示
   - 通信失敗時は存在しないステータスコードを生成せず、`transport_error`へ保存

3. **認証切れ判定の独立**
   - 認証切れは次の独立した根拠でのみ判定:
     - ログインページへのリダイレクト
     - 認証失敗を示すレスポンス
     - 既知の認証済みページ要素の消失
     - セッション検証用エンドポイントの失敗
   - 認証切れ確認時のみ `auth_context_lost` Reason Codeを付与

#### 完了条件

- [ ] レポート内に `HTTP/1.1 0` が存在しない
- [ ] 検出器の説明文がHTTPレスポンスとして出力されない
- [ ] 実通信、時間測定、ブラウザEvidence、推論が別形式で保存される
- [ ] Synthetic EvidenceだけのFindingはCandidateに残る
- [ ] 提出用Findingには最低1件の実リクエストと実レスポンスが存在する（脆弱性クラス上不要な場合を除く）
- [ ] 認証切れと通信Evidence欠落を同じ原因として扱わない

#### 対象ファイル

- `src/reporting/haddix_evidence_quality.py` — Evidence Type分類
- `src/reporting/haddix_formatter.py` — 出力フォーマット
- `src/reporting/haddix_submission_internal_formatter.py` — 提出用/内部用分離
- `tests/unit/reporting/test_haddix_evidence_quality_gate.py`

### P1-3. 提出用Findingの再現手順 (§3) — 修正確認 + 新規実装

#### 課題

提出用Findingの再現手順に「再構成してください」というプレースホルダーが残っている。

#### 修正確認（Finding個別）

- [ ] 既存レポートで「再構成してください」「TODO」「TBD」「manual verification required」が存在しないことを確認
- [ ] 空の再現手順が存在しないことを確認

#### 新規実装（構造的改善）

1. **脆弱性クラス別の再現手順自動生成**

   最低限含める内容:
   - 必要な認証状態
   - 対象URLとHTTPメソッド
   - 攻撃対象パラメータ
   - 実際に使用したペイロード
   - 送信手順
   - 攻撃成立時に確認するレスポンス、時間差、DOMイベントまたは状態変化
   - 成立を判断する具体的な条件

2. **Fail-Closed**
   - 自動生成できない場合は `submission_ready=false` としてCandidateに残す
   - 文章を推測で補完しない

3. **禁止文字列バリデーション**
   - レポート生成前に次を禁止: `再構成してください`, `TODO`, `TBD`, `manual verification required`, 空の再現手順

#### 完了条件

- [ ] 提出用Findingにプレースホルダーが存在しない
- [ ] 記載された手順だけで第三者が再現できる
- [ ] 対象パラメータと実ペイロードが明記される
- [ ] 再現手順を生成できないFindingは提出用に出力されない
- [ ] 禁止文字列を含む提出用レポートの生成テストが失敗する

#### 対象ファイル

- `src/reporting/haddix_formatter.py` — 再現手順生成
- `src/reporting/haddix_submission_internal_formatter.py` — 提出用生成
- `tests/unit/reporting/test_haddix_submission_internal_sections.py`

### P1-4. Execution NotesとProbe追跡 (§6) — 新規実装

#### 課題

Execution Notesで `Tested Params`, `Probe Sent`, `Probe Skip Reason` が多数の行で `-` となっており、何を検査したか追跡できない。

#### 実装内容

1. **値が存在しない理由の明示的区別**

   | 状態 | 意味 |
   |---|---|
   | `not_applicable` | パラメータ不要の検査（CORS等） |
   | `not_discovered` | パラメータが見つからなかった |
   | `skipped` | 意図的にスキップ |
   | `executed` | 実行済み |
   | `instrumentation_missing` | 計測機能不足 |

2. **パラメータ型検査での保存項目**
   - 対象パラメータ
   - Probeの種類
   - マスキング済み実送信値
   - 対応するEvidence ID
   - Skipした場合のReason Code

3. **Coverage判定の改善**
   - パラメータ欄が埋まっているかではなく、モジュールが要求するProbeが実行され、Evidence IDが生成されたかで判断

#### 完了条件

- [ ] `-` だけでは状態を表現しない
- [ ] パラメータ型Probeは送信値とEvidence IDを追跡できる
- [ ] パラメータ不要の検査を未実行扱いしない
- [ ] Probe未送信時は理由が必ず保存される
- [ ] 実行済みと表示された検査に対応Evidenceが存在する

#### 対象ファイル

- `src/reporting/haddix_formatter.py` — Execution Notes生成
- `src/reporting/haddix_evidence_quality.py` — Probe追跡
- `tests/unit/reporting/test_haddix_formatter_kpi.py`

---

## Phase 2: CORS分類とクラステンプレート (P0)

> **対象Section**: §7 CORSの分類、Severity、Impact / §8 Expected Result、修正案、再テスト手順
>
> **目標**: CORS分類を実レスポンスから決定し、ワイルドカードとOrigin反射を区別する。脆弱性クラス別のExpected Result/Remediationテンプレートを構築する。

### P2-1. CORS分類、Severity、Impact (§7) — 修正確認 + 新規実装

#### 修正確認（Finding個別）

- [ ] 既存レポートで `Access-Control-Allow-Origin: *` をOrigin Reflectionとして表示していないことを確認
- [ ] `wildcard_no_credentials` がMedium以上になっていないことを確認
- [ ] SGK-2026-0347 の CORS関連修正が適用されていることを確認

#### 新規実装（構造的改善）

1. **CORS分類体系**

   | 分類 | 条件 |
   |---|---|
   | `wildcard_no_credentials` | `ACAO: *` かつ `ACAC: false` |
   | `wildcard_with_credentials_invalid_combination` | `ACAO: *` かつ `ACAC: true`（仕様違反） |
   | `arbitrary_origin_reflection_no_credentials` | Origin反射、認証情報なし |
   | `arbitrary_origin_reflection_with_credentials` | Origin反射、認証情報あり |
   | `null_origin_allowed` | `Origin: null` を許可 |
   | `trusted_origin_suffix_bypass` | 信頼Originのsuffix bypass |
   | `trusted_origin_prefix_bypass` | 信頼Originのprefix bypass |
   | `origin_parser_bypass` | Origin parserのbypass |
   | `intranet_resource_exposure` | 社内リソースの公開 |

2. **分類は実レスポンスヘッダーから決定**（検出器の説明文から決定しない）

3. **Severity決定前の確認項目**
   1. 読み出せる具体的なデータ
   2. データの機密性
   3. 認証情報の必要性
   4. 攻撃者が同じデータを直接取得できるか
   5. 被害者ブラウザ経由でのみ成立する追加被害
   6. 社内ネットワーク等、攻撃者から直接到達できないリソースか
   7. URLやカスタムヘッダーに別の認証情報が含まれるか

4. **`wildcard_no_credentials` の扱い**
   - 認証不要かつ攻撃者が直接取得できる公開データのみ → Informational または N/A Candidate

5. **Impact記述要件**
   - 攻撃者、被害者、対象データ/操作、攻撃前提、成功時の具体的被害
   - 追加CIA影響を証明できない場合は「追加被害が確認できなかった」と明記

#### 完了条件

- [ ] `Access-Control-Allow-Origin: *` をOrigin Reflectionと表示しない
- [ ] CORSタイプと実レスポンスが一致する
- [ ] `wildcard_no_credentials` だけを根拠にMedium以上へしない
- [ ] SeverityにImpact Evidence IDが紐付く
- [ ] 公開データのクロスオリジン読み出しだけでは提出可能扱いにならない
- [ ] 各CORS分類に単体テストが存在する

#### 対象ファイル

- `src/reporting/haddix_evidence_quality.py` — CORS分類ロジック
- `src/reporting/haddix_formatter.py` — CORS表示
- `tests/unit/reporting/test_haddix_evidence_quality_gate.py`

### P2-2. Expected Result、修正案、再テスト手順 (§8) — 修正確認 + 新規実装

#### 修正確認（Finding個別）

- [ ] CORS Findingに対してCORS無関係の汎用文（入力値検証、出力エンコード等）が出力されていないことを確認
- [ ] 「修正後も同じ脆弱結果になることを確認する」という文章が存在しないことを確認
- [ ] SGK-2026-0347 の Q-09（CSRF remediation修正）が適用されていることを確認

#### 新規実装（構造的改善）

1. **脆弱性クラス別テンプレート管理**

   テンプレート対象クラス:
   - CORS, Command Injection, SQL Injection
   - Reflected XSS, Stored XSS, DOM XSS
   - LFI/Path Traversal, CSRF, Broken Access Control
   - Open Redirect, File Upload, Weak Session ID

   各テンプレートに含める:
   - Expected Result
   - Remediation
   - Negative Test
   - Normal-path Regression Test

2. **CORS の Expected Result**
   - 信頼されていないOriginへCORS許可ヘッダーを返さず、許可済みOriginのみ明示的に許可する内容

3. **修正後確認の統一順序**
   1. 修正前に成立したPoCを同条件で再送する
   2. 脆弱な挙動が再現しないことを確認する
   3. 許可された正常系が引き続き動作することを確認する

#### 完了条件

- [ ] 脆弱性クラスと無関係なExpected Resultが出力されない
- [ ] 「修正後も同じ脆弱結果になることを確認する」という文章が存在しない
- [ ] Negative Testと正常系Regression Testの両方が生成される
- [ ] クラス別テンプレートに単体テストが存在する
- [ ] テンプレート未定義のクラスを汎用文でsubmission_readyにしない

#### 対象ファイル

- `src/reporting/haddix_formatter.py` — テンプレート適用
- `src/reporting/haddix_submission_internal_formatter.py` — 提出用テンプレート
- `tests/unit/reporting/test_haddix_submission_internal_sections.py`

---

## Phase 3: Gate分離と回帰検知 (P0)

> **対象Section**: §9 Initial Release GateのFail-Closed化 / §10 Regression Gateの分離
>
> **目標**: Gateを独立した評価へ分け、Scenario例外が他Gateへ波及しないようにする。Regression GateをCoverage Gateから独立させる。

### P3-1. Initial Release GateのFail-Closed化 (§9) — 新規実装

#### 課題

Confirmed 1件、Candidate 10件であるにもかかわらず、Initial Release GateがPASSしている。`allowed_missing`によるScenario例外が、無関係な件数条件まで無効化している。

#### 実装内容

1. **Gate を5つの独立した評価へ分離**

   | Gate | 評価内容 |
   |---|---|
   | Scenario Coverage Gate | 必須シナリオが実行されたか |
   | Evidence Quality Gate | Confirmedに必要なEvidenceが揃っているか |
   | Finding Policy Gate | Confirmed数、Candidate数、PoC欠落数、Reason Code欠落数 |
   | Regression Gate | ロック済みBaselineから重大な検出低下がないか |
   | Submission Gate | 提出対象Findingが提出品質を満たすか |

2. **最終Release Gate**
   - 必須GateがすべてPASSした場合だけPASS

3. **`allowed_missing` のスコープ制限**
   - 指定されたScenario Coverageにのみ適用
   - Confirmed数、Candidate数、Evidence品質、Regressionを無効化しない

4. **構造化ログ**
   各条件について次を保存:
   - `policy_value`, `actual_value`, `comparison_operator`
   - `individual_result`, `exception_applied`, `exception_scope`, `final_result`

#### 完了条件

- [ ] Confirmed 1 < 3 でFAILになる
- [ ] Candidate 10 > 2 でFAILになる
- [ ] 個別条件が1つでもFAILなら対応するGateはFAILになる
- [ ] Scenario例外が他Gateへ波及しない
- [ ] 境界値の前後について単体テストが存在する
- [ ] Fail理由がレポートと構造化ログの両方に出力される

#### 対象ファイル

- `src/reporting/initial_release_gate.py` — Gate分離ロジック
- `scripts/check_initial_release_gate.py` — CLI
- `tests/unit/reporting/test_initial_release_gate.py`

### P3-2. Regression Gateの分離 (§10) — 新規実装

#### 課題

Baseline Diffが `confirmed_delta=-9` であるにもかかわらず、リリース候補としてPASSしている。

#### 実装内容

1. **Regression Gate をCoverage Gate やScenario例外から独立**

2. **ロック済み検証ターゲットのBaseline**
   - 脆弱性クラス、エンドポイント、期待Evidence単位のBaselineを持つ

3. **比較項目**
   - Confirmed総数
   - 脆弱性クラス別件数
   - 期待Findingの欠落
   - Candidateへの降格理由
   - Evidence取得失敗
   - 実行されなかった検出器
   - 重複統合による見かけ上の件数減少

4. **許容回帰量**
   - 設定可能、ロック済みテスト環境では原則0
   - 例外は明示的override、理由、承認情報を必要とする

#### 完了条件

- [ ] `confirmed_delta=-9` を警告なしでPASSにしない
- [ ] 件数減少の内訳を追跡できる
- [ ] 重複排除による減少と検出失敗を区別できる
- [ ] overrideなしの重大回帰はFAILになる
- [ ] Baseline更新は明示的な操作でのみ行われる

#### 対象ファイル

- `src/reporting/initial_release_gate.py` — Regression Gate分離
- `scripts/check_initial_release_gate.py` — CLI
- `tests/unit/reporting/test_initial_release_gate.py`

---

## Phase 4: 脆弱性クラス別成立判定 (P1)

> **対象Section**: §11〜§17
>
> **目標**: Findings個別修正は完了済みのため、主に修正確認を行う。併せて再発防止のための構造的改善（タイミング基盤、ブラウザ検証基盤、重複排除）を実装する。

### P4-1. タイミングEvidenceの共通基盤 (§11) — 修正確認 + 新規実装

#### 修正確認（Finding個別）

- [ ] Command Injection と Blind SQL Injection のタイミング検知で単発測定のみのConfirmedが存在しないことを確認
- [ ] SGK-2026-0347 の Q-05（Blind SQLi timing）修正が適用されていることを確認

#### 新規実装（構造的改善）

1. **3系列の測定**
   - Baseline
   - Delayを発生させるPositive Probe
   - Delayを発生させないNegative Control

2. **測定要件**
   - 各系列原則3回以上実行、中央値を使用
   - 実行順序は可能な範囲で交互またはランダム化

3. **保存対象**
   - 各試行のelapsed time, 中央値, 最小値, 最大値
   - Baselineとの差, Negative Controlとの差
   - タイムアウト/通信エラー, 各試行の実HTTPトランザクション

4. **Confirmed昇格条件**
   - 実ペイロード入りリクエスト、完了した測定、再現可能な差、Negative Controlとの差
   - タイムアウト/通信失敗を遅延成功として数えない
   - 同じ測定基盤をCommand Injection と SQL Injection から再利用

#### 完了条件

- [ ] 単発遅延だけではConfirmedにならない
- [ ] Baseline、Positive、Negative Controlの3系列が存在する
- [ ] 各系列の複数試行結果を確認できる
- [ ] 通信エラーを遅延として扱わない
- [ ] 実際のペイロード入りトランザクションが保存される
- [ ] 同じ測定基盤をCommand Injection と SQL Injectionから再利用できる

#### 対象ファイル

- `src/core/agents/swarm/injection/manager.py` — タイミング測定
- `src/reporting/haddix_evidence_quality.py` — Evidence検証
- `tests/unit/reporting/test_haddix_evidence_quality_gate.py`

### P4-2. Command InjectionとSSRFの分離 (§12) — 修正確認

#### 修正確認

- [ ] Candidate名が `Command Injection/SSRF` のような複合名でないことを確認
- [ ] Command Injection と SSRF が別クラスとして扱われていることを確認
- [ ] SGK-2026-0347 の Q-13（CMD_SSRF誤分類）修正が適用されていることを確認
- [ ] 実際のPOSTまたはGETリクエストと対象パラメータが保存されていることを確認
- [ ] Command Injection が出力Evidenceまたは統計的時間Evidenceを持つことを確認
- [ ] SSRF EvidenceなしでSSRFをタイトルへ含めていないことを確認
- [ ] Negative Controlでも遅延する場合はConfirmedになっていないことを確認

### P4-3. XSSのブラウザ実行検証 (§13) — 修正確認 + 新規実装

#### 修正確認（Finding個別）

- [ ] 反射だけではXSSをConfirmedにしていないことを確認
- [ ] `runtime execution observed` と `browser_execution_missing` が同時に存在しないことを確認
- [ ] SGK-2026-0347 の Q-04（XSS browser execution）修正が適用されていることを確認

#### 新規実装（構造的改善）

1. **ブラウザ検証Evidenceの共通形式**

   保存項目:
   - page_url, navigation_url, payload
   - execution_token, execution_event, execution_timestamp
   - browser_trace_id, DOM snapshot, console log
   - screenshot（任意）, 使用した認証コンテキスト

2. **実行確認方法**
   - `alert(1)` の目視ではなく、衝突しない一意トークンで確認
   - 例: `window.__shigoku_xss_executed = "<unique-token>"`

3. **XSS種別別の要件**
   - **Reflected XSS**: 反射位置のコンテキスト（HTML/属性/JS）解析後、実ブラウザ実行を確認
   - **DOM XSS**: HTTPリクエストではなくブラウザ遷移URL、フラグメント、DOM変更、実行イベントをEvidenceとする
   - **Stored XSS**: Payload保存リクエスト、再訪問リクエスト、再訪問時ブラウザ実行を別Evidenceとして保存

4. **セッション引き継ぎ**
   - HTTPセッションとブラウザセッションのCookie引き継ぎを検証
   - 認証切れが確認されるまでは不具合原因と断定しない

#### 完了条件

- [ ] 反射だけではXSSをConfirmedにしない
- [ ] 実行トークンがブラウザ内で確認された場合のみConfirmedになる
- [ ] `runtime execution observed` と `browser_execution_missing` が同時に存在しない
- [ ] DetectorとValidatorが同じ `browser_trace_id` を参照する
- [ ] Stored XSSは保存後の再訪問Evidenceを持つ
- [ ] DOMフラグメントをpayload mismatchとして誤判定しない
- [ ] 認証状態が必要なページではブラウザ側の認証コンテキストを検証できる

#### 対象ファイル

- `src/core/agents/swarm/injection/manager.py` — ブラウザ検証
- `src/reporting/haddix_evidence_quality.py` — Evidence検証
- `tests/unit/reporting/test_haddix_evidence_quality_gate.py`

### P4-4. Blind SQL Injection (§14) — 修正確認

#### 修正確認

- [ ] 単発遅延だけでBlind SQL InjectionをConfirmedにしていないことを確認
- [ ] True Conditionだけが再現可能に遅延することを確認
- [ ] False ConditionとBaselineが通常時間へ戻ることを確認
- [ ] ペイロード入り正確なリクエストが保存されていることを確認
- [ ] DBMS名を推測でレポートへ書いていないことを確認
- [ ] SGK-2026-0347 の Q-05 修正が適用されていることを確認

### P4-5. LFI／Path Traversal (§15) — 修正確認

#### 修正確認

- [ ] PoCに実際のTraversal Payloadが含まれることを確認
- [ ] 実レスポンス本文が保存されていることを確認
- [ ] Baselineとの差分が示されていることを確認
- [ ] 対象ファイル固有の内容を複数条件で確認していることを確認
- [ ] PayloadとEvidenceが一致しない場合はCandidateに残っていることを確認
- [ ] SGK-2026-0347 の Q-06（LFI traversal）修正が適用されていることを確認

### P4-6. CSRF (§16) — 修正確認

#### 修正確認

- [ ] TokenlessだけでConfirmedになっていないことを確認
- [ ] Forged Requestが保存されていることを確認
- [ ] Before/After Evidenceが存在することを確認
- [ ] 状態変更が成立した場合だけConfirmedになっていることを確認
- [ ] 復元不能な操作を自動実行していないことを確認
- [ ] 防御により失敗した場合はCandidateまたはInformationalとして理由が保存されていることを確認
- [ ] SGK-2026-0347 の Q-08（CSRF state change）修正が適用されていることを確認

### P4-7. 認証なしAPIアクセスと重複排除 (§17) — 修正確認 + 新規実装

#### 修正確認（Finding個別）

- [ ] 200レスポンスだけでConfirmedになっていないことを確認
- [ ] 公開APIの可能性を検討した記録が残ることを確認
- [ ] 機密情報または権限外操作を具体的に証明できることを確認
- [ ] C7とC8相当の結果が1件へ統合されていることを確認
- [ ] SGK-2026-0347 の Q-07（API access）修正が適用されていることを確認

#### 新規実装（構造的改善）

1. **認証状態の比較**
   - Unauthenticated / Low-privileged / High-privileged user

2. **確認項目**
   - 本来必要な認証・認可条件
   - 各セッションのレスポンス差
   - 取得できる具体的なデータと機密性
   - 権限外の作成、更新、削除操作
   - 対象アプリケーション上の公開仕様
   - `401 → 200`だけを固定条件にしない（ステータス、ボディ、業務状態を総合比較）

3. **重複判定キー**
   - normalized_endpoint, http_method, vulnerability_class
   - affected_parameter, authorization_boundary
   - root_cause_signature, response_signature

4. **複数検出器の同一問題検出時**
   - Findingを増やさずEvidence Sourceとして追加

#### 完了条件

- [ ] 200レスポンスだけではConfirmedにならない
- [ ] 公開APIの可能性を検討した記録が残る
- [ ] 機密情報または権限外操作を具体的に証明できる
- [ ] C7とC8相当の結果が1件へ統合される
- [ ] 複数DetectorのEvidenceが失われない
- [ ] 重複FindingがSeverityや件数へ二重計上されない

#### 対象ファイル

- `src/reporting/haddix_evidence_quality.py` — 重複排除ロジック
- `src/reporting/finding_extractor.py` — Finding正規化
- `tests/unit/reporting/test_haddix_evidence_quality_gate.py`

---

## Phase 5: Severity・Coverage・品質指標 (P1)

> **対象Section**: §18〜§22
>
> **目標**: CandidateのSeverityを未検証/検証済みで分離する。Submission ReadinessとEngine Release Healthを別指標にする。Coverageを5段階に分離し、Shadow Validatorの動作証明を可能にする。

### P5-1. CandidateのSeverity表示 (§18) — 新規実装

#### 実装内容

1. **Severityの2種類分離**
   - `potential_severity`: 脆弱性クラスの最大影響（未検証）
   - `validated_severity`: 攻撃成立Evidenceに基づく確定Severity

2. **Candidate の扱い**
   - 原則として `validated_severity` を確定しない
   - UI/レポート表示は `Potential High` のように未検証であることを明示

3. **Validated Severity の算出基準**
   - 攻撃成立Evidence, 必要権限, ユーザー操作
   - 対象データの機密性, 変更可能なデータ
   - コード実行範囲, 対象アセットの重要性
   - 再現性, スコープ, 具体的なCIA影響

#### 完了条件

- [ ] 未成立Candidateを確定CriticalまたはHighとして表示しない
- [ ] Validated SeverityにImpact Evidence IDが紐付く
- [ ] Evidenceが変わった場合にSeverityが再計算される
- [ ] 脆弱性クラス名だけでSeverityを決定しない
- [ ] CORSなど影響が限定されるケースを過大評価しない

#### 対象ファイル

- `src/reporting/haddix_evidence_quality.py` — Severity算出
- `src/reporting/haddix_formatter.py` — Severity表示
- `tests/unit/reporting/test_haddix_evidence_quality_gate.py`

### P5-2. Submission Readiness Scoreの再設計 (§19) — 新規実装

#### 実装内容

1. **A. Submission Readiness（提出対象Findingのみ評価）**

   各Findingに対する必須Gate:
   - 実Evidenceが存在する
   - ペイロードとリクエストが一致する
   - 再現手順が完成している
   - 攻撃成立条件が確認されている
   - 具体的Impactが確認されている
   - Severityに根拠がある
   - クラス別Expected Resultと修正案が存在する
   - 秘密情報がマスキングされている

   1つでも必須条件を満たさない提出Findingがある場合は `Not Ready`

2. **B. Engine Release Health（エンジン全体の品質）**

   評価項目:
   - Confirmed/Candidate比率, Baseline Diff
   - Evidence取得失敗率, Detector実行率
   - Reason Code網羅率, Long-running率, 重複率

   Submission Readinessへ直接加算しない

#### 完了条件

- [ ] プレースホルダーを含むFindingはReadyにならない
- [ ] Synthetic EvidenceだけのFindingはReadyにならない
- [ ] Submission ReadinessとEngine Release Healthが別表示になる
- [ ] Candidateが多いだけで完成した提出FindingをNot Readyにしない
- [ ] ScoreとReady判定が矛盾しない
- [ ] Ready判定に使用した各条件をレポートで確認できる

#### 対象ファイル

- `src/reporting/haddix_evidence_quality.py` — Readiness評価
- `src/reporting/haddix_formatter.py` — スコア表示
- `tests/unit/reporting/test_haddix_formatter_kpi.py`

### P5-3. Coverage指標の分離 (§20) — 新規実装

#### 実装内容

1. **Coverage の5段階分離**

   | Coverage段階 | 意味 |
   |---|---|
   | `surface_discovered` | 画面、エンドポイント、パラメータを発見 |
   | `detector_executed` | 対応DetectorがProbeを送信 |
   | `evidence_collected` | 実通信またはブラウザEvidenceを保存 |
   | `candidate_generated` | Candidateを生成 |
   | `finding_confirmed` | 成立条件を満たしたFindingが存在 |

2. **Category Evidence / Scenario Backfill の除外**
   - Category EvidenceやScenario BackfillをConfirmed Finding数へ加算しない

3. **表見出しの明記**
   - 各表の見出しに何を数えているかを明記

#### 完了条件

- [ ] 「触れた」「検査した」「Evidenceを得た」「Findingを確定した」を区別できる
- [ ] Finding EvidenceがないFamilyをConfirmed済みのように表示しない
- [ ] Scenario BackfillをConfirmed件数へ含めない
- [ ] 表示件数を元データから再計算するテストが存在する
- [ ] 各Coverage値から対応EvidenceまたはExecution IDへ遡れる

#### 対象ファイル

- `src/reporting/haddix_formatter.py` — Coverage表示
- `src/reporting/haddix_evidence_quality.py` — Coverage計算
- `tests/unit/reporting/test_haddix_formatter_kpi.py`

### P5-4. Scenario Coverageの欠損理由 (§21) — 新規実装

#### 実装内容

1. **未実行Scenarioの表示項目**
   - route
   - missing_reason
   - required_operator_input
   - safe_execution_constraint
   - completion_criteria

2. **`human_preferred` の扱い**
   - Coverage未達を隠す例外ではなく、未実行理由と後続作業を表す分類

3. **出力分離**
   - Submission Reportには内部Scenario情報を出力しない
   - Internal Reportから後続作業を特定できる

#### 完了条件

- [ ] 各未実行Scenarioに具体的な理由が存在する
- [ ] 必要な人間入力が明記される
- [ ] 未実行Scenarioを実行済みとして数えない
- [ ] Submission Reportには内部Scenario情報を出力しない
- [ ] Internal Reportから後続作業を特定できる

#### 対象ファイル

- `src/reporting/haddix_formatter.py` — Scenario表示
- `src/reporting/haddix_submission_internal_formatter.py` — 出力分離
- `tests/unit/reporting/test_haddix_formatter_kpi.py`

### P5-5. Evidence Quality Shadow Verdict (§22) — 新規実装

#### 実装内容

1. **Shadow Validator の記録項目**
   - policy_version, validator_version
   - evaluated_evidence_ids
   - current_verdict, shadow_verdict
   - rule_results, invocation_count, evaluation_error

2. **テストFixture**
   - ConfirmedからCandidateへ降格するケース
   - CandidateからConfirmedへ昇格するケース
   - 現行判定と一致するケース
   - Evidence矛盾でErrorになるケース

3. **判定ルール**
   - C1〜C6が必ず降格するとする期待値は置かない
   - 現行判定とShadow判定が同じなら正しいmatchとして扱う
   - Validatorエラーをmatchとして処理しない

#### 完了条件

- [ ] Shadow Validatorが実際に実行されたことを確認できる
- [ ] 昇格、降格、match、errorのテストが存在する
- [ ] C1〜C6に差分がないことだけで未動作と判定しない
- [ ] Enforcement移行時に使用するpolicy_versionを固定できる
- [ ] Validatorエラーをmatchとして処理しない

#### 対象ファイル

- `src/reporting/haddix_evidence_quality.py` — Shadow Validator
- `tests/unit/reporting/test_haddix_evidence_quality_gate.py`

---

## Phase 6: 出力構造と運用性 (P2)

> **対象Section**: §23 Long-running検査の可視化 / §24 Finding Memo Mapの構造化 / §25 提出用と内部評価用ファイルの分離
>
> **目標**: 長時間検査の可視化、内部メモの構造化、提出用/内部用ファイルの完全分離を実現する。

### P6-1. Long-running検査の可視化 (§23) — 新規実装

#### 実装内容

1. **モジュール別実行時間予算**
   - 設定可能な時間予算をモジュール別に持たせる
   - 固定60秒を全モジュールへ一律適用しない

2. **処理時間の分解**
   - navigation, network_wait, DOM rendering
   - payload execution wait, retry, browser startup, teardown

3. **状態の区別**
   - 時間予算を超えたが完了: `completed_long_running`（警告付き）
   - 期限を超えて中断: `timeout`

#### 完了条件

- [ ] 220秒の処理を通常のcompletedとして無警告にしない
- [ ] 主要フェーズの所要時間を確認できる
- [ ] timeoutとlong-runningを区別できる
- [ ] モジュール別時間予算を設定できる
- [ ] 長時間化したEvidence IDまたはBrowser Traceへ遡れる

#### 対象ファイル

- `src/reporting/haddix_formatter.py` — 実行時間表示
- `src/reporting/haddix_evidence_quality.py` — 時間予算判定
- `tests/unit/reporting/test_haddix_formatter_kpi.py`

### P6-2. Finding Memo Mapの構造化 (§24) — 新規実装

#### 実装内容

1. **構造化JSON形式への移行**

   ```json
   {
     "finding_id": "C1",
     "reason_codes": [
       "payload_request_mismatch",
       "synthetic_response_evidence",
       "command_execution_not_verified"
     ],
     "payload_in_request": false,
     "response_kind": "detector_observation",
     "timing_evidence_id": "ev-...",
     "browser_trace_id": null,
     "detector_observations": [],
     "validation_state": "candidate"
   }
   ```

2. **Markdown表の生成**
   - 構造化データから表示用に生成
   - JSONとMarkdown表示の内容を一致させる

#### 完了条件

- [ ] Reason Codeを配列として取得できる
- [ ] Evidence IDを構造化フィールドとして参照できる
- [ ] 文字列解析をせずにCandidate理由を集計できる
- [ ] JSONとMarkdown表示の内容が一致する
- [ ] 既存セッションデータとの互換性を確認する

#### 対象ファイル

- `src/reporting/haddix_formatter.py` — Memo Map生成
- `src/reporting/haddix_submission_internal_formatter.py` — 内部用JSON出力
- `tests/unit/reporting/test_haddix_formatter_kpi.py`

### P6-3. 提出用と内部評価用ファイルの分離 (§25) — 新規実装

#### 実装内容

1. **出力ファイルの分離**

   | ファイル | 内容 |
   |---|---|
   | `*_submission.md` | 提出可能なFindingのみ |
   | `*_internal.md` | 内部QA、Coverage、Gate、Candidate詳細 |
   | `*_internal.json` | 機械可読データ（Execution, Evidence, Reason Code, Gate結果） |

2. **重複出力の禁止**
   - 同一Findingを1ファイル内で日本語版/英語版として二重出力しない
   - 言語切り替えは設定または別ファイルで扱う

3. **Submission ファイルへの出力禁止項目**
   - Candidate, Scenario Coverage, Internal Gate
   - Shadow Verdict, Finding Memo, Baselineパス
   - 内部コマンド, 第三者指摘対応メモ

#### 完了条件

- [ ] Submissionファイルだけをそのまま提出できる
- [ ] Internal情報がSubmissionファイルに含まれない
- [ ] 同じFindingが1ファイル内で重複しない
- [ ] SubmissionとInternalが同一Finding ID、Evidence IDで対応する
- [ ] 出力分離のスナップショットテストが存在する

#### 対象ファイル

- `src/reporting/haddix_submission_internal_formatter.py` — ファイル分離
- `src/main.py` — CLI生成経路
- `tests/unit/reporting/test_haddix_submission_internal_sections.py`

---

## 共通: 実装順序と依存関係

### 依存関係グラフ

```
Phase 1 (Evidence基盤)
  ├─→ Phase 2 (CORS分類・テンプレート) — Evidence型に依存
  ├─→ Phase 4 (脆弱性クラス判定) — Evidence基盤に依存
  │     └─→ P4-7 重複排除 — Finding構造に依存
  └─→ Phase 3 (Gate分離) — 独立実施可能だがEvidence品質Gateに依存

Phase 5 (Severity・Coverage・品質指標)
  ├─ Phase 3 完了後 — Gate結果を使用
  └─ Phase 4 完了後 — Finding状態を使用

Phase 6 (出力構造)
  └─ Phase 1〜5 完了後 — すべての改善結果を反映
```

### 推奨実装順序

1. **Phase 1**: Evidence基盤と型分離（すべての基盤）
2. **Phase 2**: CORS分類とクラステンプレート
3. **Phase 3**: Gate分離と回帰検知
4. **Phase 4**: 脆弱性クラス別成立判定（修正確認中心）
5. **Phase 5**: Severity・Coverage・品質指標
6. **Phase 6**: 出力構造と運用性

---

## テスト計画

### ユニットテスト

```bash
# Phase 1-2: Evidence基盤・CORS
.venv/bin/pytest -q tests/unit/reporting/test_haddix_evidence_quality_gate.py
.venv/bin/pytest -q tests/unit/reporting/test_haddix_submission_internal_sections.py

# Phase 3: Gate
.venv/bin/pytest -q tests/unit/reporting/test_initial_release_gate.py

# Phase 5-6: KPI・出力構造
.venv/bin/pytest -q tests/unit/reporting/test_haddix_formatter_kpi.py
.venv/bin/pytest -q tests/unit/reporting/test_haddix_ja_en_formatter.py
```

### 実artifact検証

```bash
# 整合性チェック
python3 scripts/verify_report_session_consistency.py \
  --report workspace/projects/localhost:4280/reports/haddix_report_20260713_234334.md

# ゲートチェック
python3 scripts/check_initial_release_gate.py \
  --report workspace/projects/localhost:4280/reports/haddix_report_20260713_234334.md

# shigoku-ops 経由
.venv/bin/shigoku-ops report consistency \
  --report workspace/projects/localhost:4280/reports/haddix_report_20260713_234334.md
```

実装後は新規生成レポートに対して同じchecksを実行する。

### ドキュメント検証

```bash
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

---

## 最終受け入れ条件

本修正の完了は、次のすべてを満たした場合とする。

### P0項目

- [ ] `HTTP/1.1 0` が一切出力されない
- [ ] 検出器の推論が実HTTPレスポンスとして表示されない
- [ ] 提出用Findingに実ペイロード入りPoCが存在する
- [ ] 再現手順にプレースホルダーが存在しない
- [ ] Synthetic EvidenceだけのFindingがConfirmedにならない
- [ ] CORSのワイルドカードとOrigin反射を区別できる
- [ ] Impact未証明のCORSをMedium以上にしない
- [ ] Initial Release Gateが今回の1 Confirmed/10 CandidateをPASSにしない
- [ ] `confirmed_delta=-9` を無警告でPASSにしない

### P1項目

- [ ] XSSはブラウザ実行EvidenceなしでConfirmedにならない
- [ ] Timing系はBaseline、Positive、Negative Controlの複数測定を持つ
- [ ] CSRFは状態変化のBefore/Afterを持つ
- [ ] 認証なし200レスポンスだけでBroken Access ControlをConfirmedにしない
- [ ] 同一Root Causeの重複Findingを統合できる
- [ ] CandidateのPotential SeverityとValidated Severityを区別する
- [ ] Submission ReadinessとEngine Release Healthを別々に評価する

### P2項目

- [ ] Submissionファイルに内部QA情報が混入しない

### 共通項目

- [ ] 既存のReason Code、Evidence、Findingとの互換性または移行処理がテストされる
- [ ] DVWA固有の期待件数を本番判定ロジックへハードコードしない

---

## リスクと対策

| リスク | 影響 | 対策 |
|---|---|---|
| Evidence型追加による既存session schema破壊 | 後方互換性喪失 | additive field追加のみ、schema削除・意味変更禁止 |
| Gate分離で既存PASS caseがFAILになる | CI/運用への影響 | 段階適用、enforcement mode前にshadow modeで検証 |
| ファイル分離で既存`--format haddix`利用者への影響 | 後方互換リスク | 初期実装はopt-in推奨formatを優先、既存formatはwarning/diagnosticから段階適用 |
| ブラウザ/timing/state-change検証がflaky | CI不安定 | timeout/retry上限、dry-run、fixture testとreal artifact checkの分離 |
| redaction漏れ | 秘密情報漏洩 | lowest write/display boundaryでrecursive redaction、深いdict/listのテスト追加 |
| 修正確認で既存修正が不十分だった場合 | 再実装が必要 | 確認結果を記録し、不十分な場合は該当Phaseで新規実装に切り替え |

---

## 関連タスク

- **SGK-2026-0347** (parent): HaddixReport Bug Bounty提出品質最適化計画 — Finding個別修正の前身タスク
- **SGK-2026-0346**: Evidence Enforcement P2 Detection Expansion — 検出範囲拡張
- **SGK-2026-0345**: 親ロードマップ（SGK-2026-0347のparent）

---

## 参考ルールファイル

本タスクの計画にあたり、以下のルールファイルを参考にした:

- `rules/lessons.md` — 再発防止ルール（redaction, auth cache, docs validation）
- `rules/task-ledger.md` — タスク台帳ワークフロー
- `rules/shigoku-docs.md` — ドキュメント規約
- `rules/reporting.md` — レポート/ゲート完了基準
- `rules/report-session-consistency.md` — レポート/セッション整合性ゲート
