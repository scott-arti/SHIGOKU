---
task_id: SGK-2026-0350
doc_type: plan
status: done
parent_task_id: null
related_docs:
  - src/prompts/conductor/planning.md
  - src/prompts/conductor/planning_bb.md
  - src/prompts/conductor/planning_ctf.md
  - src/prompts/agents/manager_base.md
  - src/prompts/agents/discovery_manager.md
  - src/prompts/agents/auth_manager.md
  - src/prompts/agents/injection_manager.md
  - src/prompts/agents/logic_manager.md
  - src/prompts/roles/specialist_light.md
  - src/prompts/roles/final_judgement.md
  - src/prompts/roles/vuln_validator.md
  - src/prompts/roles/xss_specialist.md
  - src/prompts/roles/sqli_specialist.md
  - src/prompts/roles/lfi_specialist.md
  - src/prompts/roles/cmd_ssrf_specialist.md
  - src/prompts/roles/actor_critic.md
  - src/prompts/roles/attack_suggester.md
  - src/prompts/roles/chain_proposer.md
  - config/shigoku.yaml
created_at: 2026-07-10
updated_at: '2026-07-21'
---

# SGK-2026-0350: System Prompt Optimization

## 1. 背景と目的

### 1.1 問題概要

SHIGOKU の全レイヤー（MasterConductor / Sub-Managers / Workers）のシステムプロンプトを深く検討した結果、以下の問題を特定した:

1. **プレースホルダー実装**: `final_judgement.md` が「Placeholder - to be defined in later phases.」の2行のみ。これは security-critical role（fail-closed）であるにも関わらず、実質的な指示が何もない。
2. **極端に短いプロンプト**: 5つの role プロンプトが4行以下。脆弱性の定義、判定基準、出力スキーマ、エシックス制約のいずれも欠如。
3. **ReAct パースの堅牢性不足**: 全マネージャー/スペシャリストがテキストベースの THOUGHT/ACTION/INPUT フォーマットを AST+正規表現でパースしており、フォーマット崩れでパース失敗が連続し `max_turns`（現在5）到達による silent failure（発見が欠落したまま終了）が発生するリスク。※無限リトライではなく有限ターンでの強制終了である点に注意（`base_manager.py:40,218`）。
4. **言語混在**: 英語プロンプトで日本語出力を要求する箇所があり、モデルの混乱を招く。
5. **出力スキーマの不明確さ**: JSON 出力を要求するロールで、スキーマ定義が曖昧。

### 1.2 目標

1. 全 role プロンプトを具体的な指示と明確な出力スキーマを含む形に拡充する
2. security-critical role（`final_judgement`）のプレースホルダーを実装する
3. ReAct パーサーの堅牢性を考慮したプロンプト設計にする
4. 言語方針を統一する

### 1.3 戦略的重要性（CTO 視点）

SHIGOKU の false positive 率は製品の信頼性と市場競争力に直結する。`final_judgement` の完全実装により自動判定精度を手動検証レベルに近づけることが、本最適化の戦略的目標である。特に競合（Burp Suite, Nuclei+手動検証）が提供していないチェーン攻撃検出との組み合わせで差別化を図る。§6 検証計画では false positive 率の目標値を KPI として設定する。

---

## 2. 現状評価: プロンプト別診断

### 2.1 分類サマリー

| 品質 | プロンプト | 行数 | 問題 |
|---|---|---|---|
| 🔴 **Critical** | `final_judgement.md` | 2 | プレースホルダー。security-critical role が空 |
| 🔴 **Critical** | `specialist_light.md` | 4 | 脆弱性定義・出力スキーマなし。default_role で全ワーカーの基底 |
| 🔴 **Critical** | `vuln_validator.md` | 4 | 検証基準・confidence 計算方法なし |
| 🟡 **Short** | `chain_proposer.md` | 4 | チェーン構築の戦略・制約なし |
| 🟡 **Short** | `attack_suggester.md` | 4 | 提案の優先順位付け・スコープ制約なし |
| ✅ **Good** | `xss_specialist.md` | 37 | THOUGHT/ACTION/INPUT 形式、検出基準明確 |
| ✅ **Good** | `sqli_specialist.md` | 43 | 同上、DBMS 別アプローチあり |
| ✅ **Good** | `lfi_specialist.md` | 35 | 同上、バイパステクニック豊富 |
| ✅ **Good** | `cmd_ssrf_specialist.md` | 37 | JSONアクション、OOB対応 |
| ✅ **Good** | `actor_critic.md` | 26 | WAFバイパスの反復戦略 |
| ✅ **Good** | `planning_bb.md` | 16 | 簡潔、ROI重視 |
| ✅ **Good** | `planning_ctf.md` | 16 | 簡潔、深さ優先 |
| ⚠️ **Improve** | `planning.md` | 56 | JSON形式指定は良いが、戦略ガイダンス不足 |
| ⚠️ **Improve** | `manager_base.md` | 38 | テンプレート変数依存、ReAct不安定 |
| ⚠️ **Improve** | `discovery_manager.md` | 34 | ツール指示は良い、戦略の深さ不足 |
| ⚠️ **Improve** | `auth_manager.md` | 35 | 段階的アプローチは良い、IDOR検出基準不足 |
| ⚠️ **Improve** | `injection_manager.md` | 36 | WAF戦略あり、ディスパッチ基準不明確 |
| ⚠️ **Improve** | `logic_manager.md` | 96 | File Upload手順が冗長すぎる |

---

## 3. 最適化提案

### 3.1 🔴 `final_judgement.md` — 完全再実装 (最優先)

**現状**: `# Placeholder - to be defined in later phases.`

**問題**: この role は `_SECURITY_CRITICAL_ROLES`（`llm_resolver.py:39-41`）に登録されている。ただし fail-closed（`LLMResolutionError`）はロールが config に**未定義**の場合にのみ発火し（`llm_resolver.py:77-81`）、`final_judgement` は config に定義済み（`shigoku.yaml:94-97`）のため fail-closed は**バイパス**されている。結果として、プレースホルダー文字列 `"# Placeholder - to be defined in later phases."` が `_maybe_inject_system_prompt`（`llm.py:300-316`）経由で**実プロンプトとして注入**されている。脆弱性の真/偽判定を担う最も重要な role が、実質的に何の指示も受けていない状態で現行の全スキャンが稼働中である。

**提案内容**:

```
あなたは脆弱性判定の最終審査官です。
与えられた脆弱性候補について、真陽性か偽陽性かを判定してください。

## 判定基準

### True Positive (valid: true) の条件
- 再現可能な証拠（HTTP リクエスト/レスポンス、タイミング差、OOB コールバック）が存在する
- 脆弱性の種類と一致する明確な兆候がある（SQL エラー、XSS リフレクション、認証バイパス成功等）
- スコープ内のターゲットに対する攻撃である

### False Positive (valid: false) の条件
- 証拠が推測やヒューリスティックのみで、実証されていない
- WAF/エラーページの誤検知（例: WAF ブロックを脆弱性と誤認）
- スコープ外または影響がない
- ツールの false positive（nuclei テンプレートの低信頼度マッチ等）

## 出力形式（厳密な JSON）

{
  "valid": true,
  "confidence": 0.0,  // 0.0〜1.0
  "severity": "critical|high|medium|low|info",
  "reasoning": "判定理由（日本語）",
  "evidence": "再現手順と観察された証拠",
  "false_positive_indicators": ["偽陽性の兆候があれば列挙"],
  "remediation": "修正提案"
}

## 重要事項
- confidence が 0.7 未満の場合は valid: false とする（疑わしきは除外）
- 証拠不十分の場合は必ず valid: false とする
- 出力は JSON のみ。マークダウンや説明文は含めない。
```

**使用モデル**: `reasoning_api` (deepseek-v4-pro) — 維持。正しい。

### 3.2 🔴 `specialist_light.md` — 大幅拡充

**現状**: `You are a security analyst. Analyze the input and output JSON only.`

**問題**: `default_role` であり、`general_agent`、`injection agents`、`swarm specialists` の基底として使われる。しかし、何を探し、どう判定し、どう出力するかの指示が一切ない。

**提案内容**:

```
あなたは Web アプリケーションセキュリティの専門アナリストです。
入力されたデータを分析し、セキュリティ上の意味づけを行ってください。

## あなたの役割

ツールの出力、HTTP レスポンス、またはテスト結果を受け取り、
セキュリティ上の発見を特定して構造化してください。
あなた自身は攻撃を実行しません。分析のみを行います。

## 分析すべき内容

1. **脆弱性の兆候**: エラーメッセージ、異常なレスポンス、リーク情報
2. **情報漏洩**: 機密データ、スタックトレース、デバッグ情報、API キー
3. **設定ミス**: セキュリティヘッダー欠損、過剰な権限、デフォルト認証情報
4. **攻撃面**: 入力ポイント、パラメータ、エンドポイント構造

## 判定基準

- 証拠に基づく判定のみを行う。推測で脆弱性を報告しない。
- 確信度が低い場合は明示的に「unknown」と報告する。
- False positive の可能性がある場合はその理由を付記する。

## 出力形式（JSON のみ）

{
  "findings": [
    {
      "type": "vulnerability|info_leak|misconfiguration|attack_surface",
      "subtype": "xss|sqli|ssrf|...",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.0,
      "description": "発見内容の簡潔な説明",
      "evidence": "観察された証拠",
      "location": "URL/パラメータ/ヘッダー"
    }
  ],
  "summary": "全体サマリー",
  "false_positive_risks": ["偽陽性の懸念事項"]
}

findings が空の場合は空配列を返す。マークダウンや JSON 以外の出力はしない。
```

### 3.3 🔴 `vuln_validator.md` — 大幅拡充

**現状**: `Validate vulnerability. Output JSON: {"valid":bool,"confidence":0-1}`

**問題**: `biz_logic_hunter` が使用するが、検証の「方法」が不明確。ビジネスロジック脆弱性は検証が難しく、具体的な手順が必要。

**提案内容**:

```
あなたは脆弱性検証の専門家です。
報告された脆弱性候補が真陽性かどうかを検証してください。

## 検証プロセス

1. **証拠の確認**: 報告に含まれる証拠（HTTP リクエスト/レスポンス、振る舞いの差異）を確認
2. **再現性の評価**: 同じ手順で再現可能か
3. **影響の評価**: 実際のセキュリティ影響（機密性/完全性/可用性）
4. **代替説明の排除**: 別の要因（WAF、キャッシュ、ネットワーク）で説明できないか

## 判定ルール

- valid: true → 証拠が明確で、再現性があり、セキュリティ影響がある
- valid: false → 証拠不十分、再現不可、または偽陽性の要因がある
- confidence → 0.0(確信なし) 〜 1.0(確実)

## 出力形式（JSON のみ）

{
  "valid": true,
  "confidence": 0.85,
  "severity": "high",
  "verified_evidence": "検証によって確認された証拠",
  "reproduction_steps": "再現手順",
  "impact": "機密性/完全性/可用性への影響",
  "false_positive_check": "偽陽性の可能性を検討した結果",
  "notes": "追加コメント（空でも可）"
}
```

### 3.4 🟡 `chain_proposer.md` — 拡充

**現状**: `You are a security chain proposal engine. Output strict JSON only with top-level key 'candidates'. Do not include markdown.`

**提案内容**: チェーン構築の戦略、制約（各ステップが独立して証明可能であること）、最大深度、OWASP/Alex Popov のチェーン分類を参照したガイダンスを追加。

### 3.5 🟡 `attack_suggester.md` — 拡充

**現状**: `You are a security analyst. Suggest additional attack vectors based on the result. Output JSON only.`

**提案内容**: 発見済みの脆弱性からの派生ベクトル、OWASP Top 25/PortSwigger カテゴリ参照、スコープ遵守、優先度付け基準を追加。

### 3.6 ⚠️ `planning.md` — 戦略ガイダンス強化

**現状**: タスクリスト出力形式は良いが、戦略的優先順位付けのガイダンスが薄い。

**改善点**:
- ROI 計算のヒューリスティック追加（露出度 x 影響度 x 実現可能性）
- 既に試行済みのベクトルの回避方法
- エージェント選択の意思決定ツリー
- OWASP カテゴリとエージェントの対応表

### 3.7 ⚠️ `manager_base.md` — ReAct 堅牢化

**現状の問題**:
- テキストベースの Thought/Action/Observation を AST+正規表現パース
- フォーマット崩れでパース失敗が連続し、`max_turns`（5）到達で silent failure（発見欠落のまま終了）。※無限リトライではなく有限ターンでの強制終了（`base_manager.py:40,218`）
- `{{ agent_name }}` や `{{ description }}` が未展開のまま LLM に渡るケース

**改善提案**:

A案（推奨）: JSON 構造化アクション
```
## アクション形式

各ターンで以下の JSON のみを出力してください:

{"thought": "あなたの推論", "action": {"tool": "ツール名", "params": {...}}}

または、終了時:
{"thought": "推論", "final_answer": "発見のサマリー"}
```

B案（最小修正）: 既存テキスト形式を維持しつつ堅牢化
```
CRITICAL FORMAT RULES (VIOLATION = IMMEDIATE RETRY):
1. 各ターンの出力は THOUGHT: で始まり、改行後に ACTION: が続く
2. ACTION: の後に改行して INPUT: を続ける
3. コードブロック、マークダウン、余分な改行は出力しない
```

→ A案が長期的に堅牢だが、パーサー全面書き換えが必要。B案は即効性がある。
→ **段階的移行を推奨**: Phase 1 で B案（フォーマット強制ルール追加）、Phase 2 で A案（JSON化）

### 3.8 ⚠️ 各マネージャープロンプトの個別改善

#### `discovery_manager.md`
- API ディスカバリの優先順位付け基準を追加
- GraphQL イントロスペクションの具体的チェック項目を追加
- robots.txt / .env / .git exposure のチェックを明示

#### `auth_manager.md`
- IDOR の具体的検出パターンを追加（UUID 推測可能性、連番 ID、機能ベースアクセス制御）
- JWT の具体的チェック項目を追加（alg=none, weak secret, kid injection）
- OAuth のリダイレクトURI 検証、state 検証、PKCE 欠損を明示

#### `injection_manager.md`
- パラメータタイプ別の注入可能性マトリクスを追加
- ワーカーディスパッチの明確な意思決定基準を追加（「id=1 → sqli 優先」「q=search → xss 優先」）

#### `logic_manager.md` (96行 → 整理)
- File Upload 手順を別 partial に切り出し（`_partials/file_upload_procedure.md`）
- Mass Assignment / Race Condition のチェックリストを簡潔化
- 96行は長すぎる、60行程度に圧縮

### 3.9 ⚠️ 言語方針の統一

**現状の混在**:
- `manager_base.md`: 英語プロンプト → 日本語出力要求（`<Reasoning ...>` and `<Summary>` in Japanese）
- `specialist` プロンプト群: 純英語
- `planning.md`: 日本語

**提案方針**:
- **プロンプト本文**: 英語統一（LLM は英語プロンプトで最も安定して動作）
- **出力言語**: 役割に応じて指定
  - ユーザー向けサマリー（Final Answer）: 日本語
  - 内部 JSON 出力: 言語指定なし（構造化データ）
  - 判定結果（findings）: 英語（国際的な脆弱性分類との整合）

---

## 4. プロンプト別詳細改善仕様

以下、各ファイルの「現状 → 改善後」の差分仕様を定義する。

### 4.1 最優先（Phase 1）

| ファイル | アクション | 新規行数目安 |
|---|---|---|
| `roles/final_judgement.md` | 完全再実装 | 40〜50行 |
| `roles/specialist_light.md` | 大幅拡充 | **15〜20行**（※default_role で高頻度呼び出しのため短縮。Step 0-5 プロファイリング後に最終決定） |
| `roles/vuln_validator.md` | 大幅拡充 | 35〜45行 |

### 4.2 高優先（Phase 2）

| ファイル | アクション | 新規行数目安 |
|---|---|---|
| `roles/chain_proposer.md` | 拡充 | 25〜35行 |
| `roles/attack_suggester.md` | 拡充 | 25〜35行 |
| `conductor/planning.md` | 戦略ガイダンス追加 | 70〜80行 |
| `agents/manager_base.md` | フォーマット強制ルール追加 (B案) | 45〜55行 |

### 4.3 中優先（Phase 3）

| ファイル | アクション |
|---|---|
| `agents/discovery_manager.md` | API発見チェックリスト追加 |
| `agents/auth_manager.md` | IDOR/JWT/OAuth 具体チェック追加 |
| `agents/injection_manager.md` | ディスパッチ意思決定基準追加 |
| `agents/logic_manager.md` | File Upload partial 切り出し、圧縮 |

### 4.4 将来検討（Phase 4）

| 項目 | 内容 |
|---|---|
| ReAct JSON化 (A案) | 全マネージャー/スペシャリストのアクション形式をJSON構造化に移行 |
| パーシングの堅牢化 | 正規表現パーサー → 構造化パーサー（json.loads + フォールバック） |
| プロンプトバージョニング | 各プロンプトにメタデータ（version, last_updated）を付与し、A/Bテストを可能にする |

---

## 5. 設計原則

全プロンプト改修において以下の原則を遵守する:

### 5.1 構造の一貫性

各 specialist プロンプトは共通構造に従う:

```
1. 役割定義 (1-2行)
2. コマンド定義 (ACTION リスト)
3. フォーマットルール (CRITICAL RULES)
4. 検出/分析ガイドライン
5. 判定基準 (明確な True/False/Unknown 条件)
6. 出力形式テンプレート
```

**プロンプト注入経路に関する制約（A2 対策）**: `roles/*.md` は Jinja2 変数展開を必要としない自己完結型とする。これは `_maybe_inject_system_prompt`（`llm.py:300-316`）が context 変数なしで render するため。変数展開（`{{ agent_name }}` 等）が必要な場合は `agents/` 配下に配置し、`_build_system_prompt` 経由で必ず context 付き render を行うこと。

### 5.2 出力スキーマの明示化

JSON を出力する全 role について、完全な JSON スキーマ（キー名、型、値域）をプロンプト内に含める。

### 5.3 False Positive 防止

各プロンプトに「誤検知の典型例」と「確認すべき追加証拠」を明記する。セキュリティツールの最大の品質リスクは false positive である。

### 5.4 エシックス制約

全プロンプトに以下を暗黙的に含める（partials 経由または直接記述）:
- スコープ外攻撃の禁止
- 破壊的操作の禁止（または慎重な実行）
- 証拠に基づく報告の義務付け

---

## 6. 検証計画

### 6.1 単体テスト

| テスト | 内容 |
|---|---|
| `test_prompt_rendering` | 各プロンプトテンプレートが Jinja2 例外なく render されること |
| `test_final_judgement_output` | `final_judgement` role の出力が期待する JSON スキーマに従うこと |
| `test_specialist_light_output` | `specialist_light` role の出力が `findings` 配列を含むこと |

### 6.2 統合テスト

| テスト | 内容 |
|---|---|
| `test_react_format_parsing` | 改善後のマネージャープロンプトで、LLM 出力がパーサーで正しく解析されること |
| `test_false_positive_rate` | 既知の false positive パターンで、改善後の `final_judgement` が `valid: false` を返すこと |

### 6.3 回帰テスト

- 既存の specialist プロンプト（xss/sqli/lfi/cmd_ssrf）の構造を踏襲していること
- 出力形式の変更が既存のパーサーを壊さないこと

### 6.4 運用メトリクス（多視点レビュー対応）

プロンプト変更前後で以下の指標を計測し、最適化の成否を定量的に判断する:

| メトリクス | 内容 |
|---|---|
| `final_judgement_valid_rate` | final_judgement の valid:true 判定率（改善前後で比較） |
| `specialist_light_findings_count` | specialist_light 使用時の finding 出力数の中央値 |
| `parse_failure_total` | ReAct パース失敗回数（`base_manager._parse_llm_output` で action/final_answer 双方未検出時） |
| `react_turns_to_completion` | マネージャーが正常終了するまでの平均ターン数 |
| `token_usage_per_role` | ロール別の平均入出力トークン消費量 |

### 6.5 LLM-in-the-loop 検証（多視点レビュー対応）

静的テスト（§6.1-6.3）では検証できない、実 LLM 出力の動的検証を行う:

| 検証 | 内容 |
|---|---|
| `final_judgement_dynamic` | 既知の false positive パターン5件を入力し、`valid: false` + `confidence < 0.7` が返ることを確認 |
| `specialist_light_dynamic` | 代表的な入力パターン10件で新スキーマ（`findings[]`）が生成されることを確認。空入力で `findings: []` が返ることも確認 |
| `vuln_validator_dynamic` | ビジネスロジック脆弱性の典型パターンで検証プロセス通りに推論・判定することを確認 |

**KPI（戦略的目標）**: false positive 率を改善前ベースライン（Step 0-4 記録）から目標 **20%以下**に低減することを最適化の成功基準とする。

---

## 7. リスク分析

| リスク | 発生確率 | 影響度 | 対策 |
|---|---|---|---|
| プロンプト長増加でトークンコスト増 | 高 | 中 | specialist_light は頻繁に呼ばれる。Step 0-5 プロファイリング後に15-20行に抑える。長文プロンプトは partial 経由で遅延ロード |
| 出力スキーマ新規定義で下流パーサーが壊れる | 高 | 大 | specialist_light は現状スキーマ未定義のため「拡張」ではなく「新設」。Step 0-3 で下流互換性を確認してから実施 |
| JSON化移行で ReAct ループが壊れる | 中 | 大 | Phase 1 は B案（テキスト形式維持）。A案（JSON化）は別タスクでパーサーと同時に移行。B案ルールに [DEPRECATED] コメント付与 |
| 言語変更で出力品質が変動 | 低 | 小 | 出力言語指定は段階的に変更し、各段階でサンプル出力を比較 |
| パース失敗の連続によるターン浪費→silent failure | 中 | 中 | max_turns 到達前の正常終了を確保するためフォーマット強制（B案）+ observability 強化（Step 2-4） |
| final_judgement プレースホルダー稼働中の既存スキャン信頼性低下 | 高（既に発生中） | 大 | Step 0-4 でベースライン記録、Step 1-1 後に遡及再評価 |

---

## 7.5 多視点レビューによる懸念点と対策

SRE/インフラエンジニア、ソフトウェアアーキテクト、デバッガー、CTO の4視点でレビューを実施し、以下の懸念点と対策を特定した。各対策は §8 の実装ステップにアクションレベルで組み込んでいる（→ Step 番号で参照）。

### 7.5.1 SRE/インフラエンジニア視点

| # | 懸念 | 発生確率 | 影響度 | 対策（→ 実装Step） |
|---|---|---|---|---|
| S1 | プロンプト拡充によるトークン消費の定量評価欠如。specialist_light は default_role で高頻度呼び出し。4行→40-50行は約10倍増。コスト・レイテンシに直結 | 高 | 大 | §4.1 行数目安を見直し（50行→15-20行）。§7 リスク表にコスト定量化を追加。→ Step 0-5 でプロファイリング実施 |
| S2 | プロンプト変更のロールバック戦略欠如。バージョニングは Phase4 先送りで、本番不具合時にロール単位の巻き戻しが不可 | 中 | 大 | config で system_prompt_template を旧バックアップパスに切替可能なフォールバック機構を最小実装。→ Step 0-1 |
| S3 | final_judgement プレースホルダーが現行全スキャンで実プロンプトとして注入中。fail-closed はロール未定義時のみ発火し、config 定義済みのためバイパスされている（§3.1 修正済み）。既存スキャン結果の信頼性に根本的問題 | 高 | 大 | 過去スキャンサンプルの遡及再評価で影響を定量化。→ Step 0-4, Step 1-2 |
| S4 | 効果測定指標が未定義。false positive 率、パース成功率、トークン消費量等のメトリクスなしでは最適化の成否を判断不能 | 中 | 中 | §6.4 運用メトリクスを定義。→ Step 1-6, Step 2-4 で計測組み込み |

### 7.5.2 ソフトウェアアーキテクト視点

| # | 懸念 | 発生確率 | 影響度 | 対策（→ 実装Step） |
|---|---|---|---|---|
| A1 | specialist_light のスキーマ「拡張」が実際は新規定義。現状は出力スキーマ未定義（"JSON only"のみ）。新 findings[] スキーマは下流コンシューマ（general_agent, injection agents, swarm specialists）の出力パーサーと非互換のリスク | 高 | 大 | specialist_light 拡充前に全下流コンシューマを棚卸し。非互換なら Phase2 以降に延期。→ Step 0-3 |
| A2 | 2種類のシステムプロンプト注入経路の設計歪み。(1) `_build_system_prompt`（context変数付き render）、(2) `_maybe_inject_system_prompt`（context変数なし render）。roles と agents で挙動差がありバグの温床 | 中 | 中 | §5.1 に「roles/*.md は変数展開不要な自己完結型とする」原則を追加。→ Step 0-3 で確認 |
| A3 | Phase1 B案（フォーマット強制ルール）が Phase4 A案（JSON化）移行時に残滓となり LLM 挙動を歪めるリスク。段階的移行ゆえの中間状態技術負債 | 中 | 中 | B案ルールに `[DEPRECATED with Phase4 JSON migration]` コメントを付与し削除忘れを防止。→ Step 2-3 |
| A4 | プロンプトとパーサーの密結合。`_parse_llm_output` は "Action: tool(args)" 形式に密結合。フォーマットの多様な逸脱パターンに対するテスト網羅性不足。regex フォールバック経路のテスト未明示 | 高 | 中 | §6.2 にパース逸脱パターンテスト（10種）を追加。regex フォールバックの単体テスト追加。→ Step 1-6 |

### 7.5.3 デバッガー視点

| # | 懸念 | 発生確率 | 影響度 | 対策（→ 実装Step） |
|---|---|---|---|---|
| D1 | 「無限リトライ」の事実誤記。実装は `max_turns=5` で有限（`base_manager.py:40,218`）。実リスクは「ターン浪費→silent failure」。誤記述は対策の焦点を誤らせる | 高 | 中 | §1.1.3, §3.7 の記述を修正済み。対策を「パース成功率向上→max_turns 到達前の正常終了」に集約。→ Step 2-3, Step 2-4 |
| D2 | `_parse_llm_output` の `true/false/null → True/False/None` 置換が文字列値も破壊。例: `{"url": "http://true.example.com"}` → `"True"` に変換（`base_manager.py:373`） | 中 | 小 | AST パース失敗時の置換を JSON 文字列外のみに限定する修正。→ Step 1-5 |
| D3 | 検証計画が静的検証のみ（Jinja2 render, JSON schema）。実 LLM が新プロンプトで期待出力を生成するかの動的検証が欠落。LLM 出力はプロンプトから予測不能な逸脱をする | 高 | 大 | §6.5 LLM-in-the-loop 検証を追加。実 LLM 呼び出しで10件以上のパターンを検証。→ Step 1-7 |
| D4 | パース失敗→silent failure のトレーサビリティ欠如。regex フォールバックでマッチしなくても action=None が返るだけでエラーログ不出力。プロンプト変更後のパース成功率低下を検知する手段が限られる | 中 | 中 | `_parse_llm_output` で action/final_answer 双方未検出時に WARNING ログ + `parse_failure_total` メトリクスインクリメント。→ Step 2-4 |

### 7.5.4 CTO 視点

| # | 懸念 | 発生確率 | 影響度 | 対策（→ 実装Step） |
|---|---|---|---|---|
| C1 | final_judgement プレースホルダー稼働中の全スキャン結果の信頼性問題。過去の脆弱性判定が「指示なしLLM」で行われていた。顧客への報告の信頼性に根本的問題 | 高 | 大 | §1.1 に戦略的重要性を追記。final_judgement 再実装後に過去スキャンの遡及再評価を実施。→ Step 0-4, Step 1-2 |
| C2 | リスク評価の定量性不足。深刻度「高/中/低」のみで確率評価・金銭的/時間的影響の定量化なし。投資判断の根拠が弱い | 中 | 中 | §7 リスク表に発生確率列を追加。影響を「スキャン品質/APIコスト/開発工数」の軸で評価。→ Step 0-2 で再評価 |
| C3 | Phase4 の deferred_tasks が lessons.md CRITICAL ルール違反。「起票予定」は TBD と同等。`tracking_task_id` 未設定 | 中 | 中 | Phase0 で実際の SGK タスク ID を発行し §10 に記載。→ Step 0-2 |
| C4 | プロンプト品質が競合優位性に直結することへの戦略的認識不足。false positive 率は製品信頼性と市場競争力の核心。計画書に「なぜ今必要か」の戦略的文脈が欠落 | 低 | 大 | §1.2 に戦略的重要性を追記。§6 に false positive 率の目標値を KPI として設定。→ Step 1-2 |

---

## 8. 実装順序

多視点レビュー（§7.5）の対策を組み込み、Phase 0〜4 の時系列で実行する。各 Step の「根拠」列は §7.5 の懸念番号（S/A/D/C）に対応する。

### Phase 0: 事前準備（多視点レビュー対応）

| Step | アクション | 根拠 |
|---|---|---|
| **Step 0-1** | プロンプトフォールバック機構の最小実装: config の `system_prompt_template` を旧バックアップパスに切替可能にする仕組み（ロールバック用）。Phase1-3 で不具合発生時にロール単位で巻き戻し可能にする | S2 |
| **Step 0-2** | SGK deferred task 発行: ReAct JSON化・プロンプトバージョニングの追跡タスクを `task_registry.yaml` に新規登録（新規 `SGK-YYYY-NNNN` 採番）。発行した ID を §10 deferred_tasks に記載 | C3 |
| **Step 0-3** | specialist_light 下流コンシューマ棚卸し: `general_agent`, `injection agents`, `swarm specialists` の全サブクラスが specialist_light 出力をパースしている箇所を特定。新 `findings[]` スキーマとの互換性を確認。**非互換の場合は specialist_light 拡充を Phase2 以降に延期する** | A1, A2 |
| **Step 0-4** | final_judgement プレースホルダー稼働中の影響調査: 過去スキャンの代表的サンプルを抽出し、現プレースホルダーでの判定結果（valid 率・confidence 分布）を記録。改善前ベースラインとして使用 | S3, C1 |
| **Step 0-5** | トークン消費プロファイリング: specialist_light 現行（4行）での1スキャンあたりの平均呼び出し回数・トークン消費量を計測。40-50行拡充時のコスト増分を試算し、15-20行で十分かを判断 | S1 |

### Phase 1: Critical 修正（最優先）

| Step | アクション | 根拠 |
|---|---|---|
| **Step 1-1** | `final_judgement.md` 完全再実装（§3.1 仕様、40〜50行） | — |
| **Step 1-2** | 過去スキャンサンプルの遡及再評価: Step 0-4 のベースラインと Step 1-1 後の判定結果を比較し、false positive 率の変化を定量化。§6.5 `final_judgement_dynamic` 検証を併せて実施 | S3, C1, D3 |
| **Step 1-3** | `specialist_light.md` 大幅拡充（§3.2 仕様）。**Step 0-3 の棚卸し結果が互換性OKの場合のみ実施**。行数目安は §4.1 を修正し 15〜20行に圧縮（Step 0-5 プロファイリングで許容範囲確認後） | S1, A1 |
| **Step 1-4** | `vuln_validator.md` 大幅拡充（§3.3 仕様、35〜45行） | — |
| **Step 1-5** | `_parse_llm_output` の true/false/null 置換バグ修正: `base_manager.py:373` の無差別置換を JSON 文字列値外のみに限定。単体テスト `test_parse_action_string_value_preservation` を追加 | D2 |
| **Step 1-6** | プロンプトレンダリングテスト + JSONスキーマテスト実行（§6.1-6.2 全項目）。§6.2 新規項目のパース逸脱パターン10種（インデントずれ・コードブロック囲み・小文字bool等）と regex フォールバック経路テストを含む | A4 |
| **Step 1-7** | LLM-in-the-loop 検証（§6.5）: `final_judgement`, `specialist_light`, `vuln_validator` 各ロールについて実 LLM 呼び出しで動的検証。期待スキーマ適合・空入力処理・false positive 抑制を確認 | D3 |

### Phase 2: High 改善

| Step | アクション | 根拠 |
|---|---|---|
| **Step 2-1** | `chain_proposer.md` / `attack_suggester.md` 拡充（§3.4, §3.5） | — |
| **Step 2-2** | `planning.md` 戦略ガイダンス追加（§3.6） | — |
| **Step 2-3** | `manager_base.md` フォーマット強制ルール追加（B案、§3.7）。各ルールの先頭に `# [DEPRECATED with Phase4 JSON migration]` コメントを付与し、Phase4 移行時の削除忘れを防止 | A3 |
| **Step 2-4** | パース失敗時 observability 強化: `_parse_llm_output`（`base_manager.py`）で action/final_answer 双方未検出時に WARNING ログ（LLM出力全文）出力 + `parse_failure_total` メトリクスインクリメント。§6.4 の運用メトリクス計測を開始 | D4, S4 |

### Phase 3: Medium 改善

| Step | アクション | 根拠 |
|---|---|---|
| **Step 3-1** | 各マネージャープロンプトの個別改善（discovery/auth/injection/logic、§3.8） | — |
| **Step 3-2** | `logic_manager.md` の partial 切り出しと圧縮（§3.8） | — |

### Phase 4: 将来検討（別タスク: Step 0-2 で発行した SGK ID）

| Step | アクション | 根拠 |
|---|---|---|
| **Step 4-1** | ReAct JSON化（A案）+ パーサー全面書き換え。Phase1-3 の B案ルール（Step 2-3 の `[DEPRECATED]` コメント箇所）を削除 | A3 |
| **Step 4-2** | プロンプトバージョニングシステム（§4.4） | — |

---

## 9. 関連ルール・教訓

- **AGENTS.md ルール18**: role と system prompt template の対応は `config/shigoku.yaml` で管理
- **rules/codingrules.md**: "Make the behavior correct first" — プロンプト変更も動作確認を優先
- **lessons.md 行34**: Role-based config の原則（本計画はプロンプト内容の改善であり、モデル割当ては SGK-2026-0349 で扱う）

---

## 10. deferred_tasks

> Phase 0 Step 0-2 完了。実際の SGK タスク ID を発行済み。

| 項目 | 追跡先 |
|---|---|
| ReAct JSON化（A案）+ パーサー全面書き換え | **SGK-2026-0354** |
| プロンプトバージョニングシステム | **SGK-2026-0355** |
