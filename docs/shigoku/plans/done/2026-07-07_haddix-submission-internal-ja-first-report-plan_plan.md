---
task_id: SGK-2026-0345
doc_type: plan
status: done
parent_task_id: SGK-2026-0301
related_docs:
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0301_haddix-ja-en-paired-report_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/reports/2026-07-07_sgk-2026-0345_haddix-submission-internal-ja-first-report_work_report.md
- docs/shigoku/worklogs/2026-07-07_sgk-2026-0345_haddix-submission-internal-ja-first-report_work_log.md
- workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_004743.md
- workspace/projects/127.0.0.1:4280/sessions/session_20260707_004741.json
- src/reporting/haddix_formatter.py
- src/reporting/haddix_ja_en_formatter.py
- src/reporting/haddix_submission_internal_formatter.py
- src/reporting/haddix_evidence_quality.py
- tests/unit/reporting/test_haddix_formatter_kpi.py
- tests/unit/reporting/test_haddix_ja_en_formatter.py
- tests/unit/reporting/test_haddix_submission_internal_sections.py
- tests/unit/reporting/test_haddix_evidence_quality_gate.py
title: Haddix提出用/内部用レポート分離と日本語先行順序の修正計画
created_at: '2026-07-07'
updated_at: '2026-07-21'
tags:
- shigoku
- haddix
- reporting
target: src/reporting/haddix_formatter.py, src/reporting/haddix_ja_en_formatter.py
---

# 実装計画書: Haddix提出用/内部用レポート分離と日本語先行順序の修正計画

## 0. 入力確認と前提

- 対象レポート: `workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_004743.md`
- primary source of truth: 上記レポートと、整合性チェッカーが解決した `workspace/projects/127.0.0.1:4280/sessions/session_20260707_004741.json`
- 実行した整合性チェック:
  - `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_004743.md`
  - 結果: `status=consistent`, `rerun_required=false`, `reason_codes=[]`
  - coverage: report/session とも `9/12`, missing は `scn_08_oob_external_channel_flow`, `scn_10_semantic_business_logic`, `scn_12_advanced_ssrf_internal_topology`
- 本計画は、第三者評価コメントとユーザー追加要望2点を実装可能な修正計画へ落とし込む。
- 本計画では、report-only backfill と raw session evidence を混同しない。提出用 evidence は raw request/response またはブラウザ/状態変化などの再現可能な証拠に限定する。

## 1. 目的

SHIGOKU の Haddix レポートを、内部QA/運用評価ログではなく、第三者がそのまま再現できる Bug Bounty 提出用レポートとして成立する構造にする。

同時に、ユーザーが必要としている内部評価情報は削除せず、レポート後半の「内部評価（私用）」へ隔離する。レポート本文の言語順は、現状または過去設計の「英語提出 -> 日本語補助」ではなく、「日本語 -> 英語」に統一する。

## 2. 主要問題の整理

| ID | 問題 | 対象/根拠 | 修正方針 |
|----|------|-----------|----------|
| P-01 | 提出用本文と内部評価が混在している | 現行レポート冒頭に `Injection Execution Notes`, `Scenario Coverage`, `Initial Release Gate`, `Submission Readiness` が並ぶ | レポートを前半 `# 提出用レポート / Submission Report`、後半 `# 内部評価（私用） / Internal Review Notes` に分割する |
| P-02 | `PoC Request Captured: yes` なのに raw HTTP request に攻撃ペイロードが入っていない | XSS は payload `"><script>alert(1)</script>` だが request は `GET .../xss_r/ HTTP/1.1` のみ。LFI も payload と request URL が不一致 | request artifact に method/path/query/body/header/cookie を含め、payload が実際に入った raw request だけを captured=yes とする |
| P-03 | `HTTP/1.1 0` が提出用 evidence に出ている | report 内の複数 finding の response evidence | 内部表現は提出用に出さず、実レスポンス status/header/body excerpt または synthetic evidence と明示して内部評価側へ移す |
| P-04 | confirmed 昇格条件が緩い | request/response が空でないだけだと成立し、payload入り request・差分・状態変化・ブラウザ実行が保証されない | confirmed gate を evidence quality matrix に変更し、種類別の必須証拠を満たさない finding は candidate へ降格する |
| P-05 | XSS/Stored XSS/CSRF/API access などで提出に必要な影響証拠が不足している | 第三者コメントで再現性・影響・補助証拠不足が指摘された | vulnerability-specific PoC generator/validator を導入し、ブラウザ実行、保存後再表示、状態変化、認可差分などを必須化する |
| P-06 | Severity が過大評価になりやすい | XSS 全部 High、API 200->200 を High、CSRF tokenless を confirmed など | evidence と impact に基づく severity normalization を追加し、内部DVWA学習評価と提出用severityを分ける |
| P-07 | 英語と日本語の順序・正本がユーザー要望と逆 | `src/reporting/haddix_ja_en_formatter.py` は英語提出を正本としている | 出力順と責務を「日本語提出文 -> English Submission Text」に変更し、同一 canonical fields から両言語を生成する |

## 3. ユーザー要望の受け入れ仕様

### 3.1 見出し分離

レポート全体の最上位構造を次の順に固定する。

```markdown
# 提出用レポート / Submission Report

## コピー範囲 / Copy Scope
この見出しから `# 内部評価（私用） / Internal Review Notes` の直前までが提出用です。

## 日本語サマリー
## English Summary
## 提出用 Finding / Submission Findings

# 内部評価（私用） / Internal Review Notes

## 実行ログ / Execution Notes
## Scenario Coverage
## Initial Release Gate
## Submission Readiness Diagnostics
## 候補・保留項目 / Non-Submission Candidates
## 第三者指摘対応メモ
```

提出時にユーザーがコピーする範囲は、前半の `# 提出用レポート / Submission Report` から `# 内部評価（私用） / Internal Review Notes` の直前までとする。

### 3.2 内部評価の扱い

- 内部評価、gate、coverage、baseline diff、auto actions、deferred scenario backlog、candidate reason-code、timeout KPI は削除しない。
- ただし各 finding の提出本文には混ぜない。
- finding ごとの内部コメントが必要な場合は、内部評価側に `Finding ID -> 内部メモ` の対応表として残す。

### 3.3 言語順

- レポート全体は日本語 -> 英語の順にする。
- 各 confirmed finding も `#### 日本語` -> `#### English` の順にする。
- 日本語と英語は同じ canonical finding fields から生成し、片方にだけ新事実を追加しない。

## 4. 第三者指摘トレース表

| ID | 指摘 | 実装対応 | 完了条件 |
|----|------|----------|----------|
| R-01 | 内部QAレポートとしては良いが、Bug Bounty提出用には弱い | 提出用セクションを first-class output とし、内部QA指標は後半へ隔離する | copy scope 内に gate/coverage/KPI/candidate が出ない |
| R-02 | PoC raw request に攻撃ペイロードが入っていない | `_format_finding()` の raw request 表示前に payload presence validator を通す | payload evidence と raw request の URL/query/body/header のどこかに同一またはURLエンコード済み payload が存在する |
| R-03 | `HTTP/1.1 0` は実HTTPレスポンスではない | response artifact を `real_http`, `browser_evidence`, `synthetic_detector_note` に分類する | 提出用 `PoC Response` に `HTTP/1.1 0` が出ない |
| R-04 | Blind SQLi は単発 `SLEEP(3)` だけでは弱い | baseline 3回、sleep 3回、逆条件1回の timing evidence を plan/validator に入れる | confirmed blind SQLi は timing sample table と delta 判定を持つ |
| R-05 | Reflected XSS は反射だけでなくブラウザ実行証拠が必要 | Playwright 等で alert/dialog/DOM mutation の実行 evidence を取る | confirmed reflected XSS は browser execution evidence を持つ |
| R-06 | Stored XSS は投稿後、別リクエスト/別セッション/再表示での実行証拠が必要 | stored validator を posting step と revisit step に分割する | confirmed stored XSS は save request と revisit execution evidence を持つ |
| R-07 | SQLi の通常版はレスポンス差分・SQLエラー・抽出結果などが不足 | boolean/error/union/data-diff evidence を分類して必須化する | confirmed SQLi は control request と attack request の差分を持つ |
| R-08 | LFI は payload が実URLに出ていない | request artifact の URL/query に traversal payload を含める | confirmed LFI は payload入り URL と `/etc/passwd` 等の短い response excerpt を持つ |
| R-09 | API unauth access は 200->200 だけでは High/confirmed が弱い | unauth/auth differential と機密フィールド確認を必須化する | confirmed API exposure は未認証比較、認可期待、機密データ根拠を持つ |
| R-10 | CSRF は tokenless と成立確認が別物 | forged HTML/request と状態変化後確認を必須化する | confirmed CSRF は before/after state evidence を持つ |
| R-11 | CSRF remediation が CORS 寄りでズレている | CSRF 用 remediation を token, SameSite, re-auth, origin/referrer validation へ差し替える | CSRF finding の remediation に CORS 単独提案が出ない |
| R-12 | Command Injection, DOM XSS, Open Redirect, Weak Session IDs の取りこぼしがある | 検出拡張は本計画の P2 とし、まず evidence quality を優先する | P1完了後に coverage backlog として内部評価側へ記録される |
| R-13 | Severity が過大評価 | 提出用 severity normalization を追加する | reflected XSS/API/CSRF が impact evidence なしに High へ固定されない |
| R-14 | Coverage Gate や Baseline Diff は提出本文では前面に出しすぎ | 内部評価側へ移す | 提出用 copy scope に Coverage Gate/Baseline Diff が出ない |

## 5. 対象コンポーネント

### 5.1 `src/reporting/haddix_formatter.py`

- `format_markdown()` は現状、header 直後に execution notes, scenario coverage, gate, summary, findings, submission readiness を単一ストリームで出す。
- `_format_finding()` は現状、標準 evidence table、raw request、response evidence、payloads、impact、remediation を一体で出す。
- `_format_standardized_evidence_template()` は `PoC Request Captured` / `PoC Response Captured` を空文字判定だけで出す。
- `_split_findings_by_confirmation()` は request/response が空でないことを confirmed 条件にしているため、payload presence や real HTTP response の品質を追加判定する。

### 5.2 `src/reporting/haddix_ja_en_formatter.py`

- 現状の docstring と構造は「Japanese summary -> English submission」で、English を authoritative としている。
- `_format_japanese_section()` は実行ログサマリーも日本語側へ含めている。
- `_format_english_section()` は Scenario Coverage と Gate を英語提出側へ含めている。
- `format_markdown()` は日本語サマリーを先にしつつ、提出用の正本は英語側という設計のため、本計画の「日本語提出 -> 英語提出 -> 内部評価」と責務が一致しない。

### 5.3 テスト

- 既存: `tests/unit/reporting/test_haddix_formatter_kpi.py`
- 既存: `tests/unit/reporting/test_haddix_ja_en_formatter.py`
- 追加候補: `tests/unit/reporting/test_haddix_submission_internal_sections.py`
- 追加候補: `tests/unit/reporting/test_haddix_evidence_quality_gate.py`

## 6. 出力仕様

### 6.1 提出用 finding テンプレート

各 finding は次の順に寄せる。

```markdown
### 1. [MEDIUM] Reflected XSS in `name` on `/vulnerabilities/xss_r/`

#### 日本語
- 影響:
- 影響を受けるエンドポイント:
- 再現手順:
- PoCリクエスト:
- 証拠:
- 期待される結果:
- 実際の結果:
- 修正案:
- 修正後の確認:

#### English
- Impact:
- Affected endpoint:
- Steps to reproduce:
- PoC request:
- Evidence:
- Expected result:
- Actual result:
- Remediation:
- Verification after fix:
```

### 6.2 提出用に含めるもの

- confirmed findings のみ。
- 攻撃ペイロード入り raw HTTP request。
- 実HTTP response excerpt、ブラウザ実行 evidence、または状態変化 evidence。
- control request / attack request の差分。
- endpoint、parameter、payload、impact、remediation、verification。
- severity は提出用 normalized severity。

### 6.3 内部評価に移すもの

- Injection Execution Notes と KPI。
- Scenario Coverage と missing scenarios。
- Vulnerability Family Coverage Gate。
- Initial Release Gate、policy、reason codes、baseline diff、auto actions。
- Deferred Scenario Backlog。
- Submission Readiness Diagnostics。
- Candidate / manual verification / insufficient_validation。
- backfill 由来の coverage/family evidence。
- 第三者指摘対応表と、提出前チェックリスト。

## 7. Evidence Quality Gate 設計

### 7.1 共通必須条件

confirmed finding は、少なくとも次を満たす。

- raw request に攻撃 payload または検証対象 parameter mutation が含まれる。
- raw response または代替 evidence が実観測である。
- `HTTP/1.1 0` などの内部表現は提出用 response として扱わない。
- control と attack の差分、または vuln-specific proof がある。
- endpoint、method、parameter、payload、cookie/security context が再現可能な粒度で出る。

### 7.2 種別ごとの confirmed 条件

| 種別 | confirmed 必須証拠 | 不足時の扱い |
|------|--------------------|--------------|
| Blind SQLi | baseline timing 3回、sleep timing 3回、逆条件1回、delta 判定 | candidate `insufficient_timing_validation` |
| Error/Boolean SQLi | control/attack response 差分、SQL error または boolean/data difference | candidate `insufficient_response_difference` |
| Reflected XSS | payload入り URL/request、response reflection、Playwright dialog/DOM execution | candidate `browser_execution_missing` |
| Stored XSS | save request、revisit request、別セッションまたは再表示での browser execution | candidate `stored_revisit_missing` |
| LFI | traversal payload入り URL、file marker excerpt、control page comparison | candidate `payload_request_mismatch` |
| CSRF | forged request/html、before/after state、victim session context | candidate `state_change_not_verified` |
| API exposure/AuthZ | unauth/auth or userA/userB differential、sensitive fields、expected authorization boundary | candidate `authz_impact_not_proven` |
| Command Injection | command output evidence または timing fallback と control | candidate `command_execution_not_verified` |
| Open Redirect | external URL payload、Location header or navigation evidence | candidate `redirect_target_not_external` |
| Weak Session IDs | sample set、entropy/predictability evidence、control notes | candidate `weak_session_not_statistically_verified` |

## 8. 実装ステップ

1. 呼び出し経路と出力モード境界を確定する。
   - `rg` で `HaddixFormatter`, `HaddixJaEnFormatter`, `generate_haddix_ja_en_report`, `--format haddix` の呼び出し元を確認する。
   - 既定 `haddix` を変更すると既存運用に影響するため、初期実装は opt-in format/option を優先する。
   - 新 format/option の format名、既定値、互換維持方針、help表示、生成ファイル名規則を仕様として固定する。
   - P0 は提出用/内部評価分離と日本語->英語順のみを完了条件とし、P1 evidence enforcement と P2 検出拡張を混ぜない。

2. evidence schema と redaction 境界を設計する。
   - 新 evidence field は additive な TypedDict/dataclass または既存 project-standard schema で定義し、既存 field の削除/意味変更は行わない。
   - `rg` で report/session reader を確認し、schema 追加が checker/gate/extractor を壊さないことを実装前に列挙する。
   - Cookie, Authorization, PHPSESSID, security値、token、secret-like 値は最低書き込み層で recursive redaction する。
   - raw request/response は redacted copy と internal raw reference を分け、提出用 report には redacted evidence のみ出す。

3. テストを先に追加する。
   - `# 提出用レポート / Submission Report` が先頭にある。
   - `# 内部評価（私用） / Internal Review Notes` より前に execution notes, scenario coverage, gate, candidate appendix が出ない。
   - 各 finding で `#### 日本語` が `#### English` より前にある。
   - candidate が提出用 copy scope に出ない。
   - payload evidence が raw request に含まれない場合は confirmed にならない。
   - `HTTP/1.1 0` が提出用 response evidence に出ない。
   - `**Generated:**` と `**Source Session:**` は consistency checker が読める形式で残る。
   - redaction 済み evidence に secret/cookie/token が残らない。
   - generated report artifact と CLI message key を検証し、戻り値の仮定に依存しない。

4. レポートビルダーを分離する。
   - submission builder: confirmed finding と提出用 summary のみ。
   - internal builder: execution notes, coverage, gate, diagnostics, candidate, third-party memo。
   - 既存の normalized finding fields は共有し、表示先だけを分ける。
   - `HaddixFormatter` と `HaddixJaEnFormatter` の重複を増やさず、共通 section builder/helper に提出用/内部用の構造責務を寄せる。
   - formatter は表示に専念し、evidence 判定・severity 判定は独立 helper の verdict を受け取る。

5. Evidence quality validator を shadow mode で追加する。
   - raw request payload presence。
   - real response vs synthetic detector note 分類。
   - control/attack differential。
   - vuln-specific confirmed matrix。
   - 不足理由を reason code として candidate に残す。
   - 初期実装では既存 confirmed/candidate 結果を即時強制変更せず、shadow verdict と差分を内部評価側に出す。
   - shadow mode の差分が確認できた後に enforcement mode へ切り替える受け入れ条件を定義する。
   - `HTTP/1.1 0` や synthetic detector note は提出用 response evidence から除外し、内部評価で synthetic と明示する。

6. PoC artifact 生成を安全に改善する。
   - URL/query/body/header/cookie を含む raw request を保存する。
   - response は status/header/body excerpt を保存する。
   - browser/state-change/differential evidence は構造化 field として保存する。
   - request/response が report-time に合成された場合は、内部評価で synthetic と明示する。
   - 実 artifact 再生成は新 timestamp report に出力し、元 report は primary source として上書きしない。
   - browser/timing/state-change 検証には timeout、retry上限、並列数上限、dry-run を設ける。
   - flaky または timeout の evidence は confirmed に昇格せず、candidate として内部評価に理由を残す。

7. vulnerability-specific 出力と成立条件を整える。
   - SQLi: boolean/error/time を分けて evidence を出す。
   - XSS: reflected/stored/DOM を分け、browser execution を出す。
   - CSRF: forged HTML と before/after state を出し、remediation を CSRF 用へ修正する。
   - LFI: payload入り URL と file marker excerpt を出す。
   - API/AuthZ: unauth/auth differential と sensitive fields を出す。
   - Command Injection/Open Redirect/Weak Session IDs は P2 backlog として内部評価に残す。
   - payload presence は必要条件に留め、sink到達、response reflection、DOM execution、state delta、authz differential などの成立証拠を種別ごとに必須化する。
   - CSRF は victim browser context、SameSite/cross-site条件、Cookie送信有無、before/after state を evidence に含める。
   - Stored XSS は投稿セッションと閲覧セッションを分離し、保存後の別 request/別セッション再表示での実行 evidence を記録する。

8. severity normalization を追加する。
   - DVWA学習環境の検出評価 severity と、提出用 severity を分ける。
   - Reflected XSS は原則 Medium から開始し、実影響で昇格する。
   - Stored XSS、CSRF、API exposure は閲覧者範囲、操作重要度、機密データで調整する。
   - severity decision table を `vuln type`, `execution context`, `affected role`, `data sensitivity`, `exploit preconditions` で定義する。
   - 内部検出精度スコアと提出準備度スコアを分け、confirmed 降格を品質改善として内部評価に説明する。

9. CLI/ops 経路へ接続する。
   - `shigoku-ops` / `scripts/shigoku_ops_cli.py` の report consistency 導線は壊さない。
   - 新 format/option を追加する場合は help と unit test を追加する。
   - 提出先が英語のみを要求する場合に備え、日本語+英語 copy scope と英語のみ抽出版の生成方針を help/documentation に明記する。
   - 新しい public behavior は CLI test と docs/manual の更新を同時に行う。

10. 実 artifact で確認する。
   - 対象 report/session pair で consistency checker を再実行する。
   - gate script が必要な行を読めることを確認する。
   - copy scope を目視確認し、内部評価や candidate が混入していないことを確認する。
   - shadow verdict と enforcement verdict の差分を内部評価側で確認する。
   - redacted report に cookie/token/secret-like 値が出ていないことを fixture と実 artifact の両方で確認する。
   - P2 の Command Injection, DOM XSS, Open Redirect, Weak Session IDs は本タスクで実装せず、内部評価側の backlog として残す。

## 9. 検証計画

### 9.1 targeted unit tests

```bash
.venv/bin/pytest -q tests/unit/reporting/test_haddix_formatter_kpi.py
.venv/bin/pytest -q tests/unit/reporting/test_haddix_ja_en_formatter.py
.venv/bin/pytest -q tests/unit/reporting/test_haddix_submission_internal_sections.py
.venv/bin/pytest -q tests/unit/reporting/test_haddix_evidence_quality_gate.py
```

新規テストファイルは、追加実装時に作成する。

### 9.2 real artifact checks

```bash
python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_004743.md
python3 scripts/shigoku_ops_cli.py --json report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_004743.md
python3 scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_004743.md
```

### 9.3 docs validation

```bash
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

## 10. 受け入れ条件

- [ ] レポート冒頭が `# 提出用レポート / Submission Report` で始まる。
- [ ] `# 内部評価（私用） / Internal Review Notes` より前に `Injection Execution Notes`, `Scenario Coverage`, `Initial Release Gate`, `Submission Readiness Diagnostics`, `Auto Actions`, `Deferred Scenario Backlog`, `Non-Submission Candidates` が出ない。
- [ ] 各 confirmed finding は `#### 日本語` が `#### English` より先に出る。
- [ ] 提出用 copy scope に candidate finding が出ない。
- [ ] `PoC Request Captured: yes` 相当の表示は、payload入り raw request がある場合に限る。
- [ ] 提出用 response evidence に `HTTP/1.1 0` が出ない。
- [ ] CSRF confirmed は forged request と状態変化確認を持つ。
- [ ] Stored XSS confirmed は保存後再表示/別セッション実行 evidence を持つ。
- [ ] API unauth/authz confirmed は 200->200 だけでなく機密性または認可境界の根拠を持つ。
- [ ] consistency checker が `status=consistent`, `rerun_required=false` を返す。
- [ ] gate script が新見出し構造でも必要メトリクスを解釈できる。
- [ ] docs validation が 0 エラーで通る。

## 11. 実装優先度

### P0: コピー事故防止と順序修正

- 提出用/内部評価の top-level split。
- 日本語 -> 英語順。
- candidate/internal metrics を提出用 copy scope から除外。
- Generated/Source Session 互換維持。

### P1: confirmed evidence quality

- payload入り raw request 必須化。
- `HTTP/1.1 0` の提出用排除。
- vuln-specific confirmed matrix。
- CSRF/XSS/Stored XSS/API/AuthZ/LFI/SQLi の証拠条件強化。

### P2: 検出範囲と取りこぼし改善

- Command Injection timeout 原因調査。
- DOM XSS、Open Redirect、Weak Session IDs の検出/検証追加。
- DVWA low coverage の評価項目を内部評価側で継続追跡。

## 12. 懸念点と対策

### 12.1 SRE/インフラエンジニア視点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|--------|----------|--------|--------------------------|
| Playwright、複数回 timing、状態変化検証が増え、CI/ローカル実行が不安定化する | 高 | 中 | `## 8.6` に timeout、retry上限、並列数上限、dry-run、flaky時の candidate 降格を追加済み。実装時は fixture test と実 artifact check を分ける。 |
| raw request/response 保存で cookie、session、token が提出用/内部用レポートに混入する | 高 | 大 | `## 8.2` と `## 8.10` に最低書き込み層の recursive redaction と redacted artifact 確認を追加済み。Cookie/Authorization/PHPSESSID/security/token は提出用に出さない。 |
| `HTTP/1.1 0` 排除後に代替 evidence がなく、confirmed が大量降格して gate が急に落ちる | 中 | 大 | `## 8.5` に shadow mode を追加済み。まず既存判定と新 evidence verdict の差分を内部評価へ出し、enforcement は受け入れ条件確認後に切り替える。 |
| 実 artifact 再生成時に既存レポートを上書きし、比較不能になる | 中 | 中 | `## 8.6` に新 timestamp report への出力と元 report の read-only primary source 扱いを追加済み。 |

### 12.2 ソフトウェアアーキテクト視点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|--------|----------|--------|--------------------------|
| `haddix_formatter.py` と `haddix_ja_en_formatter.py` の責務が重複し、修正漏れが出る | 高 | 大 | `## 8.4` に共通 section builder/helper へ提出用/内部用の構造責務を寄せる方針を追加済み。 |
| evidence quality validator が formatter 内に入り、表示ロジックと判定ロジックが密結合する | 高 | 大 | `## 8.4` と `## 8.5` に、formatter は verdict 表示に専念し、evidence 判定は独立 helper に分離する方針を追加済み。 |
| report/session schema の追加 field が ad hoc になり reader 互換を壊す | 中 | 大 | `## 8.2` に additive schema、既存 field の削除/意味変更禁止、reader の `rg` 確認を追加済み。 |
| opt-in format と既定 format の分岐が増え、CLI利用者がどれを使うべきか迷う | 中 | 中 | `## 8.1` と `## 8.9` に format名、既定値、互換維持方針、help表示、生成ファイル名規則、docs/manual 更新を追加済み。 |

### 12.3 ハッカー視点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|--------|----------|--------|--------------------------|
| payload が raw request に含まれるだけでは、アプリ側で実際に到達・実行された証拠にならない | 高 | 大 | `## 8.7` に payload presence は必要条件に留め、sink到達、reflection、DOM execution、state delta、authz differential などを種別ごとに必須化する方針を追加済み。 |
| CSRF の forged HTML は作れても、SameSiteやmethod制約で実ブラウザ成立しない可能性がある | 高 | 大 | `## 8.7` に victim browser context、SameSite/cross-site条件、Cookie送信有無、before/after state の記録を追加済み。 |
| Stored XSS は同一セッション再表示だけだと stored と言い切れない | 中 | 大 | `## 8.7` に投稿セッションと閲覧セッションを分離し、別 request/別セッション再表示で実行 evidence を記録する方針を追加済み。 |
| Severity normalization が一般論止まりで、実影響の証拠と結びつかない | 高 | 中 | `## 8.8` に severity decision table を `vuln type`, `execution context`, `affected role`, `data sensitivity`, `exploit preconditions` で定義する方針を追加済み。 |

### 12.4 CTO視点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|--------|----------|--------|--------------------------|
| P0/P1/P2 の境界はあるが、リリース判断条件が曖昧 | 中 | 大 | `## 8.1` と `## 11` に P0 は構造分離、P1 は evidence quality、P2 は検出拡張として分ける方針を追加済み。 |
| confirmed が減ると見かけ上の検出性能が落ち、社内評価と提出品質評価が混同される | 高 | 中 | `## 8.8` に内部検出精度スコアと提出準備度スコアを分け、降格は品質改善として内部評価に説明する方針を追加済み。 |
| Bug Bounty提出用の信頼性向上が、検出範囲拡張と同時進行してスコープ肥大化する | 高 | 大 | `## 8.10` と `## 13` に Command Injection 等の検出拡張は本タスクで実装せず、P2 backlog/別タスク扱いにする方針を追加済み。 |
| 外部提出文面として、日本語->英語の二重記載が提出先の期待とズレる可能性がある | 中 | 中 | `## 8.9` に日本語+英語 copy scope と英語のみ抽出版の生成方針を help/documentation に明記する方針を追加済み。 |

### 12.5 既存リスクと対応

| リスク | 発生確率 | 影響度 | 対応 |
|--------|----------|--------|------|
| 既定 `--format haddix` を変えて既存運用が壊れる | 中 | 大 | 初期実装は opt-in format/option を優先し、format名・help・生成ファイル名規則を先に固定する。 |
| checker/gate が見出し位置前提で壊れる | 中 | 大 | `Generated`, `Source Session`, `Confirmed PoC Missing` などの機械可読行を維持し、テストで固定する。 |
| 日本語と英語の意味差分 | 中 | 中 | canonical fields を唯一の入力にし、両言語を同じ fact set から生成する。 |
| evidence quality 強化で confirmed が大幅に減る | 中 | 大 | shadow mode で差分を内部評価に出し、enforcement は受け入れ条件確認後に切り替える。 |
| 実通信ログが session に残っていない | 中 | 大 | 合成は提出用に出さず synthetic として内部評価へ置き、再実行または probe 改修を必要条件にする。 |

## 13. 次にAIへ出す実装指示案

```text
SGK-2026-0345 の計画に従って、Haddix レポートを提出用/内部評価（私用）に分離し、日本語->英語順へ変更してください。
P0は構造分離と copy scope の安全化、P1は evidence quality gate の shadow mode、P2は検出範囲拡張として分けてください。
まず tests/unit/reporting にセクション境界・candidate隔離・payload入りPoC・HTTP/1.1 0排除・redaction・shadow verdict 差分の regression test を追加し、その後 formatter と evidence helper を最小差分で修正してください。
対象レポートは workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_004743.md です。作業前後に verify_report_session_consistency.py を実行し、実 artifact で確認してください。
```
