---
task_id: SGK-2026-0347
doc_type: plan
status: active
parent_task_id: SGK-2026-0345
related_docs:
- docs/shigoku/plans/done/2026-07-07_haddix-submission-internal-ja-first-report-plan_plan.md
- docs/shigoku/plans/2026-07-07_sgk-2026-0346_evidence-enforcement-p2-detection-expansion_plan.md
- workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_163941.md
- workspace/projects/127.0.0.1:4280/sessions/session_20260707_163939.json
- workspace/projects/localhost:4280/reports/haddix_report_20260711_150744.md
- src/main.py
- src/reporting/haddix_formatter.py
- src/cli/messages.py
- tests/unit/main/test_main_auto_report_bundle.py
- tests/unit/main/test_main_report_haddix.py
- tests/unit/reporting/test_haddix_submission_internal_sections.py
title: HaddixReport Bug Bounty提出品質最適化計画
created_at: '2026-07-07'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/reporting/haddix_formatter.py, src/reporting/haddix_submission_internal_formatter.py,
  src/reporting/haddix_evidence_quality.py
---

# 実装計画書：HaddixReport Bug Bounty提出品質最適化計画

## 0. 入力確認と評価根拠

- 対象レポート: `workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_163941.md`
- primary source of truth: 上記レポートと、整合性チェッカーが解決した `workspace/projects/127.0.0.1:4280/sessions/session_20260707_163939.json`
- 実行済み整合性チェック:
  - `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_163941.md`
  - 結果: `status=consistent`, `rerun_required=false`, `reason_codes=[]`
- 実行済みゲートチェック:
  - `python3 scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_163941.md`
  - 結果: `status=pass`, `gate_passed=true`
- ただし Bug Bounty 提出品質評価では、gate pass と submission-ready は同義ではない。
- 別AI評価では、今回レポートを「運用品質は上がったが、Bug Bounty提出品質としてはまだ合格ではない」と判定している。
  - 検出精度: 前回 65 -> 今回 68
  - レポート品質: 前回 45 -> 今回 52
  - 提出準備度: 前回 35 -> 今回 42
  - 良化点: timeout 0、confirmed 過剰判定の抑制、candidate appendix 分離、API unauth access の実 HTTP evidence。
  - 未達点: payload入り実 request、実 HTTP response、`HTTP/1.1 0` 排除、CSRF confirmed 降格、種別別 confirmed gate。
- 本計画は、既存 `HaddixFormatter` / `HaddixSubmissionInternalFormatter` / evidence quality logic を、Bug Bounty 提出で突っ込まれにくい証拠水準へ最適化する。

## 1. 達成したいゴール（ユーザー視点）

- [ ] `--format haddix-submission-internal` または Bug Bounty 提出用の明示モードで生成したレポートは、先頭から提出用 copy scope として使える。
- [ ] 提出用 copy scope には内部 KPI、scenario coverage、gate、baseline diff、auto actions、deferred backlog、heuristic candidate が混入しない。
- [ ] `confirmed` と表示される finding は、payload 入り raw request、実 HTTP response または種別別の代替実証、impact 根拠、再現手順を持つ。
- [ ] `HTTP/1.1 0` や detector note だけの証拠は、提出用 confirmed evidence として出ない。
- [ ] 証拠不足の finding は candidate appendix または internal review notes に降格され、reason code が明記される。
- [ ] レポート品質スコアを提出準備度として可視化し、`submission_ready` と `internal_gate_passed` を別指標として扱う。
- [ ] session/report consistency checker と initial release gate は、新しい見出し構造でも読み取れる。

## 2. 現状課題（2026-07-07 16:39 report）

| ID | 課題 | 観測箇所 | Bug Bounty上のリスク | 修正方針 |
|---|---|---|---|---|
| Q-01 | 内部ログが冒頭に出る | `Injection Execution Notes`, `Scenario Coverage`, `Initial Release Gate` が finding より前に出る | 提出先に内部評価ログを渡してしまう | 提出用 copy scope を先頭に固定し、内部情報は後半へ隔離 |
| Q-02 | payload が raw request に入っていない | SQLi/XSS/LFI の `PoC Request Captured: yes` が素の URL | 再現不能・虚偽PoC扱い | `PoC Request Captured=yes` の定義を payload-in-request 必須へ変更 |
| Q-03 | `HTTP/1.1 0` が confirmed evidence に出る | SQLi/XSS/LFI/candidate evidence | 実HTTP証拠ではなく検出器メモに見える | submission scope から除外し、internal synthetic note として分類 |
| Q-04 | XSS が browser execution なしで High confirmed | reflected note のみ | XSS成立証拠不足、severity過大 | Playwright dialog/DOM evidence を confirmed 条件へ追加 |
| Q-05 | Blind SQLi が単発 timing note | baseline=0.00s, observed=3.01s のみ | jitter/timeout誤検知の疑い | baseline 3回、sleep 3回、inverse 1回、delta判定表を必須化 |
| Q-06 | LFI request が traversal payload を含まない | `page=include.php` のまま | `/etc/passwd` 再現不可 | traversal入りURLと marker excerpt を保存・表示 |
| Q-07 | API access が `200->200` だけに寄る | identical status/length + JSON body | 公開API/想定挙動との区別不足 | 未認証境界、期待認可、sensitive fields、authなし再現手順を明記 |
| Q-08 | CSRF が manual confirmation 必要なのに confirmed 表示 | tokenless form + GET + 空body | 状態変化未証明 | forged request/html、victim context、before/after state を必須化 |
| Q-09 | CSRF remediation が CORS 寄り | Access-Control-Allow-Origin の説明 | 修正案が脆弱性種別とズレる | anti-CSRF token, SameSite, Origin/Referer, re-auth に差し替え |
| Q-10 | 生 Cookie が report に出る | CSRF request evidence | 秘密情報漏洩 | lowest write/display boundary で recursive redaction |
| Q-11 | report metrics と session_raw_unique の差分が説明されない | gate は `session_raw_unique=8`、report は `6/3` | 読み手が件数を信頼しづらい | canonical extractor、dedup、formatter split の差分を internal notes で説明 |
| Q-12 | API unauth access の High が強すぎる | `/vulnerabilities/api/v2/user/` の JSON は `id/name/level` のみ | 公開一覧や低機密データを High と誤評価する | expected denied behavior、非公開性、`level` の権限意味、他ユーザー影響を要求し、未証明なら Medium/Info |
| Q-13 | `/vulnerabilities/exec/` を CMD_SSRF 候補として扱っている | duration 420.414s、candidate 名が `Potential CMD_SSRF attack surface` | DVWA low の Command Injection を取り逃がす | まず Command Injection として `ip` payload/output/timing control を検証し、候補名も修正 |
| Q-14 | Open Redirect が外部URLで検証されていない | `redirect=info.php?id=1` など内部相対パス中心 | open redirect 成立証拠にならない | `redirect=https://example.com/` と `302 Location: https://example.com/` を必須化 |
| Q-15 | XSS の反射文脈が不明 | `reflected without encoding` のみ | 反射はしたが実行可能か不明 | render context、browser execution signal、screenshot、DOM evidence を記録 |
| Q-16 | timeout 0 は良化したが、長時間実行が残る | `/vulnerabilities/exec/` duration 420.414s | 実運用で重い・CIで不安定 | long-running completed を KPI 別枠で warning 化し、上限/中断/軽量payloadを設計 |

## 3. 対象コンポーネント

| ファイル | 役割 | 主な変更方針 |
|---|---|---|
| `src/reporting/haddix_formatter.py` | 既存 HaddixReport renderer | evidence quality verdict を反映し、synthetic evidence と weak confirmed を提出用 confirmed から除外 |
| `src/reporting/haddix_submission_internal_formatter.py` | 提出用/内部用分離 renderer | Bug Bounty 提出用の正本として copy scope を強化し、内部情報を完全隔離 |
| `src/reporting/haddix_evidence_quality.py` | shadow-mode evidence validator | enforcement mode を追加し、種別別 confirmed 条件と reason code を正本化 |
| `src/reporting/finding_extractor.py` | raw finding canonical extractor | 読み取り互換を維持し、必要に応じて additive evidence field を拾う |
| `src/main.py` | CLI report generation route | `--format haddix-submission-internal` の案内・生成経路・artifact check を強化 |
| `scripts/check_initial_release_gate.py` / `src/reporting/initial_release_gate.py` | gate evaluator | 新見出し構造・confirmed/candidate reason を読み続けられるよう互換維持 |
| `src/core/agents/swarm/injection/smart_cmd_ssrf.py` | command/SSRF probing | DVWA exec 系は Command Injection 優先で検証し、SSRF と混同しない |
| `src/core/agents/swarm/injection/manager.py` | injection orchestration | command injection/open redirect/XSS browser verification の evidence を session に保存 |
| `tests/unit/reporting/` | regression tests | evidence quality enforcement、copy scope、redaction、real artifact 互換テストを追加 |

## 4. 仕様と制約条件

### 4.1 Evidence truth boundary

- raw findings は `src/reporting/finding_extractor.extract_all_findings()` を正本として扱う。
- report-only backfill と raw session evidence を混同しない。
- report/session consistency が `consistent` でない report では品質評価・提出用生成を停止する。
- 既存 session schema の削除・意味変更は禁止。新 evidence field は additive に追加する。

### 4.2 Confirmed 判定の最低条件

confirmed finding は共通で次を満たす。

- raw request に攻撃 payload または検証対象 mutation が含まれる。
- raw response は実 HTTP response である、または browser/state-change/authz/timing などの代替実証が構造化 evidence として存在する。
- `HTTP/1.1 0`、空 header、detector note のみ、heuristic candidate のみでは confirmed にしない。
- endpoint、method、parameter、payload、auth/cookie context、control/attack 差分が再現可能な粒度で出る。
- Cookie、Authorization、PHPSESSID、security、csrf/token/password/secret-like 値は redacted evidence のみ提出用に出る。

### 4.3 種別別 confirmed 条件

| 種別 | confirmed 必須証拠 | 不足時 reason code |
|---|---|---|
| Blind SQLi | baseline timing 3回、sleep timing 3回、inverse condition 1回、delta 判定 | `insufficient_timing_validation` |
| Error/Boolean SQLi | payload入り request、control/attack response diff、SQL error または boolean/data difference | `insufficient_response_difference` |
| Reflected XSS | payload入り URL/request、response reflection、browser dialog または DOM mutation | `browser_execution_missing` |
| Stored XSS | save request、revisit request、別セッションまたは再表示で browser execution | `stored_revisit_missing` |
| LFI | traversal payload入り URL、file marker excerpt、control page comparison | `payload_request_mismatch` |
| CSRF | forged request/html、victim browser context、Cookie送信条件、before/after state | `state_change_not_verified` |
| API/AuthZ | unauth/auth または userA/userB 差分、期待認可境界、sensitive fields | `authz_impact_not_proven` |
| Command Injection | command output または timing fallback + control | `command_execution_not_verified` |
| Open Redirect | external URL payload、Location header または browser navigation | `redirect_target_not_external` |

### 4.4 Severity / submission readiness 正規化

- `internal_gate_passed` は「内部リリース/運用ゲート」、`submission_ready` は「Bug Bounty提出可能」を表す別指標とする。
- severity は evidence と impact に基づき、検出器の種類だけで High にしない。
- API/AuthZ は次を満たさない限り High にしない:
  - 未認証または低権限では本来 401/403 になるべき根拠がある。
  - 返却データが非公開・個人情報・権限情報・業務上重要情報である根拠がある。
  - `level` などのフィールドが権限や機密性に結びつく説明がある。
  - 他ユーザー情報取得や権限境界逸脱の影響が示されている。
- reflected XSS は browser execution または実行可能 render context がない場合、confirmed に残さない。反射のみは candidate または Medium 以下にする。
- CSRF は tokenless form のみでは candidate とし、state-change evidence 取得後に confirmed へ昇格する。
- long-running completed task は timeout でなくても `slow_probe_warning` として内部評価に出す。

### 4.5 Evidence field additions

既存 session schema は壊さず、以下を additive に保存する。

| Field | 用途 |
|---|---|
| `payload_location` | payload が query/body/header/path のどこに入ったか |
| `raw_request_redacted` | 提出用に使う redacted raw request |
| `raw_response_redacted` | 提出用に使う redacted real HTTP response |
| `control_request` / `attack_request` | SQLi/LFI/AuthZ 等の比較 |
| `timing_samples.baseline/sleep/inverse_condition` | Blind SQLi timing table |
| `browser_execution.dialog_observed` / `dom_mutation_observed` | XSS execution proof |
| `render_context` | XSS payload の出力文脈 (`html_body`, `attribute`, `js_string` 等) |
| `csrf_state_change.before_state/after_state` | CSRF 成立証拠 |
| `open_redirect_evidence.location_header_external` | Open Redirect 成立証拠 |
| `command_execution_evidence.output_observed/timing_confirmed` | Command Injection 成立証拠 |
| `expected_denied_behavior` | AuthZ/API で本来拒否されるべき根拠 |

### 4.6 出力仕様

- 先頭は `# 提出用レポート / Submission Report` とする。
- `## コピー範囲 / Copy Scope` で提出範囲を明示する。
- 提出用 finding は `#### 日本語` -> `#### English` 順にする。
- `# 内部評価（私用） / Internal Review Notes` より前に以下を出さない:
  - Injection Execution Notes
  - Scenario Coverage
  - Vulnerability Family Coverage Gate
  - Initial Release Gate
  - Baseline Diff
  - Auto Actions
  - Deferred Scenario Backlog
  - Non-Submission Candidates
  - Evidence Quality Shadow/Enforcement Diagnostics
- candidate は appendix または internal notes のみに出し、提出用 copy scope には混ぜない。

## 5. 実装ステップ（AIに指示する手順）

### Step 1: 現行呼び出し経路と schema reader を棚卸しする

- `rg` で `HaddixFormatter`, `HaddixSubmissionInternalFormatter`, `HaddixEvidenceQualityValidator`, `extract_all_findings`, `check_initial_release_gate`, `--format haddix` を検索する。
- report/session reader が参照する field を列挙し、削除・意味変更しない field を明示する。
- 対象 report の consistency checker を再実行し、`status=consistent` であることを確認する。

### Step 2: evidence quality validator を enforcement-ready にする

- `HaddixEvidenceQualityValidator` に `mode="shadow" | "enforce"` を追加する。
- `evaluate_finding()` の verdict を formatter が confirmed/candidate split に使える形にする。
- synthetic response、payload mismatch、browser missing、state missing、authz impact missing を reason code として安定化する。
- `HTTP/1.1 0` は submission evidence として出さず、internal notes で `synthetic_detector_note` と明示する。

### Step 3: PoC artifact 生成と redaction を改善する

- raw request は method/path/query/body/header/cookie context を保存する。
- payload は URL/query/body/header のどこに入ったかを `payload_location` として保存する。
- response は status/header/body excerpt を保存する。
- timing/browser/state-change/authz differential は構造化 field として保存する。
- Cookie/Authorization/PHPSESSID/security/token/password は lowest write/display boundary で redaction する。
- `raw_request_redacted` と `raw_response_redacted` を submission formatter の入力正本にする。
- synthetic detector note は `synthetic_detector_note` として internal notes へ保存し、submission evidence には使わない。

### Step 4: formatter の提出用/内部用境界を強化する

- `haddix-submission-internal` を Bug Bounty 提出用の推奨 format とする。
- 既存 `haddix` は互換維持しつつ、weak confirmed を candidate 降格または warning 表示する。
- 提出用 copy scope から内部 KPI と candidate を除外する。
- `Generated` と `Source Session` は checker が読める形式で維持する。
- report metrics と session_raw_unique の件数差は internal notes で説明する。
- `submission_readiness_score` を内部評価に出し、前回比の改善/未達を説明する。

### Step 5: 種別別 PoC/impact/remediation を修正する

- SQLi: control/attack diff、timing sample table、database impact を出す。
- XSS: browser execution evidence、render context、screenshot/DOM evidence と impact を出す。reflection only は Medium/candidate に落とす。
- LFI: traversal URL、file marker excerpt、control page comparison を出す。
- API/AuthZ: unauth request、auth request、期待される認可境界、sensitive field を出す。`200->200` 単独で High confirmed にしない。
- CSRF: forged HTML/request、victim context、before/after state を出す。remediation は anti-CSRF token / SameSite / Origin or Referer validation / re-auth にする。
- Command Injection: `/vulnerabilities/exec/` は SSRF ではなく command injection として優先分類し、`ip` payload、control、command output または timing fallback を出す。
- Open Redirect: 外部 URL payload と `Location` header / browser navigation evidence を出す。内部相対 redirect だけでは candidate に留める。

### Step 5.5: 検出側の取りこぼし改善を SGK-2026-0346 と整合させる

- SGK-2026-0346 の P2 検出範囲拡張と重複しないよう、SGK-2026-0347 では「提出品質 gate」と「既存 report の分類/証拠表現」を優先する。
- Command Injection / Open Redirect の probe 実装に踏み込む場合は、SGK-2026-0346 へ related update または subtask 化する。
- ただし report formatter 側では、取りこぼし候補を正しい名前・reason code・次アクションで表示する。

### Step 6: CLI と実 artifact 検証を追加する

- CLI help に Bug Bounty 提出用は `--format haddix-submission-internal` を使う旨を明記する。
- 必要なら `shigoku-ops report` 経路にも推奨 format を表示する。
- 対象 session から新 timestamp report を生成し、元 report は上書きしない。
- consistency checker と gate script を新 report に対して実行する。

## 6. テスト計画

### 6.1 Targeted unit tests

```bash
.venv/bin/pytest -q tests/unit/reporting/test_haddix_evidence_quality_gate.py
.venv/bin/pytest -q tests/unit/reporting/test_haddix_submission_internal_sections.py
.venv/bin/pytest -q tests/unit/reporting/test_haddix_formatter_kpi.py
.venv/bin/pytest -q tests/unit/reporting/test_haddix_ja_en_formatter.py
```

追加・更新するテスト観点:

- payload が raw request に存在しない confirmed は candidate へ降格される。
- `HTTP/1.1 0` は confirmed submission response に出ない。
- reflected XSS は browser execution なしでは confirmed にならない。
- blind SQLi は timing samples 不足で confirmed にならない。
- LFI は traversal payload 入り URL と file marker excerpt がないと confirmed にならない。
- CSRF は state change evidence なしでは confirmed にならない。
- API/AuthZ は sensitive field または認可境界根拠なしでは High confirmed にならない。
- Command Injection candidate は `CMD_SSRF` ではなく `command_injection` として分類され、`ip` parameter の control/attack evidence を要求する。
- Open Redirect は external URL payload と `Location` header または navigation evidence がないと confirmed にならない。
- XSS は `render_context` と browser execution evidence が submission scope に表示される。
- long-running completed probe は timeout 0 でも warning KPI として internal notes に出る。
- Cookie/Authorization/PHPSESSID/security/token/password が submission scope に残らない。
- internal sections が submission copy scope より前に出ない。
- consistency checker と gate script が新見出し構造を読める。

### 6.2 Real artifact checks

```bash
python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_163941.md
python3 scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_163941.md
python3 scripts/shigoku_ops_cli.py --json report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_163941.md
```

実装後は、新 timestamp report に対して同じ checks を実行する。

### 6.3 Docs validation

```bash
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

## 7. 受け入れ条件

- [ ] Bug Bounty 提出用 report の先頭が `# 提出用レポート / Submission Report` で始まる。
- [ ] 提出用 copy scope に内部 KPI/gate/coverage/candidate が出ない。
- [ ] `PoC Request Captured: yes` は payload/mutation 入り raw request がある場合に限る。
- [ ] confirmed submission evidence に `HTTP/1.1 0` が出ない。
- [ ] 対象 report で弱い confirmed が candidate または internal-only に降格される:
  - SQLi blind: timing samples 不足なら candidate
  - XSS reflected: browser execution 不足なら candidate
  - LFI: traversal request 不足なら candidate
  - CSRF: state change 不足なら candidate
- [ ] API unauth access は、期待認可境界と sensitive field を示せる場合だけ confirmed に残る。
- [ ] API unauth access は、非公開性/権限情報/他ユーザー影響が未証明なら High ではなく Medium/Info または candidate になる。
- [ ] CSRF remediation が CORS ではなく CSRF 対策になっている。
- [ ] `/vulnerabilities/exec/` は Command Injection 候補として表示され、CMD_SSRF 混同を避ける。
- [ ] Open Redirect は `redirect=https://example.com/` 相当の外部URL payload と `302 Location` 等の evidence がなければ confirmed にならない。
- [ ] XSS は `Render Context` と `Browser Execution` または実行可能文脈が提出用 finding に含まれる。
- [ ] slow completed probe は timeout 0 とは別に warning として可視化される。
- [ ] Cookie/Authorization/PHPSESSID/security/token/password が submission scope に残らない。
- [ ] `verify_report_session_consistency.py` が `status=consistent`, `rerun_required=false` を返す。
- [ ] `check_initial_release_gate.py` が新 report を読める。
- [ ] targeted reporting tests が pass する。
- [ ] `python3 scripts/validate_shigoku_docs.py` が 0 エラーで通る。

## 8. 優先度

### P0: 提出事故防止

- submission/internal 境界の固定。
- `HTTP/1.1 0` の提出用排除。
- payload-in-request と redaction の hard gate。
- CSRF remediation 修正。
- `PoC Request Captured=yes` の意味を「payload/mutation入り request captured」に限定する。

### P1: confirmed 精度改善

- evidence quality enforcement mode。
- SQLi/XSS/LFI/CSRF/API/Command Injection/Open Redirect の種別別 confirmed matrix。
- weak confirmed の candidate 降格と reason code 表示。
- API severity normalization と submission readiness score。

### P2: 追加検証と検出強化

- Playwright browser execution evidence。
- timing sample collection。
- CSRF victim browser/state-change harness。
- command injection / DOM XSS / open redirect / weak session の検出拡張は SGK-2026-0346 と連携する。
- `/vulnerabilities/exec/` の 420秒級 slow completed probe を軽量化し、Command Injection 優先 probing へ寄せる。

## 9. 既知のリスクと対策

| リスク | 影響 | 対策 |
|---|---|---|
| confirmed 件数が大きく減る | gate pass と提出品質の見え方が変わる | 内部検出精度と提出準備度を分け、降格を品質改善として表示する |
| 実 artifact 再生成で元 report を上書きする | 比較不能になる | 新 timestamp report のみに出力し、元 report は primary source として保持する |
| browser/timing/state-change 検証が flaky | CI/ローカルで不安定 | timeout/retry上限、dry-run、fixture test と real artifact check の分離 |
| redaction 漏れ | 秘密情報漏洩 | lowest write/display boundary で recursive redaction、深い dict/list のテストを追加 |
| 既存 `--format haddix` 利用者の期待が変わる | 後方互換リスク | 初期実装は opt-in 推奨 format を優先し、既存 format は warning/diagnostic から段階適用 |
| P2 検出改善と本タスクが混線する | スコープ肥大化 | SGK-2026-0347 は提出品質 gate と表示/分類を優先し、probe 実装拡張は SGK-2026-0346 と同期する |
| API severity を下げすぎる | 実リスクを過小評価 | expected denied behavior と sensitive field が揃う場合は High を許可し、根拠を本文に出す |

## 10. 次にAIへ出す実装指示案

```text
SGK-2026-0347 の計画に従って、既存 HaddixReport を Bug Bounty 提出品質へ最適化してください。
対象 report は workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_163941.md です。
作業前に verify_report_session_consistency.py と check_initial_release_gate.py を実行し、resolved session を primary source of truth としてください。
P0 は submission/internal 境界、HTTP/1.1 0 排除、payload-in-request gate、redaction、CSRF remediation 修正です。
P1 は evidence quality enforcement mode、種別別 confirmed matrix、API severity normalization、submission readiness score です。
別AI評価で指摘された Command Injection 誤分類、Open Redirect 未検証、XSS render context 不足、slow completed probe も計画に統合済みです。
まず targeted tests を追加/更新し、その後 formatter/evidence helper/CLI を最小差分で修正してください。
元 report は上書きせず、新 timestamp report で consistency/gate を検証してください。
```
