---
task_id: SGK-2026-0357
doc_type: plan
status: done
parent_task_id: SGK-2026-0347
related_docs:
  - docs/shigoku/plans/2026-07-07_haddix-report-bugbounty-quality-optimization_plan.md
  - docs/shigoku/plans/2026-07-07_sgk-2026-0346_evidence-enforcement-p2-detection-expansion_plan.md
  - docs/shigoku/reports/2026-07-07_sgk-2026-0345_haddix-submission-internal-ja-first-report_work_report.md
  - workspace/projects/localhost:4280/reports/haddix_report_20260713_090445.md
  - workspace/projects/localhost:4280/sessions/session_20260711_150743.json
  - src/reporting/haddix_formatter.py
  - src/reporting/haddix_submission_internal_formatter.py
  - src/reporting/finding_extractor.py
  - src/core/agents/swarm/injection/smart_cors.py
  - src/core/attack/cors_tester.py
  - src/core/models/finding.py
title: CORSレポート品質修正 — 7指摘の根因対応計画
created_at: '2026-07-13'
updated_at: '2026-07-21'
tags:
  - shigoku
  - haddix
  - reporting
  - cors
  - quality
target: src/reporting/haddix_formatter.py, src/reporting/haddix_submission_internal_formatter.py, src/core/attack/cors_tester.py, src/core/agents/swarm/injection/smart_cors.py
---

# 計画書: CORSレポート品質修正（第三者指摘への対応）

## 0. 背景

- 対象レポート: `workspace/projects/localhost:4280/reports/haddix_report_20260713_090445.md`
- 対象session: `workspace/projects/localhost:4280/sessions/session_20260711_150743.json`
- 本レポートに対して、ユーザーがCORS Finding（`wildcard_no_credentials`）の7項目の品質指摘を行った。
- 本タスクは、全7指摘の根因を特定し、修正計画を立てる。

整合性ゲート:
- `verify_report_session_consistency.py`: `status=blocked` / `reason_codes=source_session_not_found`
- 原因: レポートheaderのsource session pathが `/app/workspace/...` (コンテナ内パス）で記録されている。
  host側のsession本体は `/home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/sessions/session_20260711_150743.json` に存在。
- 根本的な対策（session path正規化）は本タスクのスコープ外。本レポートの調査はhost側sessionを直接読んで実施済み。

## 1. 7指摘の根因サマリ

| ID | 指摘 | 根因 | 対応方針 |
|----|------|------|----------|
| R-15 | 再現手順がない | フィールド名不一致: detector出力=`reproduction_steps`, formatter読取=`steps_to_reproduce`。sessionには4step存在 | formatter側で `reproduction_steps` をフォールバック読み取り |
| R-16 | PoCのResponse Bodyがない | `CORSTester._test_origin()`が `response.text` を未取得。formatterは合成 `poc_response`(headerのみ)だけ読み、`evidence.response_body`や `poc_html` を未読 | detectorでbody取得、formatterで `poc_html` 表示 |
| R-17 | Impactがブラウザ動作説明 | detector `smart_cors.py` が汎用impactを直書き。具体的に「誰のどの情報が漏れるか」になっていない | detectorのimpact生成をdata-awareに修正 |
| R-18 | Expected ResultがCORSと無関係 | `_expected_result_text()` / `_english_expected_result()` に `cors_misconfiguration` エントリなし→汎用テキスト fallback | 両言語の expected result に CORS エントリ追加 |
| R-19 | 修正後確認手順が逆（「同じ結果になる」） | `haddix_formatter.py:1468` の検知モードstepが `"同じ結果になることを確認する"` の誤り | `"再現しないことを確認する"` に修正 |
| R-20 | Severity過大（MEDIUM→LOW） | `smart_cors.py:89`: `acac=="true"→HIGH else MEDIUM`。`wildcard_no_credentials`(ACAC空)はLOW/Infoが妥当 | severity判定に `misconfiguration` type別分岐追加: `wildcard_no_credentials→LOW` |
| R-21 | EN修正案が汎用OWASP（JAはCORS固有） | EN `_english_remediation_text()` にCORSエントリなし。JA `_remediation()` にはCORSあり | ENにもCORSエントリを追加 |

## 2. 根因詳細

### 2.1 R-15: 再現手順欠落 — フィールド名不一致

**現象:** レポートに `"(再現手順は提供された検出 evidence から再構成してください)"` と表示。
**session実態:** CORS finding に `reproduction_steps` (list, 4step) が存在。

1. `1. Send GET http://localhost:4280/vulnerabilities/api/v2/user/ with header: Origin: https://evil.com`
2. `2. Observe response header: Access-Control-Allow-Origin: *`
3. `3. If Access-Control-Allow-Credentials: true, cross-origin requests with cookies are possible.`
4. `4. Use the PoC HTML to confirm data exfiltration from a controlled origin.`

**コード根因:**
- detector (`smart_cors.py`) は `Finding` dataclass のフィールドとして `reproduction_steps` に出力。
- `finding_extractor.py` はraw dictをそのまま抽出（正規化なし）。
- `HaddixFormatter._add_finding_from_dict()` (`haddix_formatter.py:457`): `data.get("steps_to_reproduce", [])` で読み取るが、detector dictには `reproduction_steps` キーのみ。
  → `data.get("steps_to_reproduce", [])` が空リストを返し、formatterのfallback placeholderが使われる。

**修正箇所:** `haddix_formatter.py:457`
```python
# Before
steps = list(data.get("steps_to_reproduce", []))
# After: fallback to reproduction_steps from detector output
steps = list(data.get("steps_to_reproduce") or data.get("reproduction_steps", []))
```

### 2.2 R-16: PoC情報不足（Response Body / JS exfil）

**現象:** PoCはheaderのみ。poc_html(JS exfil PoC)が未表示。
**session実態:**
- `additional_info.poc_html`: 完全なJS PoC (fetch+credentials:include→表示→exfilコメント) が存在
- `additional_info.poc_response`: 合成文字列（HTTP status line + 該当headerのみ、bodyなし）
- `evidence.response_body`: `""` (空文字列) — 根本的にCORS detectorがbody未取得

**コード根因(三層):**

| 層 | ファイル:行 | 問題 |
|----|-------------|------|
| **detector:** body未取得 | `cors_tester.py:122` | `response = client.get(url, ...)` 後に `response.text` を一切読まない。`response.headers.get(...)` のみ |
| **detector:** Evidence構築時にもbody未設定 | `smart_cors.py:93-102` | `Evidence(response_body=...)` 未指定 → デフォルト `""` |
| **formatter:** poc_html未読 | `haddix_formatter.py:476-485` | `poc_request`/`poc_response` は読み取るが、`additional_info.poc_html` は未読 |

**実装戦略:**
1. `cors_tester.py:122`: response bodyを取得し `CORSResult` dataclass に `response_body` フィールドを追加
2. `smart_cors.py:93-102`: `Evidence(response_body=r.get("response_body", ""))` を設定
3. `haddix_formatter.py:476-485`: `additional_info.get("poc_html")` を読み取り、PoCセクションで表示

### 2.3 R-17: Impactがブラウザ動作説明

**現象:** `"An attacker can read unauthenticated cross-origin responses."` — CORS仕様の一般論であり、具体的なデータ漏洩内容/被害を説明していない。

**コード根因:**
- `smart_cors.py:lines 84-146` 内で `Finding(impact=...)` を設定している。impact文字列はCORSタイプ別ではなく、単一の汎用テキスト。
- 適切なimpact例: `"DVWA user data (id, name, level) of all users is readable by any attacker-controlled website via cross-origin requests without authentication. While the data is non-sensitive demo data, in real applications this pattern can expose private user information, PII, or business data."`

**修正方針:** `smart_cors.py` で、actual response bodyに基づくdata-awareなimpactを生成するか、最低でも `wildcard_no_credentials` の場合は「認証なしで読み取れるのは公開相当データに限られる」ことを明記する。

### 2.4 R-18: Expected ResultがCORSと無関係

**現象:** `"入力値検証・出力エンコード・認可チェックにより..."` は入力検証の一般論。CORS Expected Resultは `"信頼されていないOriginに対してAccess-Control-Allow-Originを返さないこと"` であるべき。

**コード根因:**
- `_expected_result_text()` (`haddix_submission_internal_formatter.py:1288-1300`, JA): `xss/sqli/csrf/lfi/ssrf` はエントリあり、`cors/cors_misconfiguration` はなし→汎用default
- `_english_expected_result()` (`haddix_submission_internal_formatter.py:1308-1320`, EN): 同上

**修正:** 両言語の expected result に `cors_misconfiguration` エントリ追加:
```python
# JA: ~line 1298
if "cors" in vtype or "misconfiguration" in vtype:
    return "信頼されていないOriginに対してAccess-Control-Allow-Originヘッダを返さないこと。"
# EN: ~line 1318
if "cors" in vtype or "misconfiguration" in vtype:
    return "Access-Control-Allow-Origin must not be returned for untrusted origins."
```

### 2.5 R-19: 修正後確認手順のロジック誤り

**現象:** `"検知モード phase1 で同手順を再実行し、同じ結果になることを確認する。"` — 修正後は「同じ結果にならない」を確認すべき。

**コード根因:**
- `haddix_formatter.py:1468` (`_verification_steps`):
```python
f"検知モード `{detection_mode}` で同手順を再実行し、同じ結果になることを確認する。"
```
- `"同じ結果になる"` はバグ。正しくは `"脆弱挙動が再現しない"`。
- なお、同じメソッドの後続のEN fallback (`haddix_submission_internal_formatter.py:525`) は正しい: `"confirm the vulnerable behaviour no longer reproduces"`

**修正:** `haddix_formatter.py:1468` の文字列を修正:
```python
f"検知モード `{detection_mode}` で同手順を再実行し、脆弱挙動が再現しないことを確認する。"
```

### 2.6 R-20: Severity過大評価（MEDIUM→LOW/Info）

**現象:** `wildcard_no_credentials` (ACAC空、ACAO:*) が MEDIUM。業界標準では P4-P5 / Informative 扱い。

**コード根因:**
- `smart_cors.py:89`: `sev = Severity.HIGH if str(r.get("acac", "")).lower() == "true" else Severity.MEDIUM`
- `r["misconfiguration"]` の種別 (`wildcard_no_credentials`, `origin_reflection`, `wildcard_with_credentials` 等) を参照していない。
- バイナリ判定: `acac=="true"` → HIGH, それ以外 → MEDIUM

**修正:** `smart_cors.py:89` の severity 判定に misconfiguration種別分岐を導入:
```python
misconf = r.get("misconfiguration", "")
if str(r.get("acac", "")).lower() == "true":
    sev = Severity.HIGH  # with_credentials → high risk
elif misconf == "wildcard_no_credentials":
    sev = Severity.LOW   # wildcard + no creds → public data only
else:
    sev = Severity.MEDIUM
```

この修正は、SGK-2026-0346（Severity normalization backlog）の部分的先行実施となる。

### 2.7 R-21: EN修正案のCORSエントリ欠落

**現象:** JA提出用はCORS固有の修正案あり。EN版は汎用OWASP文言: `"Apply the principle of least privilege. Validate and sanitize all user inputs..."`

**コード根因:**
- JA `_remediation()` (`haddix_formatter.py:1414-1446`): `cors`/`misconfiguration` エントリあり（line 1422-1427）
- EN `_english_remediation_text()` (`haddix_submission_internal_formatter.py:1342-1372`): `xss/sqli/csrf/lfi/ssrf` のみ。corsエントリなし→fallback（line 1369-1372）

**修正:** EN remediation に corsエントリ追加（~line 1367）:
```python
if "cors" in vtype or "misconfiguration" in vtype:
    return (
        "Do not use a wildcard (*) or echo untrusted origins in the "
        "Access-Control-Allow-Origin header. Maintain an explicit allow-list "
        "of trusted origins. When Access-Control-Allow-Credentials is true, "
        "this control must be especially strict."
    )
```

## 3. 変更対象ファイル一覧

| ファイル | 変更内容 | リスク |
|----------|----------|--------|
| `src/core/attack/cors_tester.py` | `CORSResult` に `response_body` 追加、`_test_origin()` で `response.text` 取得 | 低（additive） |
| `src/core/agents/swarm/injection/smart_cors.py` | `Evidence` に `response_body` 設定、severity判定に `misconfiguration`種別分岐追加、poc_html出力継続確認 | 低（論理変更あり、テスト要） |
| `src/reporting/haddix_formatter.py:457` | `reproduction_steps` フォールバック追加 | 低 |
| `src/reporting/haddix_formatter.py:476-485` | `poc_html` 読み取り追加（PoCセクション表示用） | 低 |
| `src/reporting/haddix_formatter.py:1468` | `"同じ結果になる"` → `"再現しない"` (string fix) | 極低 |
| `src/reporting/haddix_submission_internal_formatter.py:1288-1300` | JA expected result: CORSエントリ追加 | 低 |
| `src/reporting/haddix_submission_internal_formatter.py:1308-1320` | EN expected result: CORSエントリ追加 | 低 |
| `src/reporting/haddix_submission_internal_formatter.py:1342-1372` | EN remediation: CORSエントリ追加 | 低 |
| `src/core/models/finding.py` | `CORSResult` dataclass に `response_body` 追加される場合の型注釈確認 | 低 |

## 4. 実装ステップ

### Step 1: detector側の修正（body取得 + severity修正）
- [ ] `cors_tester.py`: `CORSResult` dataclass に `response_body: str` フィールド追加
- [ ] `cors_tester.py:_test_origin()`: response body を取得して `CORSResult` に格納
- [ ] `smart_cors.py`: `Evidence(response_body=...)` に body を設定
- [ ] `smart_cors.py:89`: severity判定に `misconfiguration` 種別分岐を追加（`wildcard_no_credentials→LOW`）
- [ ] `smart_cors.py`: impact 文字列を data-aware に改善（最低限、wildcard_no_credentialsは「認証データは読めない」を明記）

### Step 2: formatter側の修正（表示改善）
- [ ] `haddix_formatter.py:457`: `reproduction_steps` を `steps_to_reproduce` のフォールバックとして読み取り
- [ ] `haddix_formatter.py:476-485`: `additional_info.poc_html` を読み取り、PoCセクションに表示するロジック追加
- [ ] `haddix_formatter.py:1468`: `"同じ結果になる"` → `"再現しない"` 修正
- [ ] `haddix_submission_internal_formatter.py:1288-1300`: JA expected result に `cors_misconfiguration` 追加
- [ ] `haddix_submission_internal_formatter.py:1308-1320`: EN expected result に `cors_misconfiguration` 追加
- [ ] `haddix_submission_internal_formatter.py:1342-1372`: EN remediation に `cors_misconfiguration` 追加

### Step 3: 検証
- [ ] targeted unit tests を実行
- [ ] 同一sessionから新timestamp reportを生成し、7項目が改善されたか目視確認
- [ ] `verify_report_session_consistency.py` で新reportの整合性確認
- [ ] docs validation

## 5. テスト計画

### 5.1 Unit tests
```bash
.venv/bin/pytest -q tests/unit/reporting/test_haddix_submission_internal_sections.py
.venv/bin/pytest -q tests/unit/reporting/test_haddix_ja_en_formatter.py
.venv/bin/pytest -q tests/core/attack/test_cors_tester.py  # 存在する場合
```

追加観点:
- `reproduction_steps` フォールバックが有効か（`steps_to_reproduce` がなく `reproduction_steps` があるdictでテスト）
- `poc_html` がPoCセクションに表示されるか
- `_expected_result_text("cors_misconfiguration")` がCORS固有の文字列を返すか
- `_english_expected_result("cors_misconfiguration")` がCORS固有の文字列を返すか
- `_english_remediation_text` がCORSエントリを返すか（汎用OWASPでないこと）
- `_verification_steps` が `"再現しない"` を含み `"同じ結果になる"` を含まないか
- `SmartCORSHunter` severity: `wildcard_no_credentials→LOW`, `wildcard_with_credentials→HIGH`

### 5.2 Real artifact check
```bash
# 現行レポートの整合性確認（session source path問題を考慮）
python3 scripts/verify_report_session_consistency.py --report \
  /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260713_090445.md
# 新reportの整合性確認（生成後）
```

### 5.3 Docs validation
```bash
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

## 6. 受け入れ条件

- [ ] レポートのCORS Findingに再現手順が4step表示される（`reproduction_steps` 読取成功）
- [ ] PoCセクションに `poc_html` (JS exfil PoC) が表示される
- [ ] PoCセクションにResponse Bodyが表示される（detector側のbody取得が効く場合）
- [ ] Impactが「ブラウザ動作説明」ではなく、具体的なデータ漏洩内容を含む
- [ ] Expected Resultが `"信頼されていないOriginに対してAccess-Control-Allow-Originを返さないこと"` 相当
- [ ] Actual ResultがCORS固有の記述（現状は `finding.summary` から正しく出ている）
- [ ] EN Expected Result が `"Access-Control-Allow-Origin must not be returned for untrusted origins."` 相当
- [ ] EN Remediation がCORS固有のallow-list記述（汎用OWASPでない）
- [ ] 修正後の確認手順が `"同じ結果になる"` ではなく `"再現しない"` になっている
- [ ] SeverityがMEDIUM→LOW（wildcard_no_credentials）
- [ ] 既存のCORS以外のfindingの表示が壊れていない（回帰テストpass）
- [ ] `verify_report_session_consistency.py` が新reportでエラーにならない（少なくともsessionパス問題は追跡）
- [ ] `python3 scripts/validate_shigoku_docs.py` が0エラー

## 7. 既知の制約

1. **Response Bodyの未取得:** detectorを修正しても既存sessionのevidenceは変わらない（再実行が必要）。
   ただし同一endpoint `/vulnerabilities/api/v2/user/` のbodyはC7/C8 finding (`broken_access_control`) に存在。
   今回のformatter修正では `poc_html` を表示し、bodyは「既存sessionからは参照」と注記する。

2. **Severity normalization全体:** 本修正は `wildcard_no_credentials` のみのad-hoc修正。
   全severity normalizationは SGK-2026-0346 (backlog) のスコープ。

3. **Session path問題:** report headerの `/app/workspace/...` はコンテナパス。
   host環境では `consistency checker` がblockedになる。本タスクではhost側pathでsessionを直接参照して調査。
   対策は別タスクで実施。
