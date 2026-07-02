---
task_id: SGK-2026-0054
doc_type: plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-14'
updated_at: '2026-07-02'
---

# CRAPI + JuiceShop + DVWA 安定性プラン v3 (Auth-Aware / Anti-Curve-Fit)

## 1. 目的
- `SCN01-07` の再現性を上げる。
- ただし CRAPI だけに合わせ込むカーブフィットはしない。
- 判定は単発成功ではなく、複数 run の再現率で行う。

## 2. このターンで確定した前提
- CRAPI: 認証トークンが必要（ユーザー提供済み）。
- DVWA: 認証 Cookie が必要（`PHPSESSID`。`security=low` も付与推奨）。
- 評価対象は 3 ターゲット:
  - CRAPI
  - Juice Shop
  - DVWA

## 3. 非交渉ガードレール（反カーブフィット）
- `src/` にターゲット固有分岐（`if target==crapi` など）を入れない。
- ヒューリスティック重みの閾値は 3 ターゲットで共通にする。
- 採用判定は CRAPI 単独で行わない（3ターゲット同時判定）。
- 認証情報はコードやGit管理ファイルへ直書きしない（環境変数のみ）。

## 4. 認証運用（実行時のみ）
### 4.1 変数定義（ローカルシェル）
```bash
# ユーザーから受け取った値をそのままローカル環境に設定（ファイルへ保存しない）
export CRAPI_BEARER_TOKEN='<provided-by-user>'
export CRAPI_COOKIE='<provided-by-user-if-required>'
export DVWA_COOKIE='PHPSESSID=<provided-by-user>; security=low'
```

### 4.2 DVWA Cookieの更新方針
- `PHPSESSID` は失効し得るため、失敗時は更新して再実行する。
- 必要なら `scripts/get_dvwa_cookie.py` で再取得して差し替える。

### 4.3 CRAPI 認証の扱い
- `--bearer-token` と `--cookie` を同時付与できる形で運用する。
- このターンでは「CRAPIもCookie必要」という前提で進める。

## 5. 実行フェーズ
### Phase A: Auth疎通確認（各ターゲット 1 run）
- 目的: 「認証が通る状態」をまず確定する。
- 条件:
  - report consistency が `consistent`
  - 明確な auth failure（401/403 固定）で詰まっていない

### Phase B: 本評価（今回の最短）
- CRAPI: 5 run
- Juice Shop: 2 run
- DVWA: 2 run
- すべて同一の重み付け設定で実行する（ターゲット別の閾値変更なし）。

### Phase C: 採用前の最終安定確認
- Phase B を通過したら、Juice Shop と DVWA も 5 run に拡張して最終判定する。
- これで「3ターゲットで安定」と言える状態にする。

## 6. 実行テンプレート（CLI-First）
```bash
cd /home/bbb/Documents/App/Shigoku

# CRAPI (5 run)
TARGET_URL='http://127.0.0.1:8888' \
PROJECT_KEY='crapi_auth' \
RUN_COUNT=5 \
PROFILE_ID='P2' \
SCAN_CMD=".venv/bin/python -m src.main --target http://127.0.0.1:8888 --mode bugbounty --bearer-token ${CRAPI_BEARER_TOKEN} --cookie '${CRAPI_COOKIE}'" \
bash scripts/bench/run_scn01_07_p0_5runs.sh

# Juice Shop (2 run)
TARGET_URL='http://127.0.0.1:3000' \
PROJECT_KEY='juiceshop' \
RUN_COUNT=2 \
PROFILE_ID='P2' \
SCAN_CMD=".venv/bin/python -m src.main --target http://127.0.0.1:3000 --mode bugbounty" \
bash scripts/bench/run_scn01_07_p0_5runs.sh

# DVWA (2 run)
TARGET_URL='http://127.0.0.1:4280' \
PROJECT_KEY='dvwa_auth' \
RUN_COUNT=2 \
PROFILE_ID='P2' \
SCAN_CMD=".venv/bin/python -m src.main --target http://127.0.0.1:4280 --mode bugbounty --cookie '${DVWA_COOKIE}'" \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

## 7. 判定（Go / No-Go）
### Go（Phase B の暫定）
- CRAPI:
  - `confirmed>=3` が 5 run 中 4 run 以上
  - required classes (`access_control, idor_bola, mass_assignment, endpoint_bfla`) が 5 run 中 4 run 以上
- Juice Shop / DVWA:
  - consistency が 2/2 `consistent`
  - gate fail が連続しない（少なくとも 1/2 は pass）

### Go（最終採用）
- CRAPI / Juice Shop / DVWA の 3ターゲットすべてで 5 run 評価を実施
- 3ターゲットで現行比の悪化が許容範囲内（gate pass rate 悪化 5%以内）

### No-Go
- CRAPIだけ改善し、非CRAPIで明確悪化
- auth失効で結果が揺れる状態を放置
- target固有条件を `src/` ロジックに混入

## 8. 失敗時のリカバリ順
1. 認証情報更新（DVWA Cookie再取得、CRAPI Token再確認）
2. 同一 run 条件で再実行（設定を変えずに再現確認）
3. それでも失敗なら重み付け変更ではなく、まず execution_notes 欠落/ゲート理由を修正

## 9. 検証コマンド（各 report ごと）
```bash
# consistency
.venv/bin/shigoku-ops --json report consistency --report <absolute-haddix-report-path>

# gate
.venv/bin/shigoku-ops --json report gate \
  --report <absolute-haddix-report-path> \
  --allowed-missing scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology \
  --required-confirmed-classes access_control,idor_bola,mass_assignment,endpoint_bfla \
  --required-class-confirmed-min 1 \
  --confirmed-min 3 \
  --candidate-max 2 \
  --confirmed-poc-missing-max 0 \
  --reason-code-missing-max 0
```

## 10. このv3の意図
- CRAPI 認証あり前提を吸収しつつ、非CRAPI同時評価で過学習を防ぐ。
- 2 run は「採用前の短距離チェック」、最終採用は 3ターゲット 5 run で締める。
