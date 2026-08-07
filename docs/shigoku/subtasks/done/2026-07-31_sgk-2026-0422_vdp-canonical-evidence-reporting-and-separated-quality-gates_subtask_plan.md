---
task_id: SGK-2026-0422
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_subtask_plan.md
- docs/shigoku/reports/2026-08-04_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_work_report.md
- docs/shigoku/worklogs/2026-08-04_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_work_log.md
title: VDP canonical evidence reporting and separated quality gates
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/models,src/core/engine,src/reporting,src/main.py,pyproject.toml,uv.lock,scripts,tests
---

# 実装計画書：VDP canonical evidence reporting and separated quality gates

## 1. 達成したいゴール

- [x] sessionに保存された正本レコードから、発見から判定までを同じID系列で追えるレポートを生成する。
- [x] `confirmed`はEvidence Validatorの判定だけを表示し、生findingのラベル、LLM推論、scenario backfill、formatter補完では昇格させない。
- [x] 訓練環境の検知能力gateと、正解が分からない実VDPの実行品質gateを分離する。
- [x] 旧session、旧report reader、既存CLIとの互換性を維持する。
- [x] reportingを読み取り専用に保ち、レポート生成中の追加通信やtask queue操作を禁止する。
- [x] `confirmed`の検証proofをversion付き正規形へ固定し、EvidenceRecordの内容とEvidence Validatorの正規判定に結合する。
- [x] 署名機能をEvidence Validator境界へ限定し、任意callerや任意validator名から`confirmed`を生成できない構造にする。

## 2. 責務境界とデータの流れ

    session records
          |
          v
    canonical extractor
          |
          v
    immutable EvidenceVerdict summary (source_kind=canonical_vdp|legacy)
          |
          +------------------+
          |                  |
          v                  v
    report projection    quality gates
    (vdp_canonical_index_v1 出力)

- engineはHypothesisRecord、AttemptRecord、EvidenceRecord、EvidenceVerdict、NextActionRecordを保存する。
- Evidence Validator（`src/core/engine/vdp_evidence_validator.py`）はengine時間に実行する。呼出点はVDP follow-up dispatch（`_dispatch_vdp_follow_up`）の `result.status == "executed"` かつEvidenceRecord保存成功後の**1箇所のみ**。degraded/backpressure経路では署名しない。
- EvidenceVerdictは**upsert**する。同一verdict_id・同一hypothesisに重複verdictを作成せず、candidate→confirmedの置換を明示する。signer利用不能時はcandidate/untestedと運用Holdを記録する。
- canonical extractorは新旧schemaを読み、同じ正規形（source_kind付き）へ変換する。証拠を生成、推測、補完しない。
- report formatterは正規形を日本語・英語・機械可読JSONへ投影するだけとする。全formatterは**同一serializerから `vdp_canonical_index_v1`**（source_kind、verdict集合・件数、evidence ID/hash、summary digest）を出力する。
- gateは同じ正規形を読む。formatterごとの独自再判定を廃止し、表示と判定の食い違いを防ぐ。
- NextActionの決定はengine側で完了させ、reportingは表示のみを行う。
- reporting/gate/CLIはengineモジュール（`vdp_evidence_validator.py` / `vdp_legacy_proof_verifier.py`）をimportしない。旧HMACをreportingで検証できない場合は `legacy_proof_unverifiable` としてconfirmedに数えない。

## 3. 対象コンポーネント

- `src/core/models/vdp_contract.py`: version付きproof payloadの正規形、canonical直列化、**検証専用API**（public key検証、content hash照合）。署名factory（現行 `_create_confirmed_verdict`）とHMAC署名関数はengine validatorへ移設し、model層に署名・秘密鍵を残さない。
- `src/core/engine/vdp_evidence_validator.py`（新規）: 正本Evidence Validator。**Ed25519署名provider（private keyはここだけ）**、confirmed factory、EvidenceRecordからのcontent hash内部計算。VDP follow-up dispatch成功後の単一呼出点からのみ実行。
- `src/core/engine/vdp_legacy_proof_verifier.py`（新規）: 旧HMAC proofの**検証専用**compatibility verifier。reporting/gate/CLIはこのengineモジュールをimportしない。検証鍵なしは `legacy_proof_unverifiable` でfail-closed。
- `src/reporting/finding_extractor.py`: 正本抽出（canonical_vdp / legacy 二経路）、schema version判定、旧session互換。
- `src/reporting/haddix_evidence_quality.py`: 旧session用legacy互換ロジック（engineからimportしない）。
- `src/reporting/haddix_formatter.py`: 英語report projection（canonical summary + `vdp_canonical_index_v1` 出力）。
- `src/reporting/haddix_submission_internal_formatter.py`: submission/internal投影（canonical summary消費 + `vdp_canonical_index_v1` 出力、manifest付き複数ファイル保存）。既存の独自再判定（`_get_enforced_split`）はcanonical verdict読取へ置換。
- `src/reporting/haddix_ja_en_formatter.py`: 日本語/英語表示の意味一致（canonical summary消費）。
- `src/reporting/vdp_gates.py`（新規）: training capability gate / real VDP run-quality gateの分離実装。
- `src/reporting/report_session_consistency.py`: `vdp_canonical_index_v1` とsessionの機械比較（verdict件数・ID集合・evidence hash）。
- `src/main.py`: report/session artifact生成と終了状態の受渡し（os.replaceによる原子保存）。
- `pyproject.toml` / `uv.lock`: `cryptography==46.0.4` を直接依存として追加し、`uv lock --offline` でlockを同期する。既にuv.lockに解決済み（pygithub→pyjwt→cryptographyチェーン）の直接依存化であり、新規パッケージ追加ではない。別の暗号ライブラリは追加しない。
- `scripts/check_initial_release_gate.py`: gate profile分離（`--profile legacy|vdp-training|vdp-real`）と機械可読結果。
- `scripts/verify_report_session_consistency.py`: ID、件数、hash、timestamp、backfill区分の整合性確認。
- `scripts/shigoku_ops_cli.py`: report/session/validate操作の正規入口、`vdp gate` サブコマンド追加。
- `tests/`: extractor、validator、proof、formatter、gate、consistency、旧artifact回帰試験。

対象シンボルは実装開始時に参照元を再検索し、既存のpublic APIとschema readerを確認してから確定する。

## 4. 正本表示仕様

### 4.1 ファネル

reportは最低限、次を同じID系列で集計・明細表示する。

1. observations: 何を観測したか。
2. hypotheses: どの脆弱性仮説へ変換したか。
3. attempted: 実際に何を送信したか。
4. responded: どの応答または外部signalを得たか。
5. followed_up: 何の不足証拠を埋めたか。
6. confirmed/refuted: 何を根拠に確定または反証したか。
7. untested: なぜ最後まで検証できなかったか。

各段階は単純件数だけでなく、前段から脱落した理由コードを表示する。task成功数やcoverageだけを脆弱性検知成功として表示しない。

### 4.2 証拠の区分

- raw observation: 実送信・実応答・OOB・browser・readbackなどの直接証拠。
- derived normalization: hash、差分、正規化、相関など再現可能な派生値。
- backfill: scenario coverage等からreport時に補われた情報。
- inference: LLMまたはheuristicによる解釈。

backfillとinferenceはraw evidenceから視覚的・機械的に分離し、confirmedの必要証拠として数えない。EvidenceRecordにないresponseやpayloadをreport本文で作らない。

### 4.3 重複排除と追跡

- 重複キーはvulnerability classだけでなく、asset、endpoint/action、actor、trust boundary、evidence fingerprintを含む。
- 同じ仮説への再試行は別AttemptRecordとして残し、同じfindingへ雑に上書きしない。
- 集約後も元のhypothesis_id、attempt_id、evidence_id、verdict_idへ逆参照できる。
- 確定・反証・未検証を相互排他的に扱い、同一verdictを複数区分へ二重計上しない。
- `AttemptRecord.trigger_next_action_id: str = ""` をadditive追加し、`_dispatch_vdp_follow_up` で `spec["next_action_id"]` から設定してAttemptRecord生成時に格納する。旧session・旧recordは空文字へdefaultする。これによりNextAction→Attempt→Evidence→VerdictのID系列をreport明細から追跡できる（G1の「同じID系列で追えるreport」に必須）。

### 4.3.1 Observation欠損時の表示仕様

- sessionにObservationRecordが存在しない場合、reportは観測本文を生成・推測しない。
- 既存のobservation_idとprovenance（observation_ids、source、freshness等、保存済みの範囲）だけを表示する。
- 内容欠損は `observation_content_unavailable` 等のcompatibility reasonで明示する（「EvidenceRecordにない内容を作らない」安全境界の具体化）。

### 4.4 confirmed proofの正規化と署名境界

- 文字列の区切り記号連結は使わず、version付きcanonical JSON等の一意な直列化を使う。field名、型、配列順序、文字コード、欠損値の扱いを仕様とfixtureで固定する。
- 署名対象には少なくともproof schema version、verdict_id、hypothesis_id、`status=confirmed`、reason codes、validator version、EvidenceRecordごとのevidence_id・evidence_type・content hashを含める。
- evidence_idだけでなくEvidenceRecordの内容hashを結合し、proof作成後に証拠本文、hash、reason code、validator version、statusのいずれかが変われば検証を拒否する。
- Evidence Validatorは正本EvidenceRecordを検証し終えた後だけproofを発行する。callerが渡したvalidator名や`status=confirmed`を信用して署名してはならない。
- model層（vdp_contract.py）はproofの検証だけを担当し、汎用の署名関数や秘密鍵を公開しない。署名providerはengine層のEvidence Validator（`vdp_evidence_validator.py`）からのみ利用できる依存境界に置く。
- 旧proofはschema versionごとに明示的に扱う。旧HMACは`vdp_legacy_proof_verifier.py`（engine層）の検証専用compatibility verifierで処理し、検証できない旧confirmedを黙って維持またはcandidateへ変換せず、互換性reason付きでfail-closedにする。reporting/gate/CLIへHMAC secretを渡さない。

#### 4.4.1 proofバイト仕様（fixtureで固定）

- `validation_proof` は64-byte Ed25519署名のBase64URL（paddingなし）とし、`ed25519:<proof_key_id>:<base64url>` 形式で保持する。
- `evidence_content_sha256` は `field(default_factory=dict)` で保持し、evidence_idをキー、`sha256(canonical_json_bytes(EvidenceRecordV1.to_dict()))` のhexを値とする。
- signerはEvidenceRecordからcontent hashを**内部計算**する。callerが渡したhashを信用しない。
- `evaluated_evidence_ids` と `evidence_content_sha256` のkey集合は完全一致すること。欠損・余分なEvidenceRecordも検証失敗とする。
- callerがvalidator名や`status=confirmed`を指定して署名することはできない。`status`変更も必ず検証失敗とする。

## 5. gateの分離

### 5.1 training capability gate

ラベル付きfixtureまたは許可済み訓練環境でのみ使用する。

- 脆弱性クラス別recall。
- false promotion rate。
- evidence completeness。
- hypothesisからfollow-upまでの到達率。
- 対象固有情報をruntimeへ漏らしていないこと。

既知ラベルは評価処理だけが読み、runtime入力やprompt、recipe選択、優先順位には渡さない。

### 5.2 real VDP run-quality gate

未知の実VDPでは`confirmed_min`や推測recallを合否条件にしない。次を独立評価する。

- scopeとProgramCapabilityMatrixの適用結果。
- 発見面、trust boundary、actor、capabilityの探索範囲。
- 未検証率と理由コードの完全性。
- 証拠channel停止、予算枯渇、queue失敗などinfra由来の欠落。
- unsafe action提案、HITL bypass、scope逸脱、secret漏洩の有無。
- report/session整合性とrun終了状態。

候補件数だけでFAILにしたり、確定件数を満たすために候補を抑制・昇格したりしない。結果はPass/Failだけでなく、Go/Hold/No-Goの根拠をJSONで返す。

### 5.3 gate CLI仕様（一意確定）

- `shigoku-ops vdp gate --profile training --session <path> --labels <fixture-manifest>`: training capability gate。`--labels` はtrainingで**必須**（recall・false promotion rateの計算に使用）。ラベルは評価器だけが読み、runtime入力・prompt・recipe・優先順位へ渡さない。
- `shigoku-ops vdp gate --profile real --session <path> [--report <path>]`: real VDP run-quality gate。`--report` 指定時はconsistencyがconsistentの場合だけ続行する。
- 共通JSONは `status: pass|fail|blocked` を返す。real profileのみ `decision: go|hold|no_go` を追加する。exit codeは 0=pass/go、2=blocked/hold/入力不足、3=fail/no_go。
- real profileは `confirmed_min` / `candidate_max` を参照しない。既存 `shigoku-ops report gate` のデフォルト動作・引数・exit codeは変更しない。
- `scripts/check_initial_release_gate.py` には `--profile legacy|vdp-training|vdp-real` をadditive追加し、既定値は `legacy`（現行挙動と同一）。

## 6. 実装ステップ

0. `cryptography==46.0.4` を `pyproject.toml` の直接依存へ追加し、`uv lock --offline` でlockを同期する（既にuv.lockに解決済みの直接依存化であり、新規パッケージ追加ではない。別の暗号ライブラリは追加しない）。検証: `.venv/bin/python -c "import cryptography; print(cryptography.__version__)"` が `46.0.4` を出力すること。
1. 既存extractor、formatter、gate、consistency checkerの全readerとfield参照を検索し、互換性表を作る。
2. SGK-2026-0419のversion付きrecordを読むcanonical extractorを追加し、旧sessionは明示的なdefaultとcompatibility reasonで正規化する。
3. Evidence Validator出力を唯一のconfirmed sourceとして固定する。
   1. version付きcanonical proof payloadと直列化fixtureを定義し、区切り文字衝突や型の曖昧さを排除する。
   2. EvidenceRecordのcontent hash（全保存field由来）、reason codes、validator versionをproofへ結合する。
   3. 署名providerをengine層 `vdp_evidence_validator.py` へ移し、model層とreporting層は検証専用にする。旧HMAC検証は `vdp_legacy_proof_verifier.py` へ隔離する。
   4. report側の再判定、任意validator名による署名、暗黙昇格を除去する。
   5. Validatorの呼出点を `_dispatch_vdp_follow_up` の `result.status == "executed"` かつEvidenceRecord保存成功後の**単一箇所**に固定し、degraded/backpressure経路では署名しない。verdictはupsert（同一verdict_id・同一hypothesis重複禁止、candidate→confirmed置換を明示）。signer利用不能時はcandidate/untestedと運用Holdを記録する。
4. ファネル、脱落理由、raw/derived/backfill/inference区分、実行予算、依存状態、終了状態をreportとJSONへ追加する。全formatterは同一serializerから `vdp_canonical_index_v1`（source_kind、verdict集合・件数、evidence ID/hash、summary digest）を出力する。
5. training capability gateとreal VDP run-quality gateをprofileとして分離し、CLI（`vdp gate --profile training|real`、trainingは `--labels` 必須）で対象profileと判定根拠を表示する。
6. 旧artifact、現行artifact、新schema artifactでformatter間の意味一致、gate一致、report/session consistencyを検証する。consistency checkerは `vdp_canonical_index_v1` とsessionを機械比較し、人間向けMarkdownの正規表現解析だけに依存しない。separated 3ファイルは全temp生成・全検証後にos.replaceで昇格し、完了manifestを最後に書く。

## 7. 必須テスト

- unit: schema version分岐、旧field default、理由コード、重複排除、相互排他、secret非表示。
- unit: 生findingが`confirmed`でもEvidenceVerdictがない場合は確定表示しない。
- unit: backfill/inferenceだけではconfirmedにならない。
- unit: report生成がqueue、network、browser、OOBを呼ばない。
- unit: 区切り文字を含むID、Unicode、配列順序、型違いがcanonical payloadで衝突しない。
- unit: EvidenceRecord本文（全保存field）・hash、reason code、validator version、statusの改変後はproof検証が失敗する。
- unit: proof欠損、未知proof version、未知key ID、任意validator名、Evidence Validator以外の署名経路を拒否する。
- unit: `evaluated_evidence_ids` と `evidence_content_sha256` のkey集合不一致、EvidenceRecord欠損・余分追加で検証失敗する。
- unit: Validator呼出が `result.status=="executed"` かつEvidenceRecord保存成功後の単一呼出点でのみ実行され、degraded/backpressure経路では署名されない。
- unit: 同一verdict_id・同一hypothesisへの重複verdict追加がなく（upsert）、candidate→confirmedの置換が明示される。signer利用不能時はcandidate/untestedと運用Holdが記録され、confirmedへ昇格しない。
- unit: training gateは `--labels` 必須で、ラベルがruntime入力・prompt・recipe・優先順位へ漏れない。
- unit: `vdp_canonical_index_v1` が全formatterで同一serializerから出力され、consistency checkerがindexとsessionを機械比較できる（verdict件数・ID集合・evidence ID/hash・summary digest）。
- unit: `AttemptRecord.trigger_next_action_id` が `_dispatch_vdp_follow_up` の `spec["next_action_id"]` から設定され、旧session・旧recordでは空文字へdefaultされる。NextAction→Attempt→Evidence→VerdictのID系列がreport明細から追跡できる（G1対応）。
- unit: ObservationRecord欠損時に観測本文を生成・推測せず、observation_id/provenanceのみ表示し、`observation_content_unavailable` 等のcompatibility reasonで欠損を明示する。
- unit: separated 3ファイルはmanifest存在・3ファイル存在・manifest記載hash一致を検証し、途中失敗時はmanifestなしファイル群を正式成果物として扱わない。
- 構造: reporting/gate/CLIがengineモジュール（`vdp_evidence_validator.py` / `vdp_legacy_proof_verifier.py`）をimportしない（production import走査）。
- integration: observationからverdictまでのIDがreport明細と一致する。
- integration: 正本Evidence Validatorだけがproof付きconfirmedを生成し、session保存、別process復元、report投影まで同じverdictを維持する。
- integration: training/real VDP profileが同じartifactに異なる目的の判定を適切に返す（realはgo/hold/no_go、trainingはlabels必須）。
- compatibility: 旧sessionの未知field、欠損field、古いreason codeを安全に読む。旧HMAC proofは専用verifierで処理され、検証鍵なしは `legacy_proof_unverifiable` でfail-closed。
- real artifact: `shigoku-ops`経由でreport/session consistencyとinitial gate（legacy profile）を実行する。

## 8. 障害時の動作

| 状況 | 動作 |
|---|---|
| EvidenceVerdict欠損 | candidateまたはuntestedへfail-closedし、欠損理由を表示 |
| report/session不一致 | gateをNo-Goとし、推測で集計しない |
| 旧sessionの未知field | 無視したfieldとreader versionを監査情報へ残す |
| formatter例外 | 元sessionを変更せず、tempを削除し、部分reportを正式成果物にしない |
| backfillのみ存在 | backfill区分で表示しraw finding件数へ加算しない |
| secret検出 | report保存を止め、redaction failureとしてNo-Go |
| proof payloadまたはEvidenceRecord改変 | confirmedとして読まず、tamper reason付きNo-Go |
| signerまたは検証鍵が利用不能 | confirmedへ昇格せず、candidate/untestedと運用Holdを分離表示 |
| 旧HMAC検証鍵なし | `legacy_proof_unverifiable` でfail-closed。confirmedに数えず、candidate相当で互換性reason付き表示 |
| separated 3ファイルの途中失敗 | manifestなしのファイル群を正式成果物として扱わない。tempを削除し、manifestを書かない |

## 9. 完了条件

- 一つのsessionから各formatterとgateが同じconfirmed/candidate/refuted/untested集合を導く。
- confirmed全件がEvidenceVerdictと必要EvidenceRecordへ逆参照できる。
- report生成による追加通信、queue投入、session書換えが0件である。
- training gateとreal VDP gateの入力、指標、合否理由が混在しない（trainingはlabels必須、realはgo/hold/no_go）。
- 旧artifact回帰試験と実artifact整合性確認が合格する（legacy profileは現行initial gate挙動と同一）。
- 秘密値の平文出力と理由不明confirmedが0件である。
- canonical proofの衝突、EvidenceRecord改変後の検証成功、Evidence Validator以外からのconfirmed生成がすべて0件である。
- 正規のconfirmedが別processで復元でき、proof/version/key不明時は理由付きでfail-closedになる。
- 全formatterが同一serializerから `vdp_canonical_index_v1` を出力し、consistency checkerがindexとsessionの機械比較でconsistentとなる。
- separated 3ファイルはmanifest検証（manifest存在・3ファイル存在・hash一致）を通過した場合のみ正式成果物とみなされる。

## 10. NOT in scope

- 確定件数を増やすための閾値緩和、severity変更、候補削除。
- 特定製品の既知の正解、URL、payloadを利用したreport補正。
- report formatterからのfollow-up生成または能動通信。
- 実VDPへの攻撃実行。
- 確認鍵の本番配布、権限、ローテーション、失効、secret store運用（SGK-2026-0423で扱う）。

## 11. 付録: プリフライトB/C表（監査版）

### 11.1 B表: session field → writer / reader / formatter・gate・CLI / legacy default

| session field | writer | reader symbol | formatter/gate/CLI | legacy default |
|---|---|---|---|---|
| `vdp_contract.vdp_contract_version` | `master_conductor_session_service.inject_vdp_section_to_session_payload` L289-290, `vdp_session_reader.inject_vdp_fields` L30 | `vdp_m0_gate.VdpM0ContractGate.validate` L126-146, `vdp_session_reader.read_session_compat` L178 | extractor（schema version分岐） | `VDP_CONTRACT_SCHEMA_VERSION=1` |
| `vdp_contract.vdp_active` | `master_conductor_session_service` L287-291 | `vdp_m0_gate.validate` L149-174, `master_conductor` L3957 | extractor（inactive判定）、M0 gate | `False` |
| `vdp_contract.hypotheses` | `master_conductor._generate_vdp_hypotheses` L11018 | `vdp_m0_gate.validate` L179,196, `master_conductor._queue_vdp_follow_ups` L11231 | extractor（ファネル仮説） | `[]` |
| `vdp_contract.attempts` | `master_conductor._dispatch_vdp_follow_up` L11444-11450 | `vdp_m0_gate.validate` L180,197 | extractor（ファネルattempted） | `[]` |
| `vdp_contract.evidence_records` | `master_conductor` L11451-11457, `vdp_follow_up_executor` L477 | `vdp_m0_gate.validate` L181,198 | extractor（responded）、validator（content hash） | `[]` |
| `vdp_contract.verdicts` | `master_conductor` L11023（candidate）、0422: `vdp_evidence_validator`（upsert） | `vdp_m0_gate._parse_strict_verdicts` L201,327-352、`vdp_contract._restore_confirmed_from_dict` L1149 | extractor（confirmed/candidate/refuted/untested） | `[]` |
| `vdp_contract.next_actions` | `master_conductor` L11024、`vdp_follow_up.build_next_action_record` L487 | `vdp_m0_gate.validate` L183,202、`master_conductor` L11262 | extractor（followed_up/untested理由） | `[]` |
| `vdp_contract.budget_snapshot` | `master_conductor` L11458 | `vdp_m0_gate.validate` L168 | extractor（実行予算） | `{}` |
| `vdp_contract.run_health` | `master_conductor._set_vdp_run_health_*` L11574 | `vdp_m0_gate.validate` L168 | extractor（終了状態） | `{}` |
| `AttemptRecord.trigger_next_action_id`（0422 additive） | `master_conductor._dispatch_vdp_follow_up`（`spec["next_action_id"]`から設定） | `vdp_contract.AttemptRecord.from_dict`（additive） | extractor（NextAction→Attempt追跡） | `""` |
| `validation_proof` / `evaluated_evidence_ids` / `validator_version` | 0422: `vdp_evidence_validator`（現行: `vdp_contract._create_confirmed_verdict` L1219） | `vdp_contract._restore_confirmed_from_dict` L1149-1202、`vdp_m0_gate` L344 | extractor（proof検証）、M0 gate | `""` / `[]` / `""` |
| `proof_schema_version` / `proof_key_id` / `evidence_content_sha256`（0422 additive） | 0422: `vdp_evidence_validator` | 0422: `vdp_contract.verify_confirmed_verdict` | extractor、consistency（hash照合） | `""` / `""` / `{}` |
| `completed_tasks[*].result(.data).findings/finding/vulnerability` | engine各agent | `finding_extractor.extract_all_findings` L37-87、`main._extract_findings_and_execution_notes` L711、`session_finding_inspector` L109 | formatter3つ（legacy経路）、gate `_build_session_findings_summary` L402 | `[]` |
| `findings` / `partial_findings`（fallback） | legacy | `finding_extractor` L91-99、`main` L787-792 | legacy formatter経路 | `[]` |
| `scenario_coverage` / `context.scenario_coverage` | engine | `report_session_consistency._extract_session_scenario_coverage` L247、`initial_release_gate._load_session_scenario_coverage` L378 | consistency/gate既存比較 | `{}` |
| `context.coverage_gate.missing_families` | engine | `report_session_consistency._extract_session_missing_families` L293 | consistency | `[]` |
| `task_execution_records[*].vulnerabilities_found`（旧） | `task_execution_log` L47-172 | `target_profile_formatter` L343,665 | legacy表示 | `[]` |
| `shadow_decisions` | `src/core/models/swarm.py` L41 | `reader_compatibility` L109 | —（監査情報のみ） | `[]` |
| `vdp_canonical_index_v1`（0422新規） | 全formatter（同一serializer） | 0422: `report_session_consistency`（機械比較） | gate/CLI | 不在→compat reason |

### 11.2 C表: 計画書項目 → 実装ファイル → test名 → 実行コマンド → 合格条件

**ゴール（G1-G7）**

| 項目 | 実装ファイル | test名 | 実行コマンド | 合格条件 |
|---|---|---|---|---|
| G1 同ID系列report | `finding_extractor.py`, `haddix_formatter.py`, `haddix_submission_internal_formatter.py`, `haddix_ja_en_formatter.py` | `test_funnel_ids_match_report_detail`（新規 integration） | `.venv/bin/pytest tests/unit/reporting/test_vdp_canonical_extractor.py -q` | observation→verdictのIDがreport明細と一致 |
| G2 confirmedはValidator判定のみ | `vdp_evidence_validator.py`, formatter3つ, extractor | `test_raw_confirmed_finding_without_verdict_not_displayed`, `test_backfill_and_inference_not_confirmed` | 同左 | 生finding/backfill/inferenceでconfirmed表示されない |
| G3 gate分離 | `vdp_gates.py`（新規）, `shigoku_ops_cli.py`, `check_initial_release_gate.py` | `test_vdp_gate_profiles_independent_verdicts` | `.venv/bin/pytest tests/unit/reporting/test_vdp_gates.py tests/unit/scripts/test_shigoku_ops_cli.py -q` | training/realが同一artifactに異なる判定 |
| G4 旧session/旧CLI互換 | reader全般（additive）, CLI既存不変 | `test_legacy_session_unknown_missing_fields_safe_read`, `test_legacy_report_gate_golden` | 同左 + `tests/unit/reporting/test_initial_release_gate.py` | 旧artifactで現行挙動維持 |
| G5 reporting読み取り専用 | `vdp_evidence_validator.py`（engine）, formatter | `test_report_generation_zero_network_and_queue` | 同左 | socket 0接続・queue/書換え0 |
| G6 proof正規形+内容結合 | `vdp_contract.py`（検証API）, `vdp_evidence_validator.py`（署名） | `test_canonical_proof_payload_no_collision`, `test_proof_rejects_evidence_record_tamper` | `.venv/bin/pytest tests/unit/engine/test_vdp_proof.py -q` | 衝突0・改変後検証失敗 |
| G7 署名境界限定 | `vdp_evidence_validator.py`, 構造テスト | `test_non_validator_signing_path_rejected`, `test_reporting_no_private_key_import`（新規走査） | `.venv/bin/pytest tests/unit/engine/test_vdp_real_integration.py -q` | 他経路confirmed生成0 |

**実装ステップ（S0-S6）**

| 項目 | 実装ファイル | test名 | 実行コマンド | 合格条件 |
|---|---|---|---|---|
| S0 依存直接化 | `pyproject.toml`, `uv.lock` | —（import check） | `uv lock --offline` → `.venv/bin/python -c "import cryptography; print(cryptography.__version__)"` | `46.0.4` を出力 |
| S1 互換性表 | —（本監査B表） | — | — | B表完成 |
| S2 canonical extractor | `finding_extractor.py`, `vdp_canonical.py`（summary型・新規） | `test_canonical_extractor_schema_version_branch` | `.venv/bin/pytest tests/unit/reporting/test_vdp_canonical_extractor.py -q` | 新旧schema正規化 |
| S3 Validator唯一化 | `vdp_contract.py`, `vdp_evidence_validator.py`, `vdp_legacy_proof_verifier.py`, formatter3つ | proof 5テスト + `test_engine_validator_sole_confirmed_source_roundtrip` | `.venv/bin/pytest tests/unit/engine/test_vdp_proof.py tests/unit/engine/test_vdp_evidence_validator.py -q` | confirmed生成がvalidatorのみ |
| S4 ファネル+index | summary型 + formatter3つ | `test_vdp_canonical_index_v1_formatters_match` | `.venv/bin/pytest tests/unit/reporting/test_vdp_consistency_index.py -q` | indexが全formatter一致 |
| S5 gate profile+CLI | `vdp_gates.py`, CLI2ファイル | `test_vdp_gate_cli_args_json_exit_codes` | `.venv/bin/pytest tests/unit/scripts/test_shigoku_ops_cli.py -q` | 引数/JSON/exit code仕様一致 |
| S6 artifact検証+manifest | consistency, 保存方式 | `test_manifest_required_for_official_artifacts` + real artifact実行 | `.venv/bin/shigoku-ops --json report consistency --report <実artifact>` | legacy実artifact整合 |

**必須テスト（§7・T1-T21）** — 上記§7の各項目と対応する新規テストファイル: `test_vdp_proof.py`（T5-8）、`test_vdp_evidence_validator.py`（T9-10, 16）、`test_vdp_legacy_proof_verifier.py`（T20）、`test_vdp_canonical_extractor.py`（T1-4, 13-14, 17）、`test_vdp_gates.py`（T11, 19）、`test_vdp_consistency_index.py`（T12）、`test_vdp_report_save_manifest.py`（T15）、既存拡張: `test_vdp_real_integration.py`（T18）、`test_haddix_*` / `test_initial_release_gate.py` / `test_report_session_consistency.py` / `test_shigoku_ops_cli.py`（回帰）。実行コマンドは各ファイルの `.venv/bin/pytest <file> -q`、合格条件は§7の記述どおり（proof改変・key集合不一致・degraded無署名・labels必須・index一致・manifest検証・engine import 0）。

**障害時動作（F1-F10）→ テスト対応**: EvidenceVerdict欠損=`test_missing_verdict_fails_closed_to_candidate_untested`、report/session不一致=`test_consistency_inconsistent_gate_no_go`、旧session未知field=`test_legacy_session_unknown_missing_fields_safe_read`、formatter例外=`test_formatter_failure_no_partial_report_promoted`、backfillのみ=`test_backfill_and_inference_not_confirmed`、secret検出=`test_secret_detected_report_save_stopped`、proof/EvidenceRecord改変=`test_proof_rejects_evidence_record_tamper`、signer/鍵不能=`test_signer_unavailable_no_promotion_hold`、旧HMAC鍵なし=`test_legacy_hmac_unverifiable_fail_closed`、3ファイル途中失敗=`test_partial_file_set_without_manifest_not_official`（新規・`test_vdp_report_save_manifest.py`）。

**完了条件（D1-D10）→ 根拠テスト**: D1=`test_funnel_ids_match_report_detail` + formatter/gate一致、D2=`test_confirmed_backreference_complete`、D3=`test_report_generation_zero_network_and_queue` + mtime不変、D4=`test_vdp_gate_profiles_independent_verdicts`、D5=legacy golden + real artifact実行、D6=`test_canonical_summary_secret_free` + `test_no_unexplained_confirmed`、D7=proof 3テスト（衝突・改変・他経路）、D8=`test_engine_validator_sole_confirmed_source_roundtrip` + `test_proof_missing_unknown_version_unknown_key_rejected`、D9=`test_vdp_canonical_index_v1_formatters_match` + consistency実実行、D10=`test_manifest_required_for_official_artifacts`。

**NOT in scope（N1-N5）**: 変更なし・監査確認のみ。
