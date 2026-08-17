---
task_id: SGK-2026-0453
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0452_safe-sqli-impact-demonstration.md
- docs/shigoku/reports/2026-08-16_sgk-2026-0452_safe-sqli-impact-demonstration_work_report.md
- docs/shigoku/reports/2026-08-18_sgk-2026-0453_sqli-impact-demonstration-defense-evasion_work_report.md
- docs/shigoku/worklogs/2026-08-18_sgk-2026-0453_sqli-impact-demonstration-defense-evasion_work_log.md
created_at: '2026-08-16'
updated_at: '2026-08-18'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
- sealed-run
target: src/core/agents/swarm/injection/smart_sqli.py
---

# 実装計画: SGK-2026-0453 — SQLi 実害実証の「防御ありの相手」への対応（D02・Ver.1）

（親ロードマップ: SGK-2026-0442。0452 の deferred_task D02。0452 で live confirmed=1 に到達したが、実害実証プローブは注入文字列がそのままクエリに届く前提で、相手に入力の絞り込み・遮断が1つでもあると実証が成立しない。本タスクは、**防御を見抜いて汎用の変形で越え、確定まで持っていく力**を、確定バーを1バイトも触らずに実装する。トップハンター同等の"防御突破"を、Ver.1／Ver.2 の段階に分けて実装する。）

## 本タスクの位置づけ（D02 のうち Ver.1）

- **D02 全体テーマ** = 「防御ありの相手でも実害を実証できるようにする」。中身を Ver.1／Ver.2 に分けて実装する。
- **Ver.1（本タスク SGK-2026-0453）** = 決定的な防御突破。防御検知＋汎用すり抜け変形（決まった順で試す）＋読み取り内の抽出フォールバック。**ユーザー承認済みの案A。**
- **Ver.2（別タスク・後段）** = 応答を見て途中で優先順位を組み替える自律型（案B）。判定の非決定性対策（D01）と勝ち筋凍結の仕組みが前提。**本タスクの NOT in scope。ただし Ver.1 は Ver.2 を差し込める拡張性を持って実装する（ユーザー要求）。**

## このタスクの絶対原則（違反＝不合格）

1. **確定バーを緩めない・触らない**。`payout_grade.py`（機械床）/ `sealed_reproduction_checker.py`（再現）/ **poc_judge のプロンプト・判定基準**（AI 審査）/ `finding_validator.py` / `task_queue.py`(PCR-P1) は **diff 0**。防御突破は「門より手前＝攻撃を通す力」の拡張であり、confirmed は未改変の門が正当に通すことでのみ得る。
2. **カーブフィッティング・製品固有焼き込み禁止（本タスクの核心）**。「この相手にはこの一手」を焼き込まない。すり抜けは**標準的で製品非依存な変形の有限集合**として実装し、AI/選択ロジックはその集合の中で順序を変えるだけ。相手固有の新しい文字列を発明しない。`check_vdp_product_independence.py` verdict=pass（token hits 0）。
3. **判定を狩り側に持たせない**。「実害を実証できたか／止めてよいか」は**独立した3条件の門**が決める。狩り側の「もう十分」で confirmed にしない。送信を止める合図は**機械的な確定オラクル**（決定的な差／マーカー）が鳴った時のみ。
4. **勝ち筋を決まった手順に凍結する（再現のため）**。どの変形で越えたかを、**「この要求をこの順で送る」決定的な手順として固定・記録**し、確定はその固定手順を指す。探索の記録（ばらついてよい）と確定の証拠（決定的でなければならない）を別物として扱う。
5. **捏造禁止**。impact/evidence は**実際に観測した応答のみ**から構成（fail-closed）。
6. **機微データを抜かない（最重要・安全境界）**。抽出は**非機微1トークンのみ**（`sqlite_version()` 等メタ情報）。実ユーザーの資格情報・メール・パスワードハッシュ・PII は絶対に抽出しない。secret 生値を成果物に残さない。
7. **GET-only 境界（0447 B4）維持。状態変更（非 GET）を伴う実証はしない。**
8. **既定 OFF・オプトイン**。0451/0452 と同様、既定 run はバイト等価（回帰リスク隔離）。
9. **Python は `.venv`。commit/push しない**（オーケストレータが独立検証後にコミット。push はユーザー）。

## Ver.1 のゴール（完了契約・実装開始で固定）

「よくある入力の絞り込み・単純な遮断つきの相手に対し、**汎用の変形で自力で越えて、未改変の門で confirmed まで持っていける**」。かつ **Ver.2（自律型）を差し込める拡張点を残す**。

## Ver.1 の対象範囲（3つの部品 ＋ 拡張点）

### 部品1: 妨害の検知（interference detection）
発火が確認された実パラメータに対し、注入が「遮断／文字を削られた／別応答で弾かれた」のか「そもそも刺さらない」のかを、**汎用の signal** で見分ける。
- 例: baseline 応答 vs 素の注入プローブ応答の差、注入した鍵文字がエラー/応答に反映されない（＝除去された兆候）、既知の遮断応答パターン（汎用形のみ・特定製品の WAF ページ文字列を焼き込まない）。
- fail-closed: 妨害か否か判定不能なら「妨害なし＝従来経路」に倒す。

### 部品2: 汎用すり抜け変形の道具箱（有限集合・決定的適用）
既存の型（0452 の close-variant/boolean/UNION 系）に、**標準的で製品非依存な変形**を適用する。有限集合を**決まった順**で試し、**最初に決定的な差／マーカーを取り戻せた変形を採用**（fail-closed）。
- 危険語をコメントで割る（例: `UN/**/ION`）
- 空白をコメントに置換（例: `/**/`）
- 大文字小文字の混在（例: `UnIoN`）
- コメント終端の別種（`--` / `#` / `/**/`）
- 鍵となる文字の符号化違い（URL 符号化・二重符号化等・汎用範囲）
- 真偽条件の言い換え（`OR 1=1` → `OR 'a'='a'` 等）
- **注意**: これらは「汎用の変形カタログ」であり、相手固有ではない。recon で DBMS が分かっていればその DBMS で有効な変形を優先順に回してよい（ただし**同じ recon 入力なら毎回同じ順序**＝決定的）。

### 部品3: 抽出手段の読み取り内フォールバック
UNION 抽出が弾かれても、真偽制御（boolean オラクル）が取れているなら、**エラー経由 or 真偽1ビットずつ**で**非機微1トークン**を取る（決定的・**時間差方式は入れない**＝非決定性を避ける）。

### 拡張点（Ver.2 を差し込むための設計・本タスクで必須）
Ver.1 は決定的だが、**Ver.2（応答を見て AI が順序を組み替える自律型）を後から差し込める継ぎ目**を今回作る。
- **選択戦略の継ぎ目**: 「次にどの変形を試すか」を差し替え可能な戦略として分離する。Ver.1 実装＝決定的関数（recon＋固定順）。Ver.2 でここに AI 駆動の戦略を差し込む。**インターフェイス（入力: 観測履歴・recon・残り候補／出力: 次の候補）を Ver.1 で確定させる。**
- **勝ち筋凍結→再現手順の機構**: Ver.1 は既に決定的だが、「越えた経路を固定手順として記録し確定が参照する」機構を今回作り込む。Ver.2 の自律ループはこの機構を再利用する（Ver.2 で新設しない）。
- **妨害検知 signal・否定の記録（弾かれた手を繰り返さない）・変形カタログ**は Ver.1/Ver.2 共有。Ver.2 は選択戦略だけを差し替える。

## Ver.1 の完了条件（フェーズ0で最終確定）

1. **防御つき相手での end-to-end 実証**: 入力の絞り込み／遮断を1つ以上持つ相手に対し、SHIGOKU が妨害を検知し、**汎用の変形のみ**で越えて、決定的オラクル（＋必要なら非機微1トークン抽出）を取り戻し、**未改変の門で live confirmed=1** を出す。
   - **どの防御つき相手で実証するか**は**フェーズ0の最初に決める**（現在の練習用サイトの当該箇所は防御が無く素通りのため。候補: 別エンドポイント／封印 harness 内での入力絞り込み模擬／小さな防御つきローカル的。product-independence を壊さない形を選ぶ）。
2. **バー無改変**: バー5点すべて `git diff --quiet HEAD` exit0。
3. **カーブフィッティングでない証明**: `check_vdp_product_independence.py` verdict=pass・token hits 0。防御突破は汎用カタログのみ由来で、実証に用いた相手固有文字列の焼き込みが無い。
4. **拡張点の実在**: 選択戦略の継ぎ目・勝ち筋凍結機構が実装され、Ver.2 の戦略差し替えが「継ぎ目への実装追加」で済むこと（設計レビューで確認）。
5. **既定 OFF バイト等価**: 新フラグ OFF で既定 run が従来と等価。
6. **安全境界**: GET-only・機微データ抽出 0・secret 生値 0。
7. **単体テスト**: 妨害検知・変形カタログ・勝ち筋凍結の新規テストが pass。既存 injection/reporting スライス回帰なし。
8. **ドキュメント**: `validate_shigoku_docs.py` 0 エラー。consistency checker（実 report があれば）consistent。

## NOT in scope（Ver.2 以降・本タスクで実装しない）

- 応答を見て途中で AI が優先順位を組み替える自律ループ（案B）。
- 相手の遮断装置の指紋取り・適応的な変形連鎖。
- 時間差方式の盲目抽出・帯域外・二次注入・多段クエリ。
- 外部エンジン（sqlmap）の門下流取り込み。
- judge の非決定性対策（D01・別 deferred）。

これらは本タスクで**継ぎ目を用意する**が、実装は後段。フェーズ0で「Ver.2 のゴール」を計画書に明記し、追跡タスクへ紐付ける。

## フェーズ0（実装前・必須・設計承認ゲート）: DeepSeek 調査

コードを変える前に、以下を**実コード・実 artifact で確認**し（推測禁止・hypothesis と fact を区別）、最小差分設計を提出して**承認を得てから** STEP 2 へ進む。

1. **現状プローブの継ぎ目調査**: `smart_sqli.py` の `_fire_impact_demonstration_probe` と補助（`_quote_close_variants` / `_boolean_condition_pairs` / `_ordered_close_variants` / `_union_padding_literals` / `_run_boolean_oracle` / `_extract_non_sensitive_token`）を読み、**変形カタログ・選択戦略・勝ち筋記録を差し込む最小の継ぎ目**を特定する。既存の決定的挙動（0452）を壊さない加法設計にする。
2. **妨害検知の汎用 signal 設計**: 製品固有文字列を焼き込まずに「弾かれた／削られた」を見分ける汎用 signal を定義する（baseline 差・鍵文字の反映有無・汎用遮断パターン）。fail-closed 条件を明記。
3. **変形カタログの確定**: 部品2 の変形集合を「標準的・製品非依存・有限」で確定し、**適用順の決定規則**（recon 優先＋固定順）を定義する。product-independence を壊さないことを設計段階で確認。
4. **勝ち筋凍結→再現手順の設計**: 越えた経路を決定的な固定手順として記録し、確定（再現チェッカー replay）がそれを参照する形を設計する。**バーは触らず**、記録側（0449/0452 所有の充填・記録配線）を加法拡張する。
5. **防御つき実証ターゲットの決定**: 完了条件1の「どの防御つき相手で実証するか」を、product-independence を壊さない形で提案する（別エンドポイント／封印 harness 内の入力絞り込み模擬 等）。
6. **選択戦略インターフェイスの確定**: Ver.2 差し込み用の継ぎ目（入力/出力の型）を定義する。Ver.1 実装＝決定的関数。
7. 出力: 本計画書「フェーズ0結果」節に追記し、**最小差分設計＋どのバーも触らない証明＋拡張点の設計**を提出して承認を得る。

## 検証コマンド（このタスクで用いる）

- 単体: `.venv/bin/pytest tests/.../test_sqli_impact_probe.py` ほか新規テスト
- 製品非依存: `python3 scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt --changed-files <FILE>`
- バー無改変: `git diff --quiet HEAD -- <バー5点>` exit0
- 実 report があれば: `python3 scripts/verify_report_session_consistency.py --report <path>`
- ドキュメント: `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py`（0 エラー）

## フェーズ0結果（DeepSeek 提出後にオーケストレータが実データで裏取りして追記）

> 以下は DeepSeek によるフェーズ0調査・最小差分設計の提出（第3回・再提出、2026-08-17）。**引用規約（厳格）**: 行番号はすべて `rg -n` で現在の HEAD から取り直した値。関数・シンボルは**必ずその定義行（def/宣言行）を `def:` 付きで引用**し、文中の文レベルの参照は数値ではなく「def:XXXX 内の〜」と記述する（裸の文番号は使わない）。「事実」と「設計判断（『設計』と明記）」を区別する。承認後 STEP 2 へ。オーケストレータは実 artifact で裏取りして本節を確定する。

### A. 調査で確認した事実（実コード・定義行つき・HEAD で grep 確認済み）

| # | 事実 | 根拠（smart_sqli.py 断りなしは同ファイル。すべて grep で確定した定義行） |
|---|---|---|
| F-1 | 発火→実証の流れ: `_fire_error_based_probe`（def:1395）が `_build_error_based_probes`（def:1339）で生成した `{param}={base}'`/`{base}"` の2件を送信 → `_record_sql_observation`（def:1351）が sql_error 観測を記録 → **`_fire_error_based_probe` 内の実証ゲート判定（`_impact_demo_enabled()` が真 かつ sql_error 観測済み）が真のときのみ** `_fire_impact_demonstration_probe`（def:1488）が走る | smart_sqli.py def:1395 / def:1339 / def:1351 / def:1488 |
| F-2 | boolean オラクル: `_run_boolean_oracle`（def:1572）が**固定リテラル**の真偽プローブ（`{param}={base}{close} {cond} --`、def 内で組み立て）を、close 族（`_quote_close_variants` def:1443 = `[' , '), '))]`）× 条件ペア（`_boolean_condition_pairs` def:1459 = `[(OR 1=1,OR 1=2),(AND 1=1,AND 1=2)]`）で順に送信し、**最初の決定的差分**（`_has_boolean_differential` def:1787 = status差｜JSON行数差｜body長差≥16）を採用 | def:1572 / def:1443 / def:1459 / def:1787 |
| F-3 | 抽出: `_version_expr_for_db`（def:1716）は**閉じた非機微集合** `NON_SENSITIVE_EXTRACTION_EXPRS`（定義:97 = sqlite_version()/version()/@@VERSION のみ）から式を導出。`_discover_union_column_count`（def:1689、ORDER BY n プローブを close 族×N=1..13 で送信しエラー遷移で採用）→ `_extract_non_sensitive_token`（def:1612）が UNION SELECT プローブ（`-1{close} UNION SELECT {exprs} --`、パディング族 `_union_padding_literals` def:1478 = {NULL,1}）を送信 → 版数値が本文出現**かつ** control body に非存在のときのみ observed=True | 定義:97 / def:1716 / def:1689 / def:1612 / def:1478 |
| F-4 | 記録配線: `_fire_impact_demonstration_probe`（def:1488）が `self._impact_probe_records` を組立 → `run_as_tool`（def:393）が `result["impact_probe_records"]` に surface（firing∧impact ON 時のみ）→ manager.py の sqli_impact_records 配線（firing∧impact ON 時のみ）→ `injection_evidence_fields.build_sqli_impact_and_reproduction_steps`（def:137）が観測事実のみから impact/reproduction_steps を合成 | smart_sqli.py def:1488 / def:393 / manager.py / injection_evidence_fields.py def:137 |
| F-5 | 証拠チェーンのピン留め（A-1/A-2）: `_record_sql_observation`（def:1351）が**最初の** sql_error 観測の poc ペアを `self._error_poc_request/_error_poc_response` に固定。`run_as_tool`（def:393）が result の poc ペアをその観測に固定。`_build_sqli_evidence_and_impact`（def:2144、`parse_observed_request_url` def:31 を使用）が evidence URL/status を同一プローブに一致 | def:1351 / def:393 / def:2144 / injection_evidence_fields.py def:31 |
| F-6 | 再現チェッカー（バー）: `check`（sealed_reproduction_checker.py:215）が finding の `evidence.request_url` を封印 GET 1回で再送し（`_send_get` :349）、payout_grade の marker 語彙（import）で同一カテゴリ発火を確認（`_detect_marker_in_response` :129）。`sql_error` は body 観測可能 marker（`_BODY_OBSERVABLE_MARKERS` :76）。**URL がそのまま再送される** | sealed_reproduction_checker.py:215 / :349 / :129 / :76 |
| F-7 | 観測オブジェクト: `_send_request`（def:1810）は {status, diff, body_snippet(200字), elapsed_seconds, db_detection, error_classification, poc_request, poc_response} を返す。**body は送信元で500字に切り詰め**（def:1810 内）。GET-only 維持（def:1810 内の GET 分岐） | def:1810 |
| F-8 | 設定: `sqli_firing_path_enabled`（settings.py:673）/ `sqli_impact_probe_enabled`（settings.py:677）既定 OFF。impact ゲートは firing を要求（`_firing_path_enabled` def:1284 / `_impact_demo_enabled` def:1294） | settings.py:673 / :677 / smart_sqli.py def:1284 / def:1294 |
| F-9 | 0453 が埋める穴: **plain クォートが防御で弾かれると sql_error が未観測のまま実証プローブ全体が走らない**（F-1 の実証ゲートが False のまま）。0452 の実証は「注入文字列がそのまま届く」前提 | 0452 work_report:37 ほか / 本 plan 冒頭 |
| F-10 | 0447 preflight: 全プローブ同一 (status, body) = canned（転送なし）を fail-closed 検知（`check_forwarding` caido_check.py:480） | caido_check.py:480 / lessons.md:46 |

### B. 現状プローブの継ぎ目調査（タスク1）

最小の継ぎ目は3点。いずれも既存メソッド内の**加法挿入**で、既存のプローブ文字列・試行順・終了条件は不変（ゲートOFF＝既定は byte 等価、既存ゲートOFFテスト test_sqli_impact_probe.py:571-587 が回帰を検知）。

- **継ぎ目1（変形レンダリング）**: `_run_boolean_oracle`（def:1572）／`_discover_union_column_count`（def:1689）／`_extract_non_sensitive_token`（def:1612）の各プローブ文字列組み立て箇所（いずれも def 内の固定リテラル組み立て文）に、純関数レンダラ `render(canonical_probe, step) -> str` を通す**オプショナル引数 `renderer=None`** を追加。既定（None）は恒等関数＝現行文字列と byte 同一。
- **継ぎ目2（選択戦略）**: 各ループの「次に試す候補」を `TransformSelectionStrategy.next_candidate(...)` に置換（§G）。Ver.1 実装は「カタログ順＋否定スキップ」＝現行の「最初の差分採用」と同義。
- **継ぎ目3（妨害検知→回避の発火点）**: `_fire_error_based_probe`（def:1395）内の実証ゲート判定の**直前**に新分岐を挿入: 「sql_error 未観測 かつ 新フラグON」のとき `classify_interference(...)` を実行し、verdict ∈ {blocked, stripped_suspected} なら変形カタログで error プローブ族を再試行。勝ち筋プローブが sql_error を観測すれば、**以降は既存ゲートがそのまま進行**（F-1/F-5）。

### C. 妨害検知の汎用 signal（タスク2）

新規純関数 `classify_interference(baseline_obs, probe_obs_list) -> InterferenceVerdict`（新モジュール `sqli_transform_catalog.py`、stdlib のみ）。製品固有文字列を一切焼き込まない。入力は `_send_request`（def:1810）の観測フィールド（F-7）のみ。

- **S1 baseline差**: 各 probe の (status, body_snippet) と baseline の差。
- **S2 鍵文字の反映**: 送信したプローブの実ペイロード部分文字列（例 `1'`、送信側が保持）が `poc_response`（500字）に出現するか。出現＝入力がそのままアプリに届いた（inert 方向）。**反映は確認できた場合のみ** inert に使う（未確認は中性。切り詰め制約 F-7 を理由に過検出しない）。
- **S3 汎用遮断パターン**: status ∈ {403,406,412,429}、または「複数の異なるプローブが (status, body) 完全一致で baseline と異なる」＝汎用のブロックページ形状。製品の WAF ページ文字列は使わない。
- **verdict（決定的）**: S3 成立→`blocked`／S3 不成立 かつ 全 probe が baseline と完全一致 かつ S2 不成立→`stripped_suspected`／それ以外（probe 間差・baseline 差・反映あり）→`no_interference`。
- **fail-closed**: 判定不能・観測不足・信号矛盾はすべて `no_interference`＝従来経路に倒す。さらに verdict が blocked/stripped でも、**変形カタログを回して決定的差が戻らなければ回避前の状態（sql_error 未観測・実証なし）に完全復帰**する＝妨害検知の誤検知がハンティング結果を変えない。

### D. 変形カタログの確定（タスク3）

新規純関数モジュール `sqli_transform_catalog.py`。6家族＋引用無し家族の7つを**有限列挙**し、適用順を `catalog_sequence(fragment, db_type)` の**純関数**で固定（同じ入力→毎回同じ順序・乱数なし・時刻なし・recon 優先）。recon は `_detect_database_type`（def:1946）の結果（db_type）を使用。

| 家族 | 内容（標準的・製品非依存・有限） | DB 制約 |
|---|---|---|
| TERMINATOR | コメント終端の別種: `-- `／`#`／`/* */`。db_type で優先順を変える（mysql → `#`,`-- `,`/* */`。他 → `-- `,`/* */`） | `#` は mysql/mariadb のみ |
| CASE_MIX | 危険語トークン（SELECT/UNION/ORDER BY/OR/AND）の大文字小文字混在（例 `UnIoN`）を有限列挙 | 全 DB |
| WS_COMMENT | 断片内の区切り空白1箇所を `/**/` に置換（候補数＝空白位置の有限数） | 全 DB |
| COMMENT_SPLIT | 危険語をコメントで割る（`UN/**/ION`） | **mysql/mariadb 限定**（他 DB は構文エラー） |
| NO_QUOTE | 引用無し形状 `{base} {cond} --`（数値コンテキスト。引用除去防御への主要回答） | 数値コンテキストで有効 |
| COND_PARAPHRASE | 条件言い換え（`1=1`→`'a'='a'` 等）を有限列挙 | 全 DB |
| ENCODING | 危険文字の二重 URL 符号化（`%27`→`%2527`）。**最後に試す**（2層デコードがある環境のみ有効・アプリを壊す可能性が最も高い）。専用の `pre_encoded` 送信フラグで実装（既定 False→byte 等価） | 2層デコード時 |

- 適用順: Tier0=TERMINATOR(db_type優先) → Tier1=CASE_MIX → Tier2=WS_COMMENT → Tier3=COMMENT_SPLIT(mysql のみ) → Tier4=NO_QUOTE → Tier5=COND_PARAPHRASE → Tier6=ENCODING。recon が unknown でも固定の汎用順で回る。全候補数は断片あたり数十件以内の確定値（実装でテスト可能）。
- **製品非依存の設計段階確認**: カタログは標準 SQL の字句・コメント・符号化のみを操作し、実証相手の名称・URL・遮断ページ文字列を持たない。denylist（sealed_product_denylist.txt: juice/dvwa/owasp/各エンドポイント等）非該当。実装後 `check_vdp_product_independence.py` で token hits 0 を検証する（§I）。

### E. 抽出フォールバック（タスク4）— 回数上限つき

UNION が弾かれ（列数発見失敗 or UNION 応答に値なし）ても boolean 差分が取れている場合、`_extract_non_sensitive_token`（def:1612）の後段に決定的手順 `_extract_token_by_boolean_oracle(param, base, close, expr)` を追加。**時間差方式は入れない**。抽出式は既存 `_version_expr_for_db`（def:1716）の閉じた集合（F-3）を再利用＝抽出面の拡張なし（機微データ経路ゼロ維持）。

1. **長さ特定（二分探索・上限つき）**: `AND length((SELECT {expr})) >= {n}` vs `AND length((SELECT {expr})) < {n}` を n ∈ [1,16] で**二分探索**（真偽各1件×最大4回比較＝最大8プローブ）。特定後、等号ペア1件（2プローブ）で確定。差分が取れなければ observed=False。
2. **文字特定（二分探索・有限アルファベット）**: 位置 i=1..len × アルファベット A={0-9, '.', '-'}（12文字・バージョン文字のみ）で `AND {fn}(substr((SELECT {expr}),{i},1)) > {ord(c)}` vs `<=` を二分探索（1位置あたり最大4比較×2＝最大8プローブ）→ 等号ペア1件（2プローブ）で確定。`fn` は DB 別テンプレート表（sqlite→unicode / mysql,postgres→ascii / mssql→unicode）＝DBMS 汎用知識。**ネスト引用を使わない**（引用除去防御に頑健）。
3. **確定**: 組み立てたトークン全体で1回 `AND substr((SELECT {expr}),1,{len})='{token}'` の真偽差分（2プローブ）を観測（直接観測1件でトークン全体を裏付け）。
4. **送信回数上限（設計・明示）**: 最悪 8+2（長さ）＋ 16位置×10（文字）＋ 2（確定）＝ **最大 172 プローブ**。**ハードキャップ = 200 プローブ**とし、超過時は即中止・observed=False（fail-closed・予算超過で捏造しない）。GET-only（`_send_request` def:1810 の GET 分岐経由）・機微データ抽出 0 は不変。
5. 記録は各位置の観測（true/false プローブと結果）＋確定プローブ。impact 文では「boolean オラクル経由で導出」と明記（AGENTS.md §8 の backfill ラベル規則：生観測と区別）。
6. fail-closed: 途中で差分が消えたら即中止・observed=False（値未記録）。

### F. 勝ち筋凍結→再現手順（タスク5）— 凍結対象の明示

- **凍結対象（明示）**: `impact_probe_records["evasion"]` と、再現が参照する poc_request/evidence URL は、**越えた変形の要求そのもの（素のプローブではない）** である。F-5 により `_record_sql_observation`（def:1351）は「最初に sql_error を観測したプローブ」＝**勝ち筋（変形済み）エラープローブ**の poc ペアを固定する（素のプローブは sql_error を観測できないため、ピン留め対象になり得ない）。`run_as_tool`（def:393）と `_build_sqli_evidence_and_impact`（def:2144）がこれを evidence URL/status・impact payload に一致させる。
- **再現の根拠**: 再現チェッカー（バー）は `check`（sealed_reproduction_checker.py:215）で `evidence.request_url` を**そのまま**封印 GET 再送（`_send_get` :349）。同一 URL ＝ 同一の変形済みペイロード（URL 内に百分率符号化）＝ 防御を同じ経路で通過 ＝ 同一の `sql_error` 発火（`_detect_marker_in_response` :129 が payout_grade の `_SQL_ERROR_PATTERNS` 語彙で再検出）。**同一入力→同一挙動**の決定性が再現の根拠であり、チェッカー側の変更は一切不要（F-6）。
- **記録（加法・バーに触れない）**: `impact_probe_records["evasion"]`（新キー・既存キーは不変。消費側は records.get なので未知キー安全、injection_evidence_fields.py:192-198）に次を記録: `interference`（verdict+reason+信号）、`route`（**観測した全プローブを送信順**に `{step, kind, probe, observed}` で列挙＝決定的固定手順）、`adopted`（勝ち筋の step/kind/rendered/canonical＋その poc_request）、`rejected`（弾かれた手＝否定の記録。Ver.2 が再利用）。
- **充填（0449/0452 所有の加法拡張）**: `injection_evidence_fields.build_sqli_impact_and_reproduction_steps`（def:137）に分岐追加: `evasion.adopted` があるとき reproduction_steps = route の「GET {url} で {probe} を送り {observed} を観測」列（最終ステップ＝adopted の poc_request URL）。未観測なら現行文言（byte 等価）。
- manager.py は無変更（既存の sqli_impact_records 配線が impact_probe_records をそのまま通す）。

### G. Ver.2 差し込みの継ぎ目（タスク6・選択戦略インターフェイス）

```python
@dataclass(frozen=True)
class TransformStep:            # カタログ1候補
    kind: str; variant: int; canonical: str; rendered: str
@dataclass(frozen=True)
class ProbeObservation:         # 観測履歴（1件）
    step: TransformStep; probe: str; result: str; differential: bool

class TransformSelectionStrategy(Protocol):
    def next_candidate(self, *, candidates: Sequence[TransformStep],
                       observations: Sequence[ProbeObservation],
                       recon: ReconInfo, rejected: FrozenSet[TransformStepKey]
    ) -> Optional[TransformStep]: ...
```

- Ver.1 実装 `DeterministicFixedOrderStrategy`: candidates をカタログ順（§D）で返し rejected をスキップ、最初の決定的差を採用（＝現行挙動と同義）。
- **Ver.2 はこのインターフェイスに AI 駆動の実装を差すだけ**（入力: 観測履歴・recon・残り候補／出力: 次の候補）。妨害検知・否定の記録・変形カタログ・勝ち筋凍結は Ver.1/Ver.2 共有（計画書の拡張点設計どおり）。

### H. 防御つき実証ターゲットの提案（タスク7）— 的分離の明示

**採用案: 封印 harness 内の「入力絞り込み模擬」（計画書候補b）**。

- **配置（明示・的分離）**: 新設ターゲット（FastAPI + SQLite、GET `/search?q=`）は **`tests/fixtures/` 配下**（例 `tests/fixtures/vdp_filtered_search_app/`）に置く。`check_vdp_product_independence.py` の走査対象は PRODUCTION_PREFIXES（定義:53 = src/, scripts/, config/, recipes/, prompts/, data/）のみ（同スクリプトがこの接頭辞でフィルタ）であり、**テスト側ターゲットは token 走査対象外**。製品コード（smart_sqli.py / 新規 sqli_transform_catalog.py / injection_evidence_fields.py / settings.py）には**的固有の文字列（名称・URL・遮断ページ文字列）を一切入れない**。これにより `check_vdp_product_independence.py --changed-files <変更済み製品ファイルのみ>` で verdict=pass・total_token_hits 0 が担保される（§I で実測）。
- アプリは SQL を**実際に実行**し、クエリ依存の実コンテンツ（検索結果行）を返す。入力フィルタ（引用符除去／`union` 大文字小文字非依存ブロック／`--` 除去／`/*` ブロック 等）を**設定で切替**可能にし、素通し→遮断の両方の実証を1 harness で実現。
- 転送の実在性: 0445 の教訓（stub proxy は全応答が同一 canned 文字列→ confirmed=0 の真因）と F-10（0447 preflight・`check_forwarding` caido_check.py:480）を尊重し、応答はパス依存の実コンテンツとし、preflight forwarding チェックを実 target に対して通す。
- 非推奨（併記）: 実在の WAF 付き別エンドポイントは環境依存で決定性に劣るためフォールバック扱い。

### I. 最小差分設計＋バー無改変証明＋拡張点（タスク8・出力）

**変更ファイル（最小・5点）**:
1. `src/core/agents/swarm/injection/sqli_transform_catalog.py`（新規・純関数のみ: カタログ/render/catalog_sequence/classify_interference/TransformSelectionStrategy/DeterministicFixedOrderStrategy。stdlib のみ）
2. `src/core/agents/swarm/injection/smart_sqli.py`（加法: 3継ぎ目への配線・`_extract_token_by_boolean_oracle`・`impact_probe_records["evasion"]` 記録。既存メソッドのプローブ文字列・順序は不変）
3. `src/core/agents/swarm/injection/manager_internal/injection_evidence_fields.py`（加法: evasion.route からの reproduction_steps 合成。未観測時 byte 等価）
4. `src/core/config/settings.py`（加法: `sqli_evasion_catalog_enabled: bool = False`。既定 OFF・firing∧impact を要求）
5. テスト: `tests/unit/test_sqli_evasion.py`（新規）＋既存ゲートOFF回帰テスト（test_sqli_impact_probe.py:571 / :587）

**バー無改変証明**:
- 機械的: `git diff --quiet HEAD -- payout_grade.py sealed_reproduction_checker.py poc_judge.md finding_validator.py task_queue.py` → exit 0（STEP 2 完了時に検証）。
- 論理: 新モジュールは stdlib のみ・バーへの import 追加なし。`injection_evidence_fields.py` は既存 import のまま。バーは判定入力を変えず、**防御突破は「門より手前＝攻撃生成」の拡張**なので confirmed は未改変の門（3条件AND）が正当に通す。
- 製品非依存: `check_vdp_product_independence.py` verdict=pass・total_token_hits 0（新コードは汎用 SQL 知識のみ・denylist 非該当・的固有文字列なし=§H）。
- 既定OFFバイト等価: 新フラグ OFF（既定）で既存テスト（test_sqli_impact_probe.py:571 / :587 / test_smart_sqli_firing_path.py）が pass し、送信プローブ列・finding フィールド不変。

**拡張点（Ver.2）**: §B の継ぎ目1/2/3 と §G のインターフェイス。Ver.2 は `DeterministicFixedOrderStrategy` を AI 実装に差し替えるだけで、妨害検知・カタログ・否定記録・勝ち筋凍結は共有。

**NOT in scope（本設計で触らない）**: 応答適応ループ（案B）・WAF 指紋取り・時間差/OOB/二次注入/多段クエリ・sqlmap 統合・judge 非決定性（D01）。

**仮説/事実の区別**: §A は実コードの定義行で確認済みの事実。verdict 閾値・カタログ順序・アルファベット・回数上限（§E の 200）等のパラメータは設計判断であり、STEP 2 の単体テストで確定する。

**フェーズ0の検証コマンド（オーケストレータ裏取り用）**: バー無改変 `git diff --quiet HEAD -- <バー5点>`／製品非依存 `check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt --changed-files <新規2+変更3>`／単体 `.venv/bin/pytest tests/unit/test_sqli_evasion.py tests/unit/test_sqli_impact_probe.py`／ドキュメント `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py`（0 エラー）。

## STEP 4 診断結果（綻び2・綻び1 の原因診断・2026-08-17・コード変更なし）

> 診断ゲート。**コード変更なし・コミットなし・バー無改変**。統制比較は実 run 10 本＋既存 run の実 artifact を根拠とする。hypothesis と fact を明示的に区別する。

### 4-1. 統制比較（診断 OFF 5回 / ON 5回・全件報告）

同一の的（`tests/fixtures/vdp_filtered_search_app`・`SHIGOKU_DEMO_FILTER=strip_quote`＋`SHIGOKU_DEMO_DOUBLE_DECODE=1`・127.0.0.1:18080）・同一3フラグ＋T3＋GET_ONLY・本物 Caido 8081 経由で 10 本実行（rc=0 全件）。

| # | diag | 回避起動 (poc `%2527`/evasion route) | phase2 | confirmed | funnel 経路 | first_failure_reason |
|---|---|---|---|---|---|---|
| 1 | OFF | **Y**（poc `q=1%2527`・impact に evasion route） | early-return で skip（正常経路） | 0 | （診断OFFのため未収録） | - |
| 2 | OFF | Y | skip | 0 | - | - |
| 3 | OFF | Y | skip | 0 | - | - |
| 4 | OFF | Y | skip | 0 | - | - |
| 5 | OFF | Y | skip | 0 | - | - |
| 6 | ON | Y | skip | 0 | F1→F3skip→F4（max F4） | phase2_skipped_early_return |
| 7 | ON | Y | skip | 0 | F4 | phase2_skipped_early_return |
| 8 | ON | Y | skip | 0 | F4 | phase2_skipped_early_return |
| 9 | ON | Y | skip | 0 | F4 | phase2_skipped_early_return |
| 10 | ON | Y | skip | 0 | F4 | phase2_skipped_early_return |

**経路分布**: 回避起動 = OFF 5/5・ON 5/5（**診断の有無で差なし**）。confirmed = 全 10 本 0。phase2 skip = 全 10 本（正常経路）。funnel は診断 ON のみ収録（下記 4-5 参照）。

### 4-2. 主仮説の検証（fact）

**主仮説「計器（diagnostics）ON が攻撃経路を変える」は実証的に否定された（hypothesis → 否定）**。

- (fact・コード) 注入経路（smart_sqli.py / manager.py / execution_policy.py）に `diagnostics.enabled` の読み取りは**存在しない**。diagnostics を読むのは `finding_funnel_trace.get_finding_funnel()`（finding_funnel_trace.py:344-356）のみで、これは測定専用（OFF で None → emit が no-op）。計器が判定・発火・dispatch を変える経路がない。
- (fact・実測) 統制比較 10 本すべてで回避が起動（poc `q=1%2527`・impact に boolean 差分＋抽出＋Defense-evasion route・再現手順 113 件）。OFF/ON で同一。

### 4-3. 綻び2 の実態（confirmed=0 と phase2_skipped_early_return の真因）

- (fact・コード) `_t3_apply_hybrid_verdict`（manager.py:1150-1180、特に **:1176-1177**）:
  ```python
  record = ledger.get(finding_id)
  if record is not None and record.state != LifecycleState.NEEDS_MORE:
      return False  # already terminal/parked: skip judgement entirely
  ```
  **ledger で terminal（confirmed 等）の finding は judge 呼び出しなしで完全スキップ**される。
- (fact・実測) sqli finding ID は**全 run で同一 `77bc2af9eda9`**（URL/param フィンガープリントの dedup）。ledger に `77bc2af9eda9 | confirmed | hybrid_confirmed`（first_seen 01:47:49 = run 5 = **この finding の初回判定で accept**）。以降の run（105506・比較10本）は terminal-skip により judge 未呼び出し・ledger 未更新（parent ledger updated_at は 01:47:49 のまま）。
- したがって **比較10本の confirmed=0 は「判定却下」ではなく「既 confirmed の再判定スキップ」**。検出機構の揺らぎではない。
- (fact・コード) `phase2_skipped_early_return`（manager.py:3428）は `dispatch`（:2736）内で、phase1 finding あり＋ `should_early_return_phase2`（execution_policy.py:140 = `bool(findings) and (early_return_enabled or auto_early_return)`、`early_return_enabled` の既定は `not phase1_coverage_mode`）が真のときの**正常経路**。確定は phase2 ではなく直前に走る `_t3_run_hybrid_pass`（manager.py:3389）で行われる。**0452 の confirmed run（B9）も `phase2_skipped_early_return` で F3 skip かつ F5/F6 到達**（session_20260816_223550 の funnel: finding 58388d66e8b2 が F6 reached）＝本件とは無関係の正常挙動。

### 4-4. 105506 の矛盾解消（記録0 と %2527×1039）

- (fact・実測) session_20260817_105506.json に `%2527` が **1039 回**。これは**回避チェーンの実走行の記録**であって他所からの転記ではない: sqli finding（task 63d14774）の `poc_request = GET /search?method=GET&q=1%2527`、impact に「payload 'q=1%2527' … HTTP 500」＋ boolean 差分（`q=1%2527...1%253D1`→rows=3 vs rows=0）＋「Defense-evasion route」、reproduction_steps が回避ルート全プローブ（各プローブ文字列に `%2527` を含む）を列挙。
- 「interference/evasion の記録0」は、**生の `impact_probe_records` dict が finding の `additional_info` に格納されない**（`build_sqli_impact_and_reproduction_steps` が文言に消費する）という設計事実による観測点の違い。回避・妨害検知は**実際に実行・記録**されている（evasion の全要素は impact 文言と poc に現れる）。

### 4-5. 綻び1（confirmed と F6 の同居）

- (fact・コード) F6 emit は manager.py:1265、`_funnel_finding_event(finding, "F6", "reached")` を **ledger が真に confirmed へ遷移したときのみ**発火。レコーダ `get_finding_funnel()` は **diagnostics.enabled が ON のときのみ**存在（OFF → None → emit no-op）。
- (fact・実測) 0452 の B9（session_20260816_223550）は **診断 ON で実行されており**、funnel `by_stage: F6=1`（finding 58388d66e8b2 が F0..F6 all reached）＝ **「confirmed かつ F6=1」は同一成果物に同居可能**。
- 本タスクの confirmed run（session_104759）は**診断 OFF で実行した**（私のセットアップ漏れ）ため funnel 未収録。**綻び1 はコード欠陥ではなくセットアップ/手順の問題**。綻び2 とは同根ではない（綻び2 の主仮説は否定された）。

### 4-6. 分類（証拠付き）

- **綻び2 = in_scope_blocker ではない（deferred_followup）**。根拠: (a) 計器が経路を変える証拠なし（コード読解＋統制比較 10/10 回避起動）。(b) confirmed=0 は terminal-skip（既 confirmed finding の再判定なし）＝機構の決定性の一部。(c) phase2_skipped_early_return は正常経路（B9 も同様）。完了条件違反・当該変更由来の回帰・安全境界違反のいずれにも該当しない。
- **綻び1 = in_scope_blocker ではない（deferred_followup）**。根拠: F6 収録には診断 ON が必要だが、B9 が同居を実証済み。confirmed run の診断 OFF は私の実行手順の欠落。
- **STEP 3 報告の訂正**: 前報告で「judge のぶれ: run2 sqli needs_more vs run5 confirmed」としたのは**別 finding**（run2 系 9d655ef8b393 はターゲット URL `.../search`（?q=1 なし）由来・judge 正当却下 / run5 系 77bc2af9eda9 は `.../search?q=1` 由来・初回判定で accept）。同一 finding の accept/reject ぶれは本タスクの run 群では観測されていない（0452 の B6/B7/B8 は別事象）。

### 4-7. 追跡方針（deferred_followup・承認後 STEP 5 で検討）

1. **F6 収録の手順化**: 初回確認 run に `SHIGOKU_DIAGNOSTICS__ENABLED=1` を含める（measurement-only・バー無改変）。diagnostics の既定 OFF は 0425 の character 契約に触れない（本タスクでは run 手順として対応）。
2. **terminal-skip の可視性**: 既 confirmed finding の再訪を run ログに記録するか否か（計装）。funnel は F4 で止まるため、運用上「確認済みの再訪」と「未確認」を区別できると監視しやすい。**バー・判定は触らない**。
3. D01（judge 非決定性）は既存 deferred のまま（本診断で新たな同一 finding ぶれは観測されず）。

### 4-8. 検証（STEP 4・実測）

- バー5点 `git diff --quiet HEAD -- <バー5点>` → **exit 0**。
- 統制比較 run: 10/10 rc=0・回避起動 10/10・confirmed 0/10（terminal-skip・判定なし）。funnel は ON のみ収録（F4 max）。
- 既存テスト失敗の全件開示: `test_smart_sqli_hunter_post_json_support`（1件）＝HEAD でも失敗する既存問題（STEP 2 で git stash により確認済み・本タスク無関係）。

## STEP 5 実測結果（安定度の正直な実測・2026-08-18・コード変更なし）

> まっさらな台帳から 5 本実行。条件固定: 同一ハーネス（`strip_quote`＋`SHIGOKU_DEMO_DOUBLE_DECODE=1`・127.0.0.1:18080）・同一3フラグ（firing / impact_probe / evasion_catalog ON）・T3＋GET_ONLY ON・**計器（diagnostics）ON**・本物 Caido 8081 経由。
>
> **台帳リセット手順（対象ハーネス専用・実コマンド）**:
> ```bash
> cp workspace/projects/127.0.0.1:18080/candidate_ledger.json /tmp/opencode/ledger_backup_step5_<N>.json   # 退避
> rm -f workspace/projects/127.0.0.1:18080/candidate_ledger.json                                            # まっさら
> ```
> `CandidateLedger.open` は欠損ファイルを空 ledger として扱う（candidate_ledger.py:135-141）ため、この削除が「台帳だけをまっさらに戻す」操作。本番・バー・他対象には触れない。各 run 前に実行。

### 5-1. 5 本の表（全件・cherry-pick 禁止）

| run | confirmed (hybrid_final_state) | judge | 回避起動 (interference + poc) | ファネル経路 (sqli) | first_failure_reason |
|---|---|---|---|---|---|
| 1 | **1**（confirmed） | **accept** | Y（stripped_suspected・poc `q=1%2527`） | **F1→F3skip→F4→F5→F6** | phase2_skipped_early_return |
| 2 | **1**（confirmed） | **accept** | Y（stripped・poc `q=1%2527`） | **F1→F3skip→F4→F5→F6** | phase2_skipped_early_return |
| 3 | **1**（confirmed） | **accept** | Y（stripped・poc `q=1%2527`） | **F1→F3skip→F4→F5→F6** | phase2_skipped_early_return |
| 4 | **1**（confirmed） | **accept** | Y（stripped・poc `q=1%2527`） | **F1→F3skip→F4→F5→F6** | phase2_skipped_early_return |
| 5 | **0**（needs_more） | **reject**（`ai_no_prize_grade`） | Y（stripped・poc `q=1%2527`） | F1→F3skip→F4（F5/F6 未到達） | phase2_skipped_early_return |

（各 run rc=0。confirmed は当該 run の report `confirmed_count`（gate JSON）＋ funnel の sqli F6 到達（manager.py:1265 の F6 emit は ledger が真に confirmed へ遷移したときのみ）で二重に裏取り。judge accept は report confirmed=1 と F6 到達からの帰結。）

### 5-2. 集計

- **確定率 = 4/5（80%）**・**回避起動率 = 5/5（100%）**。
- **失敗の型（run 5・1本のみ）**: `judge reject`（ai_no_prize_grade・境界 severity の正当却下）。回避未起動・早期終了・その他は 0 件。回避は毎回起動し、判定に回っている。
- **毎回成功するとは書かない**: 4/5 であり、run 5 は judge が正当に却下した。STEP 3 の run 5（初回判定 accept）と合わせると、judged 6 回中 accept 5 回・reject 1 回（約83%）。

### 5-3. 正本（confirmed と F6 同居）

run 1 を正本とする:
- session: `workspace/projects/127.0.0.1:18080/search?q=1/sessions/session_20260818_001905.json`
- report: `workspace/projects/127.0.0.1:18080/search?q=1/reports/haddix_report_20260818_001907.md`（confirmed_count=1・sqli F6 reached）
- consistency: `verify_report_session_consistency.py --report <abs>` → **status=consistent・rerun_required=false**（reason_codes 空）

### 5-4. 検証（実測）

- バー5点 `git diff --quiet HEAD -- <バー5点>` → **exit 0**（各 run 前後で確認済み）。
- コード変更: **0 件**（実測のみ・ledger リセットは run 副作用の対象外データ）。
- 既存テスト失敗の全件開示: `test_smart_sqli_hunter_post_json_support`（1件・HEAD でも失敗する既存問題、STEP 2 で git stash 確認済み）。
