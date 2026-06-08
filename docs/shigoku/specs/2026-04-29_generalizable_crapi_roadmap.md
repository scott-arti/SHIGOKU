---
task_id: SGK-2026-0088
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-04-29'
updated_at: '2026-05-19'
---

# 仕様書: crAPI起点で汎用性を維持する検出強化ロードマップ

## 1. 目的
本仕様は、crAPIでの改善をきっかけにしつつ、特定ターゲットへのカーブフィッティングを避け、
SHIGOKUが「人手より高速に拾える領域」を安定して取り切るための実装ロードマップを定義する。

## 2. 達成したい状態（Sufficient Level）
「十分」を以下で定義する。

### 2.1 自動優位領域の定義
自動優位領域（SHIGOKU単独で人手より効率が高い領域）は次とする。
- Access Control差分（unauth/authA/authB）
- IDOR/BOLA（object A/B 比較）
- Mass Assignment（スキーマ候補抽出 + 変更試験）
- Endpoint/BFLA探索（隠しAPI/権限境界）
- 低〜中摩擦 Injection（SQLi/NoSQLi/XSS/SSRFのうち機械判定可能なもの）
- Rate-limit/Bruteforce耐性検査

### 2.2 十分レベル判定条件
直近5ラン（同一ターゲット、同一ポリシー）で次を満たすこと。
1. 自動優位領域のうち Access Control / IDOR-BOLA / Mass Assignment / Endpoint-BFLA で、それぞれ Confirmed が1件以上。
2. Confirmedは全件 PoC request/response を保持（欠損0）。
3. Candidateの reason_code 欠損0。
4. family gate は PASS。
5. 同一クラスの Confirmed が 5回中3回以上で再現（単発ヒット依存を排除）。

注: OOB・高度業務ロジック・高度内部SSRFは deferred/HITL 管理を継続し、この十分条件の必須対象には含めない。

## 3. カーブフィッティング防止原則

### 3.1 実装原則
- ターゲット固有文字列（例: 固定エンドポイント名、固有パラメータ名）のハードコード禁止。
- ルールは「カテゴリ/信号/HTTP特性/差分結果」で一般化して表現する。
- 「Scenario coverage」と「Exploit evidence」を分離し、coverageの見かけ達成で成功扱いしない。

### 3.2 レビュー原則
PR/差分レビュー時に以下を必須確認する。
- 新規ロジックに `target contains "<app固有文字列>"` がないこと。
- 判定条件が「レスポンス差分・構造差分・権限差分」に基づくこと。
- 固有環境に依存する前提がある場合、設定化されデフォルト無効であること。

### 3.3 評価原則
- crAPIだけで合格判定しない。
- 最低2種類の異なるターゲット群で同一ゲートを通す（例: API中心アプリ + Webフォーム中心アプリ）。

## 4. 実装ロードマップ

### Phase 1: メトリクス分離と真値化（1週間）
目的:
- 「見つけたつもり」を除去し、改善が数字で追える状態にする。

実装:
- `scenario_coverage` と `confirmed_by_vuln_class` を明示分離。
- レポートに「クラス別 Confirmed/Candidate 推移」を追加。
- Gate判定で coverage と finding を別理由コードで返す。

完了条件:
- coverage 100% でも finding不足なら FAIL 理由が明確に分かれる。
- 最新レポートから「どのクラスが実際にConfirmed化したか」が一目で分かる。

### Phase 2: 自動優位4領域の深掘り（2週間）
目的:
- Access Control / IDOR-BOLA / Mass Assignment / Endpoint-BFLA を取り切る。

実装:
- Access Control: unauth/authA/authB の3比較を全API候補へ標準適用。
- IDOR/BOLA: object A/B 変異戦略をIDパターン別に強化（path/query/body）。
- Mass Assignment: 応答スキーマから可変候補の抽出精度を改善。
- Endpoint/BFLA: 発見APIの権限差分検証を自動連結。

完了条件:
- 直近5ランで上記4領域すべてに Confirmed が出る。
- Confirmed PoC欠損が0を維持する。

### Phase 3: Injection検出の安定化（2週間）
目的:
- SQLi/NoSQLi/XSS/SSRF の「誤検知を増やさず」再現率を上げる。

実装:
- payload投入前の前提検査（反射性/解釈器到達性/URL fetch性）を必須化。
- blind/timeベースの相関証拠を標準フォーマットで保存。
- 降格理由（insufficient_payload / insufficient_validation など）を詳細化。

完了条件:
- Injection系で少なくとも1クラス以上が5ラン中3回以上 Confirmed。
- Candidate reason_code 欠損0を維持。

### Phase 4: 汎用性検証トラック（2週間）
目的:
- crAPI依存を排除し、外部ターゲットでも通ることを示す。

実装:
- ベンチマークターゲットを2系統用意（API偏重 / Web偏重）。
- 同一ゲート・同一レポート整合チェックで連続実行。
- クラス別再現率の比較レポートを生成。

完了条件:
- 2ターゲット以上で family gate PASS。
- 自動優位4領域のうち3領域以上で Confirmed を再現。

### Phase 5: リリースゲート確定（1週間）
目的:
- 運用中に判定がぶれない最終基準を固定する。

実装:
- 初期版ゲートと strictゲートを併存（環境変数で切替）。
- strict時の既定値: `confirmed_min=3`, `candidate_max=2`, `confirmed_poc_missing_max=0`, `reason_code_missing_max=0`。
- deferred/HITL（SCN08/10/12等）は別トラックとして常時出力。

完了条件:
- 同一入力に対して gate verdict が再現する。
- deferred backlog と本線ゲートが混線しない。

## 5. KPI
- `confirmed_count_by_class`
- `confirmed_with_poc_rate`
- `candidate_with_reason_code_rate`
- `reproducibility_5run`（5回中何回再現したか）
- `time_to_first_confirmed`
- `full_scan_ratio`

## 6. 実行順（運用）
- 1) `focus-tests`
- 2) `short attack loop`
- 3) 必要時のみ `full scan`
- 4) `report consistency check`
- 5) `initial/strict gate check`
- 6) `deferred/HITL` 実施

## 7. リスクと対策
- リスク: Confirmed数が一時減少する。
  - 対策: 判定厳格化の副作用として許容し、再現率KPIを主指標にする。
- リスク: ログ・証跡増加で処理が重くなる。
  - 対策: evidence保持レベルを設定化（full/minimal）。
- リスク: ターゲット固有ルールが混入する。
  - 対策: PRテンプレートに「固有条件の有無」チェック項目を追加する。

## 8. この仕様での「完了」
次の2条件を満たした時点を完了とする。
1. 自動優位4領域（Access Control / IDOR-BOLA / Mass Assignment / Endpoint-BFLA）が十分条件を満たす。
2. crAPI以外のターゲットで同等ゲートを通し、汎用性が実証される。
