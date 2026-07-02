---
task_id: SGK-2026-0329
doc_type: plan
status: done
parent_task_id: SGK-2026-0066
related_docs:
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
- docs/shigoku/specs/adr/2026-02-27_RequestGuard_Implementation.md
- docs/shigoku/specs/2026-05-14_ver1x_hitl_gate_policy.md
title: BugBountyデフォルト化とSQLi危険操作HITL強制化 実装計画
created_at: '2026-06-30'
updated_at: '2026-07-02'
tags:
- shigoku
target: ''
---

# 実装計画書：BugBountyデフォルト化とSQLi危険操作HITL強制化 実装計画

## 1. 達成したいゴール（ユーザー視点）
- [ ] `--mode` を明示しない通常実行で、SHIGOKU が Bug Bounty 前提の fail-closed 挙動を取ること。
- [ ] SQLi/XSS などの injection 系 specialist が `POST/PUT/DELETE/PATCH` を送る場合、Bug Bounty 運用では必ず HITL または明示承認を経由すること。
- [ ] SQL payload に `DELETE/UPDATE/INSERT/DROP/TRUNCATE/ALTER` などの危険操作が含まれる場合、Bug Bounty 運用では送信前に fail-closed で遮断されること。
- [ ] CTF モードでは既存の探索自由度を維持しつつ、Bug Bounty との安全境界がコード上で明確に分離されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/security/`: （新規追加候補）HTTP method guard と payload guard を統合する共通セーフガードサービスの配置先。
  - `src/core/agents/swarm/injection/smart_sqli.py`: （修正）`SmartSQLiHunter` のデフォルトモードを変更し、個別判定ではなく共通セーフガードサービスを参照する。
  - `src/core/security/request_guard.py`: （修正または adapter 化）既存の endpoint 承認キャッシュ / HITL 判定を共通セーフガードサービスへ統合する。
  - `src/core/infra/smart_request.py`: （修正）specialist 共通の送信ラッパー。統合済みセーフガードサービスの呼び出し点にする。
  - `src/core/security/enhanced_ethics_guard.py`: （参照または一部流用）破壊的 SQL パターンの既存定義元。必要なら rule source として正本化する。
  - `src/core/engine/admission_policy.py`: （確認/必要なら修正）mutating lane の fail-closed と allowlist 制御。
  - `src/core/config/settings.py`: （確認/必要なら修正）mutating / aggressive lane のデフォルト設定管理。
  - `tests/unit` 配下の security / smart request / injection 関連テスト: （追加/修正）共通セーフガードサービスを各モジュールから参照したときの一貫性確認。
  - `tests/unit/engine/test_admission_policy.py`: （追加/修正）mutating lane の fail-closed 回帰確認。
  - `tests/unit/test_smart_sqli_post.py`: （追加/修正）Bug Bounty での POST + HITL 必須化、共通 payload block 参照、CTF override の確認。
- **データの流れ / 依存関係:**
  - CLI / task config / specialist config -> mode 解決 -> `ExecutionSafeguardService` -> `SmartRequest` -> 実送信可否判定。
  - `ExecutionSafeguardService` -> `MethodRiskPolicy` + `PayloadRiskPolicy` + endpoint approval cache / HITL -> `allow | deny | require_hitl` の共通判定。
  - SQLi payload -> `PayloadRiskPolicy` -> Bug Bounty なら block / CTF なら許容条件評価 -> request 実行。
  - `attack_inject` task -> mutating lane 判定 -> allowlist / HITL / state assertion -> specialist 実行可否。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - 実行モード: `bugbounty | ctf | vulntest | other compatible aliases`
  - HTTP method: `GET/POST/PUT/DELETE/PATCH`
  - injection payload: specialist が生成する SQLi 試行文字列
  - runtime approval context: `RequestGuard` callback / allowlist / task approval 情報
- **出力/結果 (Output):**
  - 成功時: Bug Bounty 既定で安全側の mode 解決と、承認済み endpoint のみ mutating request が通る。
  - 失敗時: 未承認 mutating request は統合済みセーフガードサービス経由で停止し、危険 SQL payload は明示 reason を付けて fail-closed で停止する。
  - CTF 時: 既存の time-based / POST probing 能力を維持しつつ、Bug Bounty との差分が設定とテストで明文化される。
- **制約・ルール:**
  - `SmartSQLiHunter` のデフォルト mode は `ctf` ではなく `bugbounty` を正本に寄せる。CTF の自由実行は明示モード指定時のみ有効化する。
  - Bug Bounty で `POST/PUT/DELETE/PATCH` を送る経路は、specialist 直送でも共通セーフガードサービスを必ず通す。
  - payload 文字列レベルで `DELETE FROM`, `UPDATE ... SET`, `INSERT INTO`, `DROP TABLE`, `TRUNCATE`, `ALTER` を検知し、Bug Bounty では deny を既定とする。
  - time-based blind SQLi (`SLEEP`, `pg_sleep`, `WAITFOR DELAY`, `BENCHMARK`, `randomblob`) はプロファイル別に制御可能とし、少なくとも Bug Bounty では明示ポリシー下で動かす。
  - CTF と Bug Bounty の差分は暗黙分岐にせず、mode / policy / tests の3点で確認可能にする。
  - 既存の `RequestGuard` ADR と lane fail-closed 方針に反する bypass は導入しない。`RequestGuard` は削除前提ではなく、共通セーフガードサービスに統合または adapter 化する。
  - 共通セーフガードサービスは少なくとも `SafeguardDecision` 相当の DTO を返し、`allowed`, `requires_hitl`, `reason_code`, `matched_rules` を他モジュールが読めるようにする。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 現状の mode 解決経路と public behavior を棚卸しし、`SmartSQLiHunter` を含む injection specialist のデフォルト mode を `bugbounty` に統一する変更点を特定する。CLI / config / task config の優先順位、`bugbounty` と `ctf` の差分表、既存の互換パスをここで固定する。
- [ ] ステップ2: HTTP method guard と payload guard をまとめる共通セーフガードサービスを設計する。`RequestGuard` の endpoint 承認キャッシュと HITL 判定をどの境界で統合するかを決め、`SafeguardDecision` DTO、reason code、`allow|deny|require_hitl` 契約を定義する。
- [ ] ステップ3: セーフガードの責務分割を明文化する。`ExecutionSafeguardService` facade、`MethodRiskPolicy`、`PayloadRiskPolicy`、既存 `RequestGuard` / `EnhancedEthicsGuard` の adapter 境界、rule source の正本を決め、巨大な単一クラス化を避ける。
- [ ] ステップ4: endpoint 承認キャッシュの mode/session/origin 単位の分離方針を定義し、mode 切替・セッション再開・並列実行で承認状態が混線しないキー設計と reset 条件を決める。
- [ ] ステップ5: `SmartRequest` を共通セーフガードサービスの呼び出し点に置き換える。Bug Bounty での `POST/PUT/DELETE/PATCH` は必ず HITL 必須とし、callback 不在時は fail-open ではなく fail-closed になることを確認する。
- [ ] ステップ6: `PayloadRiskPolicy` を実装し、`DELETE/UPDATE/INSERT/DROP/TRUNCATE/ALTER` の deny ルールを specialist 非依存の共通判定として追加する。HTTP method とは独立に payload 文字列単位で止め、複数モジュールから参照可能にする。
- [ ] ステップ7: time-based SQLi の扱いを整理する。`SLEEP` 系の blind probe を profile / mode ごとに制御できる policy とし、Bug Bounty の既定挙動、HITL checkpoint、CTF 例外、緊急 rollback 用 override を定義する。
- [ ] ステップ8: 共通セーフガードサービスの観測性を追加する。deny / require_hitl / approved / adapter fallback / timeout を reason code 付きで監査ログ・メトリクス・テストから追跡できるようにする。
- [ ] ステップ9: targeted unit tests を追加する。少なくとも共通セーフガードサービス、`SmartRequest`, `RequestGuard`, `SmartSQLiHunter`, `ActionAdmissionPolicy` について、Bug Bounty default / CTF override / dangerous SQL block / HITL required / cache namespace / timeout / async failure を検証する。
- [ ] ステップ10: 影響範囲の広い回帰を最小限で確認する。injection manager 経由の起動、mutating lane 設定、既存の POST 系 specialist や補助モジュールが同一サービスを参照できるかを関連テストで確認する。
- [ ] ステップ11: 変更した public behavior と運用ルールを計画書/ADR/関連ドキュメントへ反映し、fallback/rollback 手順と非対象スコープを明記してから実装完了とする。

## 5. 懸念点と対策

### 5.1 SRE / インフラエンジニア観点
- [ ] 【発生確率:高】【影響度:大】mode の既定値が CLI / config / specialist 初期値でずれると、Bug Bounty なのに CTF 扱いで fail-open になる可能性がある。
  - 具体的な計画書への修正案: mode 解決順序と public behavior matrix を先に固定するステップを追加し、`bugbounty`/`ctf` の差分を計画段階で明文化する。
- [ ] 【発生確率:中】【影響度:大】endpoint 承認キャッシュが mode・session・origin をまたいで再利用されると、別コンテキストで危険リクエストが誤許可される可能性がある。
  - 具体的な計画書への修正案: 承認キャッシュのキーを mode/session/origin を含む設計にし、mode 切替時 reset 条件をステップへ追加する。
- [ ] 【発生確率:高】【影響度:中】deny / require_hitl / allow の判定が観測できないと、運用時に「なぜ止まったか」「なぜ通ったか」が追えず、誤設定の切り分けが難しい。
  - 具体的な計画書への修正案: reason code 付き監査ログ・メトリクス・イベント出力を追加し、Step で observability 実装とテストを必須にする。
- [ ] 【発生確率:中】【影響度:中】並列実行中に承認状態やガード判定が競合すると、同一 endpoint の HITL 状態が不整合になる可能性がある。
  - 具体的な計画書への修正案: キャッシュ更新と判定順序の並行性前提を設計タスクに含め、cache namespace / async failure テストを追加する。

### 5.2 ソフトウェアアーキテクト観点
- [ ] 【発生確率:高】【影響度:大】`RequestGuard` と `EnhancedEthicsGuard` と新サービスを無造作に統合すると、責務が肥大化したモノリスになり保守不能になる。
  - 具体的な計画書への修正案: facade / `MethodRiskPolicy` / `PayloadRiskPolicy` / adapter の分割を明示し、巨大単一クラス化を避ける Step を追加する。
- [ ] 【発生確率:高】【影響度:大】危険 SQL パターン定義が複数箇所に散ると、将来の更新でルールが食い違い、片方だけ防げない状態になる。
  - 具体的な計画書への修正案: rule source の正本を1つに決め、既存ガードは adapter 参照に寄せる方針を計画へ追記する。
- [ ] 【発生確率:中】【影響度:中】共通サービスの API が曖昧だと、specialist ごとに独自解釈が生まれ、再び直接ガードを呼ぶ分岐が増える。
  - 具体的な計画書への修正案: `SafeguardDecision` DTO と共通 entry point 契約を早期定義し、他モジュールはその DTO のみを見ると明記する。
- [ ] 【発生確率:中】【影響度:中】適用対象を一度に広げすぎると、設計の正しさが検証できないまま多モジュール改修になる。
  - 具体的な計画書への修正案: core path を `SmartRequest`/`SmartSQLiHunter`/`RequestGuard` に限定して先行統合し、その後に補助モジュールへ横展開する段階化を Step に反映する。

### 5.3 デバッガー観点
- [ ] 【発生確率:高】【影響度:中】deny 時に reason code や matched rule が残らないと、誤検知か仕様通りかを再現できず、デバッグが長引く。
  - 具体的な計画書への修正案: `SafeguardDecision` に `reason_code` と `matched_rules` を必須化し、deny/allow の診断可能性を設計要件に追加する。
- [ ] 【発生確率:中】【影響度:大】fail-closed 経路で callback 不在・timeout・例外発生が重なると、想定外の broad fallback が入りやすい。
  - 具体的な計画書への修正案: callback 不在、timeout、async failure を個別にテスト観点へ追加し、回復ではなく停止を正とすることを Step に明記する。
- [ ] 【発生確率:中】【影響度:中】mode 切替・session resume・cache reset が絡むケースはバグが再現しづらく、単発テストだけでは取りこぼしやすい。
  - 具体的な計画書への修正案: mode matrix と cache namespace のテスト fixture を追加し、resume 相当の状態遷移も回帰に含める。
- [ ] 【発生確率:中】【影響度:中】time-based SQLi policy が profile ごとに曖昧だと、「止めるべきだったのに通った」「通すべきだったのに止まった」の判断が困難になる。
  - 具体的な計画書への修正案: `bugbounty`/`ctf` ごとの time-based policy table を作り、HITL checkpoint 条件を Step で固定する。

### 5.4 CTO観点
- [ ] 【発生確率:高】【影響度:大】共通セーフガードサービス導入と同時に全 specialist へ一気に適用すると、スコープが膨らみ、コア安全性の完成前に実装が拡散する。
  - 具体的な計画書への修正案: Phase 1 を core path 先行、Phase 2 を横展開に分ける段階化を計画に明記する。
- [ ] 【発生確率:中】【影響度:大】既定 mode を `bugbounty` に変える変更は public behavior change なので、既存運用・デモ・CTF ワークフローを壊すリスクがある。
  - 具体的な計画書への修正案: public behavior 変更の文書更新と、緊急時に `ctf`/互換モードへ戻せる override/rollback 手順を Step に追加する。
- [ ] 【発生確率:中】【影響度:大】time-based や高リスク SQL payload のガバナンスが曖昧なままだと、「安全に止める仕組み」を入れたのに組織判断の境界が残る。
  - 具体的な計画書への修正案: action class ごとの policy matrix と HITL 必須条件を明文化し、ADR/関連 docs まで更新対象に含める。
- [ ] 【発生確率:中】【影響度:中】新サービスがブラックボックス化すると、将来のレビューで「どのルールが経営判断で入ったか」が追跡しづらい。
  - 具体的な計画書への修正案: SoD・rule source・rollback 条件を ADR レベルでも補足し、実装完了条件にドキュメント反映を含める。

### 5.5 継続的な技術的負債 / 横展開メモ
- [ ] `SmartSQLiHunter` 以外の specialist が独自に mutating request を送る経路にも同等の判定を適用する必要がある。- 共通セーフガードサービスを entry point にし、XSS / Cmd / second-order / distributed SQLi 系へ順次横展開する。
- [ ] time-based blind SQLi は Bug Bounty でも有用だが、誤差・高ノイズ・運用摩擦が大きい。- profile 別 opt-in / HITL checkpoint / low-noise 条件を次段で詰める。

### 5.6 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0329-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
