---
task_id: SGK-2026-0023
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-27'
updated_at: '2026-07-02'
---

# ADR: エンドポイント承認キャッシュによるガードレール競合の解決

## ステータス

承認済み / 実装完了 (2026-02-27)

## コンテキスト

SHIGOKUには「POST/PUT/DELETE等の破壊的メソッドを制限する」ガードレールが複数存在していたが、以下の問題が発生していた。

1.  **ガードレールの競合**: `AggressiveLimiter`（Dispatcher層）と `safe_mode`（エージェント層）が独立しており、意図しない二重ブロックや、逆にバイパスが発生していた。
2.  **探査効率の低下**: XSSやSQLiの探査エージェント（SmartXSSHunter等）が直接HTTPリクエストを発行する場合、Dispatcher層の制限をバイパスできてしまうか、あるいは逆にDispatcherで止まりすぎて1リクエストごとの試行錯誤（Thought Loop）が困難になっていた。
3.  **安全性の欠如**: 初期案の「エージェントの自己申告（intentフラグ）でガードを外す」方式は、エージェントが誤判断（XSSだと思って叩いたPOSTが実は記事削除だった等）をした場合に致命的な破壊を招くリスクがあった。

## 決定事項

「人間に依る一度の承認を、エンドポイント単位でキャッシュする」**RequestGuard** 方式を導入する。

### 1. RequestGuard の新設

ネットワーク層（`SmartRequest`）の直前に `RequestGuard` を配置する。

- 全ての `POST/PUT/DELETE/PATCH` メソッドに対し、**URLパスを正規化してキャッシュ**する。
- 例: `/api/users/1` へのPOSTリクエストを承認すると、`/api/users/{id}` が承認済みテーブルに登録される。
- 以後、同じエンドポイントに対する探査（100通りのペイロードテスト等）は、人間に再確認することなく自動的に許可される。

### 2. ガードレールの職務分掌（SoD）

- **AggressiveLimiter**: インフラ保護（RPS制限、同時実行制限）に専念する。HTTPメソッド自体の判定からは手を引く。
- **RequestGuard**: 倫理・安全保護（どこを叩いていいか、破壊操作の承認）を担当する。
- **Agent safe_mode**: 人間がタスクまたはエンドポイントを承認した場合（`user_approved` フラグ）には、自動的に安全モードを解除し、本格的なテストを許可する。

## 実装の詳細

1.  `src/core/security/request_guard.py`: 承認ロジックとパス正規化（ID/UUID/Hex）を実装。
2.  `src/core/infra/smart_request.py`: `RequestGuard` と連携し、リクエスト実行前に承認をチェック。
3.  `src/core/engine/swarm_dispatcher.py`: タスク承認時に `params['user_approved'] = True` を伝播。
4.  `src/core/agents/swarm/logic/idor.py`: `user_approved` なら内部の `safe_mode` をオフに切り替え。

## 影響

- **安全性**: 人間が一度も承認していない「初見のPOST先」は、AIがどう主張しようと必ずブロックされ、人間に判断を仰ぐ。
- **機動力**: XSSやSQLiのSpecialistは、Dispatcherに邪魔されることなく、一度承認された場所に対して高速にPayloadを試行できる。
- **UX**: 1つの脆弱性調査に対して何度も似たような承認ボタンを押す必要がなくなる。

## 代替案

- **Intent-Based Bypass**: エージェントが `intent="probe"` と言えば通す方式。エージェントが嘘を言ったり間違えたりした場合にノーガードになるため却下。
- **Dispatcher完全委任**: Dispatcherを通さないリクエストが全てノーガードになるため、Specialistのリサーチ自由度を奪うことになり却下。
