---
task_id: SGK-2026-0113
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Specification: Phase 2 - Opaque Session & Auth Bypass Enhancement

## 1. 概要

SHIGOKUの認証・認可テスト機能を、JWT（JSON Web Token）以外の不透明なセッション管理方式（PHPのPHPSESSID、独自Cookie等）にも対応させる。
特にDVWA Mediumレベルで見られる「弱いセッションID（予測可能なID）」の検出と、認可不備（IDOR/権限昇格）テストにおけるCookie操作の自動化を実現する。

## 2. 変更範囲

- `src/core/models/finding.py`: 脆弱性タイプ（`WEAK_SESSION_ID`, `SESSION_FIXATION`）の追加。
- `src/core/attack/session_tester.py` (新規): Cookieエントロピー分析、予測可能性テスト、改変ペイロード生成ロジックの実装。
- `src/core/agents/swarm/auth_ninja.py`: `SessionInspector` エージェントを新規実装し、AuthNinja群に追加。
- `src/core/agents/swarm/biz_logic_hunter.py`: IDOR/権限昇格検証プロセスにおいて、機微と思われるCookie（uid, user, role等）の自動改変試行を追加。

## 3. 具体的な挙動

### 3.1 Session ID 分析 (`SessionInspector`)

- ターゲットへのリクエストを複数回（デフォルト5回）繰り返し、レスポンスの `Set-Cookie` からセッションIDを収集。
- 以下のパターンを自動検出：
  - **インクリメント**: IDが1ずつ増加している。
  - **ハッシュ化された低エントロピー**: MD5(1), MD5(2) のようなパターン。
  - **タイムスタンプベース**: 生成時刻がIDに含まれている。
- 予測可能な場合は `WEAK_SESSION_ID` としてFindingを生成。

### 3.2 Cookie 操作によるバイパス (`BizLogicHunter`)

- ログインセッションを維持したまま、以下のCookie改変を試行：
  - `admin=0` -> `admin=1`
  - `role=user` -> `role=admin`
  - `user=victim` -> `user=attacker` (IDORのCookie版)
- レスポンスの変化（ステータスコード、ボディ内容、管理者メニューの有無）で成功を判定。

### 3.3 汎用的な認可テストの強化

- `Authorization` ヘッダーが存在しなくても、`Cookie` ヘッダーを主権限情報として扱い、セッションを跨いだリソースアクセス（Cross-Session Matrix Testing）を実施する。

## 4. 制約と安全性

- **EthicsGuard連携**: 全ての改変リクエストは `ethics_guard.check_scope()` を通過させる。
- **低負荷試行**: セッション収集時のリクエスト間隔を `AdaptiveRateLimiter` で制御。
- **破壊的アクセスの禁止**: 削除エンドポイント等に対するテストは成功判定（200 OK）が出た時点で停止し、実際の削除実行は避ける。

## 5. 期待される成果

- DVWA Mediumの "Weak Session IDs" カテゴリを自動攻略可能になる。
- Cookieベースのセッション管理を行っている古いシステムや、独自実装のアプリケーションに対するスキャン精度が向上する。
