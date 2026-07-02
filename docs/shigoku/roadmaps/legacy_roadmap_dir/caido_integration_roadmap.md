---
task_id: SGK-2026-0069
doc_type: roadmap
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Roadmap: Unified Caido & Modern Web Scan Strategy

SHIGOKUを「Caido駆動型」の次世代ハッキングエンジンへと進化させるための詳細ロードマップです。

## Phase 1: 接続の信頼性と可視化（Infrastructure） [DONE]

**目的**: スキャン情報の「目」と「記憶」をCaidoに完全に同期させる。

1.  **プロキシ・ゲートキーパーの実装** [DONE]
    - `src/core/infra/network_client.py` にCaidoの死活監視を実装。
    - Caidoが停止している場合、スキャンを安全に中断しユーザーに通知する仕組みの構築。
2.  **Katana Headlessエンジンの強化** [DONE]
    - JSレンダリングおよび詳細解析フラグ（`-jc`, `-jsluicy`）の適用。
    - Katanaの全ての通信が漏れなくCaidoを通過することを保証。
3.  **グローバル・プロキシ・強制化** [DONE]
    - 偵察（Recon）だけでなく、脆弱性診断（Specialists）の全ての通信をプロキシ経由に変更。
    - 開発者がCaidoのHistoryを見るだけで、AIが何をしようとしているか完全に把握できるようにする。

## Phase 2: Caido MCP 連携と自動解析（Automation） [DONE]

**目的**: Caidoに蓄積された生情報をAIが読み取り、攻撃の起点にする。

1.  **Caido MCP Serverの統合** [DONE]
    - `caido-mcp-server` をAntigravityに登録し、AIがProxy HistoryやSitemapを検索可能にする。
2.  **Sitemap Parser Agentの構築** [DONE]
    - Katanaが見逃したかもしれない「JSが裏で投げているAPIリクエスト」をCaidoから抽出し、タスク化するAIモジュールの開発。
3.  **プロキシ情報に基づいたコンテキスト強化** [DONE]
    - 「Caidoのリクエスト #402 の認証ヘッダーをコピーして攻撃に使用する」といった、高度なコンテキスト伝搬の実装。

## Phase 3: プロキシ主導型攻撃エージェント（Attack）

**目的**: 実際のBug Bountyで高額賞金を狙えるエージェントをデプロイする。

1.  **API Security / IDOR Hunter**
    - Caidoのリプレイ機能を活用し、トークンの入れ替えやエンドポイントのバージョンダウングレード（v2->v1）を自律実行。
2.  **Intelligent XSS Expert**
    - 入力値が「ブラウザのどこで実行されるか（DOM Context）」をCaidoのレスポンス履歴から推論し、最適なWAF回避ペイロードを生成。
3.  **Logic Flaw Hunter (IDOR/BOLA)**
    - Caidoの履歴からUUIDやIDパラメータを特定し、他人のデータにアクセス可能かテストするロジックの実装。

## Phase 4: ハイブリッド・オペレーション（Experience）

**目的**: 人間とAIがCaidoを共有して共同作業を行う。

1.  **インタラクティブ解析依頼**
    - 「Caidoにあるこの`/admin`系のパスを重点的にスキャンして」といった、プロキシ内情報をキーにした会話型の指示に対応。
2.  **Findingsの同期**
    - SHIGOKUが見つけた脆弱性を、Caidoの「Findings」タブへ自動的にプッシュする。
