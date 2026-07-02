---
task_id: SGK-2026-0068
doc_type: roadmap
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-26'
updated_at: '2026-07-02'
---

1. 次に完成させるべきサブエージェント（Bug Bounty優先度順）
DVWAに特化せず、「実際のBug Bountyで頻出かつ致命的」なものを優先します。

🥇 優先度1: API Security & IDOR (BOLA) Specialist
対応するDVWA: API Security, Auth Bypass
理由: 現代のBug Bounty（特にSaaSやReact/Next.jsなどのSPA）では、APIの認証不備（IDOR/BOLA）が最も稼げる脆弱性です。
AIがやるべきこと:
エンドポイントのバージョンダウングレード（/v2/user -> /v1/user で隠し情報が露出しないかテスト）
パラメータやJSONボディのID書き換え（{"user_id": 123} -> {"user_id": 124}）
メソッドの変更（GET -> PUT/DELETE など）
Adminと一般ユーザーのTokenを入れ替えてのアクセス制御テスト
所属: LogicManager または AuthManager の配下。
🥈 優先度2: XSS Specialist (Stored & Reflected)
対応するDVWA: XSS(Reflected), XSS(Stored)
理由: 非常に頻出します。ただし、AIがただのペイロードリストを投げるだけでなく、「入力値がどこに、どうサニタイズされて反射しているか」をLLMに推論させ、「<がエスケープされているなら、" onfocus="のような属性埋め込みに切り替える」といった知的なXSSハンター（WAF Bypass）を作ると強力です。
所属: 

InjectionManager
 の配下。
🥉 優先度3: Command Injection / SSRF Specialist
対応するDVWA: Command Injection
理由: 見つけるのは難しいですが、影響度がCriticalになります。特定のパラーメータ名（?ip=, ?daemon=, ?url=）に対して集中的にペイロードを投げるエージェントとして実装コストが低いです。
🛑 今回スキップを推奨するもの:

Brute Force: IPBANやWAFに弾かれるだけでAIの推論を活かせません。単純なツール（ffuf/hydra）の仕事です。
CSP Bypass / Javascript Attacks: 非常に高度で人間でも時間がかかる領域です。DVWAのCTF要素が強く、まずは基本的なXSSやAPIの探索を完了させてから挑むべきエンドゲームです。


2. 他にSHIGOKUと先に連携しておくと強力なMCP
Bug Bountyに特化するなら、以下のMCPがSHIGOKUの破壊力を格段に上げます。

Exa Web Search / Brave Search MCP (調査用)
理由: あるポートやCMS（例：WordPress 6.1）を発見した際、AIが「WordPress 6.1 exploit PoC github」で自動的に検索し、最新の攻撃エクスプロイトをWebから取得して使用できるようになります。
GitHub MCP (ソースコード・シークレット漏洩)
理由: Reconの初期段階でターゲット企業のドメイン名からGitHubを検索し、「うっかりPublicリポジトリにコミットされたAPIキーや内部コード」をAIが自動で探しに行く（GitHub Dorks）ことができます。（※Antigravity標準の github-mcp-server がそのまま使えます）。
Shodan/Censys MCP (将来的な外部ASPM)
Webの枠を超えて、ターゲット企業の漏れているデータベース（Elasticsearch等）や開発用サーバーをIPアドレスベースで発掘します。