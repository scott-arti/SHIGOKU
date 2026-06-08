"""
Master Conductor 専用プロンプト

動的質問生成とコンテキスト充足判定用のプロンプトを定義。
"""

# ===== 動的質問生成プロンプト =====
DYNAMIC_QUESTION_PROMPT = """あなたはセキュリティ診断のプラニング担当です。

ユーザーとの対話からターゲット情報を収集しています。
以下のコンテキストを分析し、**不足している重要な情報**があれば追加質問を1-2個生成してください。

## 現在のモード
{mode}

## 収集済みコンテキスト
{context}

## モード別の必須情報
- bugbounty: ターゲット、プログラム名、スコープ、注力したい脆弱性タイプ
- ctf: ターゲット、問題文、ヒント、制限事項
- vulntest: ターゲット、診断範囲、認証情報の有無、除外エンドポイント

## 出力形式
追加質問が必要な場合:
```json
{{"questions": ["質問1", "質問2"], "reason": "不足している情報の説明"}}
```

十分な情報がある場合:
```json
{{"questions": [], "reason": "sufficient"}}
```
"""

# ===== コンテキスト充足判定プロンプト =====
CONTEXT_SUFFICIENCY_PROMPT = """以下のコンテキストでセキュリティ診断を開始できるか判定してください。

## モード
{mode}

## コンテキスト
{context}

## 判定基準
- ターゲットが明確に指定されているか
- モードに応じた最低限の情報があるか

## 出力
```json
{{"sufficient": true/false, "missing": ["不足情報1", "不足情報2"]}}
```
"""

# ===== Human-in-the-loop 確認プロンプト =====
HITL_DECISION_PROMPT = """以下のタスク実行結果について、ユーザーへの確認が必要か判定してください。

## タスク情報
- タスク名: {task_name}
- エージェント: {agent_type}
- アクション: {action}

## 実行結果
{result}

## 確認が必要なケース
1. HIGH/CRITICAL severity の脆弱性を発見した
2. 攻撃的なアクション（SQLi, 認証バイパス等）を実行しようとしている
3. スコープ外のリソースにアクセスしようとしている
4. 重要な方針変更が必要

## 出力
```json
{{
  "requires_approval": true/false,
  "reason": "確認理由",
  "severity": "info/warning/critical",
  "summary": "ユーザーに表示するサマリー"
}}
```
"""

# ===== チャット応答生成プロンプト =====
CHAT_RESPONSE_PROMPT = """あなたはセキュリティ診断のMaster Conductor（司令塔）です。

ユーザーからの入力に対して適切に応答してください。

## 現在のモード
{mode}

## 収集済みコンテキスト
{context}

## ユーザー入力
{user_input}

## 応答ルール
1. 情報収集フェーズの場合：
   - ユーザーの回答を確認し、必要に応じて追加質問
   - 「done」「完了」「ok」と言われたら情報収集を終了
   
2. 十分な情報が集まった場合：
   - 「情報収集完了」と伝え、プラン作成に進む旨を説明

3. 常に：
   - 簡潔で専門的な応答
   - 日本語で応答
   - 不明な点があれば確認
"""


def get_dynamic_question_prompt(mode: str, context: dict) -> str:
    """動的質問生成用プロンプトを取得"""
    try:
        from src.prompts import get_renderer
        return get_renderer().render("conductor/dynamic_question.md", {
            "mode": mode,
            "context": context
        })
    except Exception:
        # フォールバック: レガシープロンプト
        import json
        return DYNAMIC_QUESTION_PROMPT.format(
            mode=mode,
            context=json.dumps(context, ensure_ascii=False, indent=2)
        )


def get_context_sufficiency_prompt(mode: str, context: dict) -> str:
    """コンテキスト充足判定用プロンプトを取得"""
    try:
        from src.prompts import get_renderer
        return get_renderer().render("conductor/context_sufficiency.md", {
            "mode": mode,
            "context": context
        })
    except Exception:
        # フォールバック: レガシープロンプト
        import json
        return CONTEXT_SUFFICIENCY_PROMPT.format(
            mode=mode,
            context=json.dumps(context, ensure_ascii=False, indent=2)
        )


def get_hitl_decision_prompt(task_name: str, agent_type: str, action: str, result: dict) -> str:
    """HITL判定用プロンプトを取得"""
    try:
        from src.prompts import get_renderer
        return get_renderer().render("conductor/hitl_decision.md", {
            "task_name": task_name,
            "agent_type": agent_type,
            "action": action,
            "result": result
        })
    except Exception:
        # フォールバック: レガシープロンプト
        import json
        return HITL_DECISION_PROMPT.format(
            task_name=task_name,
            agent_type=agent_type,
            action=action,
            result=json.dumps(result, ensure_ascii=False, indent=2)
        )


def get_chat_response_prompt(mode: str, context: dict, user_input: str) -> str:
    """チャット応答生成用プロンプトを取得"""
    try:
        from src.prompts import get_renderer
        return get_renderer().render("conductor/chat_response.md", {
            "mode": mode,
            "context": context,
            "user_input": user_input
        })
    except Exception:
        # フォールバック: レガシープロンプト
        import json
        return CHAT_RESPONSE_PROMPT.format(
            mode=mode,
            context=json.dumps(context, ensure_ascii=False, indent=2),
            user_input=user_input
        )


# ===== プラン生成プロンプト (Phase 3) =====
# NOTE: レガシープロンプト定数は移行完了後に削除予定
PLANNING_PROMPT = """あなたは自律型セキュリティ診断エンジンのプランナーです。
現在の状況とユーザーの要求に基づいて、次に実行すべき攻撃または調査タスクを計画してください。

## ユーザーの要求
{goal}

## 現在のコンテキスト
{context}

## 自己省察からの教訓 (Self-Reflection Insights)
{insights}

## 利用可能なエージェント
[
    {"name": "scope_parser", "desc": "スコープや禁止事項の検証"},
    {"name": "cartographer", "desc": "エンドポイント探索、サブドメイン収集"},
    {"name": "fingerprinter", "desc": "技術スタック特定"},
    {"name": "vuln_scanner", "desc": "既知の脆弱性スキャン"},
    {"name": "spider_crawler", "desc": "高度なクローリング"},
    {"name": "secret_finder", "desc": "機密情報の検出"},
    {"name": "jwt_inspector", "desc": "JWTトークンの検証・バイパス試行"},
    {"name": "oauth_dancer", "desc": "OAuth/OIDCの脆弱性検証"},
    {"name": "mfa_bypasser", "desc": "MFAバイパスの試行"},
    {"name": "biz_logic_hunter", "desc": "ビジネスロジック脆弱性検証"}
]

## 出力形式
実行すべきタスクのリストを以下のJSON形式で出力してください。
優先順位の高い順（priority: 100〜1）に並べてください。
タスクが依存を持つ場合は parent_id を指定してください。

```json
{{
  "tasks": [
    {{
      "id": "task_unique_id",
      "name": "タスク名",
      "agent": "使用するエージェント名",
      "action": "実行するアクション",
      "priority": 90,
      "params": {{
        "target": "対象URL",
        "option1": "value1"
      }},
      "reason": "このタスクを選んだ理由"
    }}
  ]
}}
```

## 注意事項 (Ethics & Optimization)
- コンテキストの`ActionHistory`を参照し、同じタスクの重複実行を避けてください。
- **自己省察からの教訓**を最優先で考慮してください。過去に失敗した手法は避け、成功率の高いエージェントや手法を優先してください。
- スコープ外への攻撃は提案しないでください。
- 破壊的なアクションは慎重に計画してください。
"""


def get_planning_prompt(goal: str, context: dict, insights: list = None) -> str:
    """プラン生成用プロンプトを取得"""
    try:
        from src.prompts import get_renderer
        return get_renderer().render("conductor/planning.md", {
            "goal": goal,
            "context": context,
            "insights": insights or []
        })
    except Exception:
        # フォールバック: レガシープロンプト
        import json
        return PLANNING_PROMPT.format(
            goal=goal,
            context=json.dumps(context, ensure_ascii=False, indent=2),
            insights=json.dumps(insights or [], ensure_ascii=False, indent=2)
        )


# ===== ReAct観察プロンプト (Phase 4) =====
REACT_OBSERVATION_PROMPT = """あなたはセキュリティ診断のエキスパートです。
以下のタスク実行結果を分析し、**追加で試すべき攻撃ベクトル**を提案してください。

## 完了したタスク
{task_name}

## 実行結果
{task_result}

## ターゲットの技術スタック
{tech_stack}

## RAGからのヒント
{rag_hints}

## 提案ルール
1. 結果から推測できる新しい攻撃面を特定
2. 既に試行済みの手法は除外
3. 技術スタックに適した攻撃を優先
4. 最大2個まで

## 出力形式
```json
{{
  "additional_attacks": [
    {{
      "name": "攻撃タスク名",
      "agent_type": "使用するエージェント",
      "action": "アクション名",
      "params": {{"key": "value"}},
      "rationale": "この攻撃を提案する理由"
    }}
  ],
  "observation": "結果から得られた洞察"
}}
```
"""


def get_react_observation_prompt(
    task_name: str,
    task_result: dict,
    tech_stack: list,
    rag_hints: list,
) -> str:
    """ReAct観察用プロンプトを取得"""
    try:
        from src.prompts import get_renderer
        return get_renderer().render("conductor/react_observation.md", {
            "task_name": task_name,
            "task_result": task_result,
            "tech_stack": tech_stack,
            "rag_hints": rag_hints,
        })
    except Exception:
        # フォールバック: レガシープロンプト
        import json
        return REACT_OBSERVATION_PROMPT.format(
            task_name=task_name,
            task_result=json.dumps(task_result, ensure_ascii=False, indent=2)[:500],
            tech_stack=", ".join(tech_stack) if tech_stack else "不明",
            rag_hints="\n".join(rag_hints) if rag_hints else "なし",
        )
