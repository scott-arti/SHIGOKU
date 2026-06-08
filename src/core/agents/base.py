from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from src.core.workspace.shared_workspace import SharedWorkspace
from src.tools.builtin.handoff import HandoffTool

class AgentConfig(BaseModel):
    """
    Agent Configuration
    """
    model_config = ConfigDict(extra='allow')

    name: str
    description: str
    model: str
    instructions: str
    tools: List[Any] = Field(default_factory=list)

    def get(self, key: str, default: Any = None) -> Any:
        """Dictionary-like get for compatibility."""
        return getattr(self, key, default)

class BaseAgent(ABC):
    """
    Abstract Base Class for all agents.
    Defines the common interface for processing messages.
    """
    
    def __init__(
        self,
        config: Dict[str, Any],
        project_manager: Optional[Any] = None,
        master_conductor: Any = None,
        workspace_root: Optional[Union[str, Path]] = None,
        **kwargs
    ) -> None:
        self.config = AgentConfig(**config) if isinstance(config, dict) else config
        self.project_manager = project_manager
        self.master_conductor = master_conductor
        self._workspace_root = workspace_root
        self._history: List[Dict[str, Any]] = []
        self.messages: List[Dict[str, Any]] = []
        self.current_context: Optional[Dict[str, Any]] = None  # Task Execution Context
        
        # LLM Client integration (from Agent class)
        from src.core.models.llm import LLMClient
        self.llm = LLMClient(model=self.config.model)

        # Handoff Mechanism Integration
        has_handoff = any(isinstance(t, HandoffTool) or getattr(t, "name", "") == "handoff" for t in self.config.tools)
        if not has_handoff:
            self.config.tools.append(HandoffTool())

        self._initialize_system_prompt()
        
    def _initialize_system_prompt(self):
        """Initialize the messages list with the system prompt."""
        instructions = self.config.instructions
        
        # ワークスペースパスが指定されている場合、システムプロンプトに注入
        if self.workspace_root:
            workspace_instruction = (
                f"\n\n## 重要: ワークスペースの利用\n"
                f"ファイルを出力または保存する際は、必ず以下のディレクトリ配下を使用してください:\n"
                f"Path: {self.workspace_root}\n"
                f"ファイル名には必ず一意性を持たせる（タイムスタンプ等）か、指示されたパスを厳守してください。\n"
                f"例: {self.workspace_root}/artifacts/scan_result_20251224.txt"
            )
            instructions += workspace_instruction
            
        self.messages.append({
            "role": "system", 
            "content": instructions
        })
        
    @property
    def workspace_root(self) -> Optional[Union[str, Path]]:
        return self._workspace_root
        
    @property
    def name(self) -> str:
        return self.config.name
    
    @property
    def description(self) -> str:
        return self.config.description

    @property
    def model(self) -> str:
        return self.config.model

    @property
    def instructions(self) -> str:
        return self.config.instructions

    @property
    def workspace(self) -> SharedWorkspace:
        """Lazy initialization of SharedWorkspace"""
        if not hasattr(self, "_workspace_instance") or self._workspace_instance is None:
            # SharedWorkspace.__init__ only takes workspace_root (str)
            # Ensure it is a string if it's a Path
            ws_root = str(self._workspace_root) if self._workspace_root else "./workspace"
            self._workspace_instance = SharedWorkspace(workspace_root=ws_root)
        return self._workspace_instance
        
    @abstractmethod
    async def process(self, input_message: str) -> str:
        """
        Process a user input and return a response.
        Must be implemented by subclasses.
        """
        pass

    async def close(self):
        """
        Release resources (e.g., network sessions).
        Should be overridden by subclasses if they manage their own resources.
        """
        pass

    async def _ingest_if_available(self, url: str, body: Optional[str] = None, role: Optional[str] = None):
        """レスポンスからIDを抽出して共有ワークスペースに蓄積（存在する場合のみ）"""
        if self.workspace:
            try:
                # 共有ワークスペースの統一APIを呼び出す
                self.workspace.ingest_response(url, body, role)
            except Exception as e:
                # 基底クラスでのエラーはログに留める
                import logging
                log = logging.getLogger(__name__)
                log.debug("Automatic ID ingestion failed: %s", e)

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """AgentProtocol準拠の統一実行メソッド (Phase 1: ADR-002)
        
        内部で既存の process() を呼び出し、結果を統一フォーマットに変換。
        
        Args:
            task: タスクパラメータ辞書
                - target: ターゲットURL/ドメイン
                - action: 実行アクション (optional)
                - params: 追加パラメータ (optional)
        
        Returns:
            実行結果辞書 (create_run_result() 形式)
        """
        from src.core.agents.protocol import create_run_result
        
        try:
            target = task.get("target", "")
            action = task.get("action", "")
            params = task.get("params", {})
            
            # コンテキストを保存 (execute_tool_with_guardrail で使用)
            self.current_context = params
            
            # process() への入力を構築
            input_message = f"Target: {target}\nAction: {action}"
            if params:
                import json
                input_message += f"\nParams: {json.dumps(params, ensure_ascii=False)}"
            
            result = await self.process(input_message)
            
            return create_run_result(
                success=True,
                data={"output": result},
                agent=self.name
            )
        except Exception as e:
            return create_run_result(
                success=False,
                error=str(e),
                agent=self.name
            )
        finally:
            self.current_context = None  # Clean up

    def add_message(self, role: str, content: str):
        """Add a message to the history."""
        self.messages.append({"role": role, "content": content})
        self._prune_messages()

    def _prune_messages(self, max_messages: int = 40):
        """
        メッセージ履歴が長くなりすぎないように整理する。
        システムメッセージ（通常インデックス0）を保持しつつ、直近の会話を残す。
        """
        if len(self.messages) <= max_messages:
            return
            
        system_msg = None
        if self.messages and self.messages[0].get("role") == "system":
            system_msg = self.messages[0]
            
        # 直近のメッセージを残す
        keep_count = max_messages - (1 if system_msg else 0)
        recent_messages = self.messages[-keep_count:]
        
        if system_msg:
            self.messages = [system_msg] + recent_messages
        else:
            self.messages = recent_messages
    def get_tools_schema(self) -> List[Dict[str, Any]]:
        """Convert tools to schema format."""
        schemas = []
        for tool in self.config.tools:
            if hasattr(tool, "to_schema"):
                schemas.append(tool.to_schema())
        return schemas
    
    # ===========================================
    # Guardrail Integration
    # ===========================================
    
    def check_input_guardrail(self, user_input: str) -> tuple[bool, str | None]:
        """
        入力ガードレールを実行
        
        全エージェントで統一的にInput Guardrailを適用するための共通メソッド。
        子クラスのprocess()内で呼び出すことを推奨。
        
        Returns:
            (is_safe, reason): 安全ならTrue, 危険ならFalseと理由
        """
        from src.core.security.guardrails import check_input
        return check_input(user_input)
    
    def check_output_guardrail(self, command_or_code: str) -> tuple[bool, str | None]:
        """
        出力ガードレールを実行（ツール実行前のコマンド/コード検査）
        
        コマンド実行やコード実行の前に呼び出し、危険な操作をブロック。
        
        Returns:
            (is_safe, reason): 安全ならTrue, 危険ならFalseと理由
        """
        from src.core.security.guardrails import check_output
        return check_output(command_or_code)

    async def execute_tool_with_guardrail(
        self, 
        tool_name: str, 
        args: Dict[str, Any],
        tools: List[Any],
        context_params: Optional[Dict[str, Any]] = None  # New arg for context injection
    ) -> str:
        """
        ガードレール付きでツールを実行
        
        Args:
            tool_name: 実行するツール名
            args: ツールに渡す引数
            tools: 利用可能なツールのリスト
            context_params: タスク実行コンテキスト（Auth情報など）
            
        Returns:
            ツールの実行結果、またはブロックメッセージ
        """
        import asyncio
        
        # Use stored context if not provided explicitely
        if context_params is None:
            context_params = self.current_context
        
        # コマンド/コード系ツールの場合、事前検査
        COMMAND_TOOLS = ("linux_cmd", "python_code", "shell", "code", "bash")
        if tool_name in COMMAND_TOOLS:
            # commandまたはcodeパラメータを取得
            command = args.get("command", args.get("code", ""))
            if command:
                is_safe, reason = self.check_output_guardrail(command)
                if not is_safe:
                    return f"🛡️ Blocked by Output Guardrail: {reason}"
        
        # ツールを検索して実行
        for tool in tools:
            if getattr(tool, "name", "") == tool_name:
                
                # Auth Header Injection
                # NucleiTool, HttpxTool など headers を受け取れるツールに注入
                if context_params and "auth_headers" in context_params:
                    # tool.to_schema() をチェックして headers を受け入れるか確認すべきだが
                    # 簡易的に tool_name や属性で判定
                    
                    # NucleiToolは headers 引数を持つ (直前に修正済み)
                    # HttpxTool も wrapper 経由で -H をサポート (直前に修正済み)
                    # KatanaTool も headers をサポート (直前に修正済み)
                    
                    # 既知のHeadersサポートツール
                    # Note: tool_name might differ from class name standard (e.g. "httpx" vs HttpxTool)
                    # We check if run method has 'headers' parameter or if it's one of known tools
                    import inspect
                    sig = inspect.signature(tool.run)
                    supports_headers = "headers" in sig.parameters
                    
                    if supports_headers:
                        # 既に args に headers がある場合はマージ
                        current_headers = args.get("headers", [])
                        if isinstance(current_headers, str): # JSON strの場合
                             try: import json; current_headers = json.loads(current_headers)
                             except: current_headers = [current_headers]
                        
                        injected_headers = context_params["auth_headers"]
                        if isinstance(injected_headers, dict): # Dict -> List["Key: Val"]
                            injected_list = [f"{k}: {v}" for k, v in injected_headers.items()]
                            # 重複排除しつつマージ (単純連結)
                            current_headers.extend(injected_list)
                        elif isinstance(injected_headers, list):
                            current_headers.extend(injected_headers)
                            
                        args["headers"] = current_headers
                
                # ツール実行: 同期/非同期を判定して適切に呼び出す
                if asyncio.iscoroutinefunction(tool.run):
                    return await tool.run(**args)
                else:
                    return await asyncio.to_thread(tool.run, **args)
        
        return f"Error: Tool {tool_name} not found."
    
    # ===========================================
    # Self-Healing Capabilities
    # ===========================================
    
    async def retry_with_adaptation(
        self, 
        error: Exception, 
        context: Dict[str, Any],
        max_retries: int = 3
    ) -> Optional[Dict[str, Any]]:
        """
        エラーに基づいて適応的リトライを実行
        
        Args:
            error: 発生したエラー
            context: 実行コンテキスト（url, method, headers等）
            max_retries: 最大リトライ回数
        
        Returns:
            成功時は結果辞書、失敗時はNone
        """
        import asyncio
        import random
        import logging
        
        logger = logging.getLogger(__name__)
        
        error_str = str(error).lower()
        retry_count = context.get("_retry_count", 0)
        
        if retry_count >= max_retries:
            logger.warning("Max retries (%d) reached for %s", max_retries, context.get("url"))
            return None
        
        context["_retry_count"] = retry_count + 1
        
        # 適応戦略を決定
        adaptation = self._determine_adaptation(error_str)
        
        if adaptation == "proxy_rotate":
            context = self._apply_proxy_rotation(context)
            logger.info("Applied proxy rotation (retry %d/%d)", retry_count + 1, max_retries)
        
        elif adaptation == "rate_limit":
            delay = self._calculate_backoff_delay(retry_count)
            logger.info("Rate limited, waiting %.1fs (retry %d/%d)", delay, retry_count + 1, max_retries)
            await asyncio.sleep(delay)
        
        elif adaptation == "waf_bypass":
            context = self._apply_waf_bypass(context)
            logger.info("Applied WAF bypass headers (retry %d/%d)", retry_count + 1, max_retries)
        
        elif adaptation == "timeout_extend":
            context["timeout"] = context.get("timeout", 30) * 2
            logger.info("Extended timeout to %ds (retry %d/%d)", context["timeout"], retry_count + 1, max_retries)
        
        return {"adapted_context": context, "adaptation": adaptation, "retry": retry_count + 1}
    
    # ===========================================
    # Workspace Helpers
    # ===========================================
    
    async def save_finding(self, finding: Dict[str, Any] | Any) -> str:
        """
        発見を共有ワークスペースに非同期で保存
        """
        if self.workspace:
            return await self.workspace.save_finding(finding)
        return ""

    async def save_intel(self, intel_type: str | None = None, data: Dict[str, Any] = None) -> str:
        """
        偵察情報を非同期で保存
        """
        if not data:
            return ""
            
        type_name = intel_type or self.name
        if self.workspace:
            return await self.workspace.save_intel(type_name, data)
        return ""
    
    def _determine_adaptation(self, error_str: str) -> str:
        """エラーに基づいて適応戦略を決定"""
        if "403" in error_str or "forbidden" in error_str:
            return "waf_bypass"
        elif "429" in error_str or "rate" in error_str or "too many" in error_str:
            return "rate_limit"
        elif "timeout" in error_str or "timed out" in error_str:
            return "timeout_extend"
        elif "connection" in error_str or "refused" in error_str:
            return "proxy_rotate"
        else:
            return "rate_limit"  # デフォルトは待機
    
    def _apply_proxy_rotation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """プロキシローテーションを適用"""
        # 環境変数からプロキシリストを取得
        import os
        proxy_list = os.getenv("SHIGOKU_PROXY_LIST", "").split(",")
        proxy_list = [p.strip() for p in proxy_list if p.strip()]
        
        if proxy_list:
            import random
            context["proxy"] = random.choice(proxy_list)
        
        return context
    
    def _calculate_backoff_delay(self, retry_count: int) -> float:
        """指数バックオフ + ジッターを計算"""
        import random
        base_delay = 2 ** retry_count  # 2, 4, 8, 16...
        jitter = random.uniform(0, base_delay * 0.5)
        return min(base_delay + jitter, 60)  # 最大60秒
    
    def _apply_waf_bypass(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """WAFバイパスヘッダーを適用（設定で有効時のみ）"""
        import random
        import os
        
        # WAFバイパスが無効の場合は何もしない
        if not self._should_apply_waf_bypass():
            return context
        
        headers = context.get("headers", {})
        
        # 一般的なWAFバイパスヘッダー
        bypass_headers = [
            {"X-Forwarded-For": f"127.0.0.{random.randint(1, 254)}"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
        ]
        
        # ランダムに選択して追加
        selected = random.choice(bypass_headers)
        headers.update(selected)
        
        # User-Agentローテーション
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
        ]
        headers["User-Agent"] = random.choice(user_agents)
        
        context["headers"] = headers
        return context
    
    def _should_apply_waf_bypass(self) -> bool:
        """
        WAFバイパス機能が有効か判定
        
        制御方法:
        1. 環境変数: SHIGOKU_WAF_BYPASS_ENABLED=true
        2. デフォルト: false（安全側）
        """
        import os
        return os.getenv("SHIGOKU_WAF_BYPASS_ENABLED", "false").lower() == "true"
