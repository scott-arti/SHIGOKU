"""
BaseManagerAgent: Phase 2 Hierarchical Swarm Manager

This class extends SwarmManager to provide LLM-driven task orchestration (Think-Act-Observe Loop).
It delegates tasks to Worker agents and executes tools based on LLM reasoning.

Implementation Plan Section: Core Architecture
"""

import asyncio
import logging
import json
import re
import inspect
from types import SimpleNamespace
from typing import List, Dict, Any, Optional, Tuple, Union, cast

from src.core.agents.swarm.base import SwarmManager, Specialist, Task, ContextSchema
from src.core.models.finding import Finding
from src.core.models.swarm import SwarmResult
from src.core.models.llm import LLMClient
from src.core.agents.protocol import create_run_result

logger = logging.getLogger(__name__)

class BaseManagerAgent(SwarmManager):
    """
    LLM駆動型マネージャーエージェント基底クラス
    
    特徴:
    1. Think-Act-Observe Loop (ReAct Like)
    2. 動的なWorker/Tool実行
    3. コンテキスト管理 (Working Memory)
    """
    
    # サブクラスで定義
    name: str = "BaseManager"
    description: str = "Base manager agent"
    system_prompt_template: str = "agents/manager_base.md"
    max_turns: int = 5  # ループ最大回数（DiscoverySwarm タイムアウト対策）
    
    def __init__(self, config: Optional[Union[Dict[str, Any], 'AgentConfig']] = None, project_manager: Any = None, master_conductor: Any = None, workspace_root: Optional[str] = None, project_id: Optional[str] = None, session_id: Optional[str] = None):
        super().__init__(
            config=config, 
            project_manager=project_manager, 
            master_conductor=master_conductor, 
            workspace_root=workspace_root
        )
        
        # LLMクライアント初期化 (DI対応: ここではNoneで初期化し、set_llm_clientで注入されることを期待)
        self.llm = SimpleNamespace(agenerate=None)
        
        # 後方互換性: Configからモデル名だけ保持（遅延初期化が必要な場合のため）
        cfg = config or {}
        if hasattr(cfg, "model"):
             self.model_name = cfg.model
        elif isinstance(cfg, dict) and cfg.get("model"):
             self.model_name = cfg["model"]
        else:
             self.model_name = LLMClient(role="swarm_manager").model
        
        # Working Memory
        self.history: List[Dict[str, str]] = []
        # ContextSchema キーを管理する実行コンテキスト。
        # auth_headers は後段で set_context / run() 経由で注入される。
        self.current_context: Dict[str, Any] = {}
        if project_id is not None:
            self.current_context["project_id"] = project_id
        if session_id is not None:
            self.current_context["session_id"] = session_id
        
        # 使用可能なツール/Workerのマッピング
        self.available_tools: Dict[str, Any] = {}

    def get_specialists(self, tags: List[str]) -> List[Specialist]:
        """
        SwarmManagerの抽象メソッド実装 (Managerでは動的にWorkerを呼ぶため未使用)
        """
        return []

    def _validate_context_schema(self) -> None:
        """ContextSchema の必須キー欠落を警告する。run() 呼び出し前に実行すること。"""
        _required = ("project_id", "session_id", "auth_headers")
        missing = []
        for key in _required:
            if key not in self.current_context:
                missing.append(key)
                continue
            value = self.current_context.get(key)
            if value is None:
                missing.append(key)
                continue
            if key in {"project_id", "session_id"} and value == "":
                missing.append(key)
        if missing:
            logger.warning(
                "[%s] current_context missing ContextSchema keys: %s",
                self.name,
                missing,
            )

    def set_llm_client(self, client: Any) -> None:
        """Shared LLM Client を設定 (Override)"""
        super().set_llm_client(client)
        self.llm = client

    def register_tool(self, name: str, func: Any, desc: str = ""):
        """ツールを登録（LLMから呼び出し可能にする）"""
        self.available_tools[name] = {
            "func": func,
            "description": desc
        }

    def _select_role_for_turn(self, turn: int, degraded_responses: int = 0) -> str:
        """ターン数/応答品質に応じて使用roleを選択（Phase 3: role-based）"""
        if degraded_responses > 0 or turn >= max(3, self.max_turns // 2 + 1):
            return "planner"
        return "swarm_manager"

    async def dispatch(self, task: Task) -> SwarmResult:
        """
        オーバーライド: 直列実行ではなく、思考ループを開始する
        """
        start_time = asyncio.get_running_loop().time()
        auth_headers = task.params.get("auth_headers", {})
        cookies_str = task.params.get("cookies", "")
        
        # Cookie正規化: auth_headersにないがcookies_strがある場合に付与
        if "Cookie" not in auth_headers and cookies_str:
            auth_headers["Cookie"] = cookies_str

        # --- task.target 補完 ---
        # _create_attack_tasks_from_recon で生成されたタスクは target が空で
        # targets または targets_file しか持たない。LLM がコンテキストを理解できるよう補完する。
        effective_target = task.target
        if not effective_target:
            # (a) params["targets"] (リスト) から最初の URL を使用
            targets_list = task.params.get("targets", [])
            if targets_list:
                effective_target = targets_list[0]
                task.target = effective_target
            # (b) params["targets_file"] から最初の行を読む
            elif task.params.get("targets_file"):
                try:
                    import json as _json
                    from pathlib import Path as _Path
                    tf = _Path(task.params["targets_file"])
                    if tf.exists():
                        with tf.open("r", encoding="utf-8") as _f:
                            first_line = _f.readline().strip()
                        if first_line:
                            obj = _json.loads(first_line)
                            effective_target = obj.get("url", obj.get("target", ""))
                            task.target = effective_target
                            # targets リストも params に追加して後続処理で使えるように
                            all_urls = []
                            _f2_content = tf.read_text(encoding="utf-8").splitlines()
                            for _line in _f2_content:
                                try:
                                    _obj = _json.loads(_line.strip())
                                    _url = _obj.get("url", _obj.get("target", ""))
                                    if _url:
                                        all_urls.append(_url)
                                except Exception:
                                    pass
                            if all_urls:
                                task.params["targets"] = all_urls
                                logger.info(
                                    "[%s] Resolved %d targets from targets_file, primary: %s",
                                    self.name, len(all_urls), effective_target
                                )
                except Exception as _e:
                    logger.warning("[%s] Failed to resolve targets_file: %s", self.name, _e)

        if not effective_target:
            logger.warning("[%s] task.target is empty and could not be resolved from params", self.name)

        _preserved_project_id = self.current_context.get("project_id")
        _preserved_session_id = self.current_context.get("session_id")
        self.current_context = {
            "target": effective_target,
            "params": task.params,
            "auth_headers": auth_headers,
            "findings": []
        }
        if _preserved_project_id:
            self.current_context["project_id"] = _preserved_project_id
        if _preserved_session_id:
            self.current_context["session_id"] = _preserved_session_id
        self._validate_context_schema()
        
        # 初期化
        self.history = []
        execution_log = []
        self.total_tools_executed = 0 # リセット
        
        # システムプロンプト構築
        system_prompt = await self._build_system_prompt(task)
        self.history.append({"role": "system", "content": system_prompt})
        
        # LLMクライアントの確認とフォールバック
        if self.llm is None or not callable(getattr(self.llm, "agenerate", None)):
            logger.warning(f"[{self.name}] LLM client not injected. initializing new instance (Performance Warning).")
            self.llm = LLMClient(role="swarm_manager")

        # 共有クライアントのモデル上書き競合を避けるため、LLMClient は dispatch 単位で複製して使う
        llm_for_dispatch = self.llm
        if isinstance(self.llm, LLMClient):
            llm_for_dispatch = LLMClient(role="swarm_manager")

        # 思考ループ開始
        turn = 0
        status = "running"
        degraded_responses = 0
        
        logger.info(f"[{self.name}] Starting Think Loop for task: {task.name}")
        
        while turn < self.max_turns and status == "running":
            turn += 1
            
            # 1. Think (LLM Query)
            try:
                if isinstance(llm_for_dispatch, LLMClient):
                    selected_role = self._select_role_for_turn(turn, degraded_responses)
                    llm_for_dispatch = LLMClient(role=selected_role)
                    logger.debug(f"[{self.name}] Turn {turn}: using role={selected_role}")

                # Semaphore による同時実行制御 (LLMリクエストのバースト防止)
                async with self.semaphore:
                    response = await llm_for_dispatch.agenerate(self.history)
                
                if response is None or not hasattr(response, 'choices') or not response.choices:
                    logger.warning(f"[{self.name}] LLM returned empty or invalid response. Retrying turn {turn}...")
                    self.history.append({"role": "user", "content": "The response was empty. Please continue your reasoning and provide an Action or Final Answer."})
                    execution_log.append({"turn": turn, "type": "warning", "content": "Empty LLM response, retrying..."})
                    degraded_responses += 1
                    continue
                    
                llm_output = response.choices[0].message.content

                if llm_output is None:
                    logger.warning(f"[{self.name}] LLM returned null content. Retrying turn {turn}...")
                    self.history.append({"role": "user", "content": "Your previous response had null content. Please continue and provide an Action or Final Answer."})
                    execution_log.append({"turn": turn, "type": "warning", "content": "Null LLM content, retrying..."})
                    degraded_responses += 1
                    continue

                if not isinstance(llm_output, str):
                    llm_output = str(llm_output)

                if not llm_output.strip():
                    logger.warning(f"[{self.name}] LLM returned blank content. Retrying turn {turn}...")
                    self.history.append({"role": "user", "content": "Your previous response was blank. Please continue and provide an Action or Final Answer."})
                    execution_log.append({"turn": turn, "type": "warning", "content": "Blank LLM content, retrying..."})
                    degraded_responses += 1
                    continue

                degraded_responses = 0
                
                self.history.append({"role": "assistant", "content": llm_output})
                execution_log.append({"turn": turn, "type": "thought", "content": llm_output})
                
                logger.debug(f"[{self.name}] Turn {turn} Thought: {llm_output[:100]}...")
                
            except Exception as e:
                logger.error(f"[{self.name}] LLM Generation Error: {e}")
                execution_log.append({"turn": turn, "type": "error", "error": str(e)})
                break

            # 2. Parse & Act
            action, args, final_answer = self._parse_llm_output(llm_output)
            
            if final_answer:
                logger.info(f"[{self.name}] Final Answer detected.")
                status = "success"
                break
                
            if action:
                # ツール実行
                logger.info(f"[{self.name}] Action: {action}({args})")
                
                try:
                    # Semaphore による同時実行制御
                    async with self.semaphore:
                        result = await self._execute_tool(action, args)
                    
                    self.total_tools_executed += 1 # カウントアップ
                    observation = f"Observation: {json.dumps(result, ensure_ascii=False)}"
                    
                    self.history.append({"role": "user", "content": observation})
                    execution_log.append({"turn": turn, "type": "action", "action": action, "result": result})
                    
                except Exception as e:
                    error_msg = f"Observation: Tool execution failed. Error: {str(e)}"
                    self.history.append({"role": "user", "content": error_msg})
                    logger.error(f"[{self.name}] Tool Error: {e}")
            else:
                # アクションも答えもない場合（思考のみ、あるいはパース失敗）
                # LLMに続きを促す
                self.history.append({"role": "user", "content": "Please continue. Specify an Action or Final Answer."})
        
        # 結果生成
        all_findings = self.current_context["findings"]
        total_time = asyncio.get_event_loop().time() - start_time
        
        return SwarmResult(
            findings=all_findings,
            status=status,
            execution_log=execution_log,
            swarm_name=self.name,
            total_specialists=self.total_tools_executed, # 実際にツールを実行した回数
            successful_specialists=self.total_tools_executed if status == "success" else 0,
            failed_specialists=0,
            execution_time_seconds=total_time,
            input_tags=task.tags,
            output_tags=[] # Findingから収集すべき
        )
        
    async def _build_system_prompt(self, task: Task) -> str:
        """システムプロンプトを構築（PromptRenderer使用）"""
        try:
            from src.core.utils.prompt_renderer import prompt_renderer
            
            tool_descriptions = [
                f"- {name}: {info['description']}" 
                for name, info in self.available_tools.items()
            ]
            tools_desc_str = "\n".join(tool_descriptions)
            
            context = {
                "agent_name": self.name,
                "description": self.description,
                "target": task.target,
                "context": task.params,
                "tools_desc": tools_desc_str
            }
            
            return prompt_renderer.render(self.system_prompt_template, context)
            
        except Exception as e:
            logger.error(f"Failed to render system prompt: {e}")
            # Fallback to simple prompt if rendering fails
            return f"You are {self.name}. Target: {task.target}. Error loading prompt: {e}"

    def _parse_llm_output(self, text: str) -> Tuple[Optional[str], Dict[str, Any], Optional[str]]:
        """
        LLMの出力をパースする
        Supports:
        - Action: tool({"key": "val"})
        - Action: tool(key="val", key2=123)
        """
        lines = text.split('\n')
        action = None
        args = {}
        final_answer = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # すでにActionを見つけている場合は、それ以降の行（LLMが自分で書いたObservationなど）を無視
            if action:
                break

            if line.startswith("Action:"):
                try:
                    content = line[len("Action:"):].strip()
                    # Pattern: name(args)
                    try:
                        import ast
                        # 共通のLLMミス（true/false/null）をPython形式に修正
                        content_fixed = content.replace("true", "True").replace("false", "False").replace("null", "None")
                        # Action: tool(args) の形式を AST でパース
                        tree = ast.parse(content_fixed)
                        if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Call):
                            call_node = tree.body[0].value
                            if isinstance(call_node.func, ast.Name):
                                action = call_node.func.id
                                # キーワード引数の抽出
                                args = {}
                                for kw in call_node.keywords:
                                    try:
                                        args[kw.arg] = ast.literal_eval(kw.value)
                                    except:
                                        # literal_eval で失敗する場合（複雑なネスト等）はそのまま文字列化等の暫定処理
                                        args[kw.arg] = str(kw.value)
                                # 位置引数が dict 1個だけの場合は kwargs として展開
                                if not args and len(call_node.args) == 1:
                                    try:
                                        first_arg = ast.literal_eval(call_node.args[0])
                                        if isinstance(first_arg, dict):
                                            args = dict(first_arg)
                                    except Exception:
                                        pass
                                # 位置引数の抽出 (必要あれば)
                                # if call_node.args: ...
                    except Exception as e:
                        logger.warning(f"[{self.name}] AST parsing failed for '{content}': {e}. falling back to regex.")
                        # Fallback regex parser (very simple)
                        # This regex is a simplified version of the original one, focusing on key=value pairs
                        kv_pairs = re.findall(r"(\w+)\s*=\s*(['\"])(.*?)\2|(\w+)\s*=\s*({.*?})|(\w+)\s*=\s*([\w\d\.]+)", content)
                        for match in kv_pairs:
                            k = None
                            v = None
                            if match[0]: # Quoted string
                                k = match[0]
                                v = match[2]
                            elif match[3]: # Dictionary
                                k = match[3]
                                try:
                                    v = ast.literal_eval(match[4])
                                except:
                                    v = match[4]
                            elif match[5]: # Simple value (bool/int/float)
                                k = match[5]
                                low = match[6].lower()
                                if low == "true": v = True
                                elif low == "false": v = False
                                elif low == "none": v = None
                                else:
                                    try:
                                        if "." in match[6]: v = float(match[6])
                                        else: v = int(match[6])
                                    except:
                                        v = match[6]
                            if k:
                                args[k] = v
                    
                    # Actionを見つけた時点でループ（パース）を終了
                    # これにより、同じ応答内の Observation: や Final Answer: を無視する
                    break

                except Exception as e:
                    logger.warning(f"[{self.name}] Failed to parse Action line '{line}': {e}")
                    
            elif line.startswith("Final Answer:"):
                final_answer = line[len("Final Answer:"):].strip()
        
        # Actionがある場合は、推論の自己完結を防ぐためFinal Answerを無効化する
        if action:
            final_answer = None
            
        return action, args, final_answer

    async def _execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        """指定されたツールを実行"""
        if name not in self.available_tools:
            raise ValueError(f"Unknown tool: {name}")

        # ---- Compiled guard enforcement (Phase 2: SGK-2026-0335) ----------
        current_mode = (self.current_context.get("mode", "") or "").lower()
        if current_mode == "bugbounty":
            from src.core.security.guard_enforcement import (
                EnforcementStage,
                evaluate_at_layer,
                extract_host_from_target,
                get_shared_guard_context,
            )
            from src.core.security.compiled_guard_models import GuardInput

            guard_ctx = getattr(self, "_guard_context", None)
            if guard_ctx is None:
                guard_ctx = get_shared_guard_context()

            policy = guard_ctx.get("policy") if guard_ctx else None
            stage = (guard_ctx.get("stage") if guard_ctx else None) or EnforcementStage.MC_ONLY

            target = str(args.get("target", args.get("url", "")) or self.current_context.get("target", ""))
            gi = GuardInput(
                bundle_id=getattr(policy, "bundle_id", "") if policy else "",
                policy_id=getattr(policy, "policy_id", "") if policy else "",
                target=target,
                host=extract_host_from_target(target),
                requested_action="external_tool_exec",
                proposed_tool=name,
                enforcement_layer="worker",
            )
            # Always evaluate — shadow mode logs, fail-closed on missing policy
            decision = evaluate_at_layer(policy=policy, guard_input=gi, layer="worker", stage=stage)
            if decision.decision == "block":
                logger.warning(
                    "Guard BLOCKED tool=%s at worker layer: reason=%s",
                    name, decision.reason_code,
                )
                raise RuntimeError(
                    f"Tool execution blocked by compiled guard: {decision.reason_code}"
                )

        func = self.available_tools[name]["func"]
        
        # run_file_upload_check への引数リマップ (params={} で呼ばれた場合のフォールバック)
        if name == "run_file_upload_check" and "params" in args and "param_name" not in args:
            legacy_params = args.pop("params", {})
            args["param_name"] = legacy_params.get("param_name", "uploaded")
            args["extra_params"] = legacy_params.get("extra_params", {})

        # --- Context Propagation (Auth Headers & Cookies) ---
        
        # Merge cookies into top-level args (if tool accepts them directly)
        if "cookies" not in args and self.current_context.get("params", {}).get("cookies"):
            args["cookies"] = self.current_context["params"]["cookies"]
        
        # Merge auth_headers into top-level args
        if "auth_headers" not in args and self.current_context.get("auth_headers"):
            args["auth_headers"] = self.current_context["auth_headers"]
        # ----------------------------------------------------

        # --- Argument Filtering (Prevent TypeError: unexpected keyword argument) ---
        sig = inspect.signature(func)
        has_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        
        if not has_kwargs:
            # func が **kwargs を持っていない場合、シグネチャに含まれる引数のみを抽出
            filtered_args = {
                k: v for k, v in args.items()
                if k in sig.parameters
            }
            args = filtered_args
        # --------------------------------------------------------------------------

        if asyncio.iscoroutinefunction(func):
            return await func(**args)
        else:
            return func(**args)

    # ----------------------------------------
    # Built-in Tools for Manager
    # ----------------------------------------
    
    async def report_finding(self, **kwargs):
        """脆弱性を報告（Findingオブジェクトを作成してContextに追加）"""
        # args: title, description, severity, vuln_type
        # Finding作成ロジック
        f = Finding(
            title=kwargs.get("title", "Unknown"),
            description=kwargs.get("description", ""),
            target_url=self.current_context["target"],
            source_agent=self.name,
            severity=kwargs.get("severity", "medium"), # Enum変換が必要
            # ...
        )
        self.current_context["findings"].append(f)
        return "Finding reported successfully."


    async def close(self) -> None:
        """リソース解放"""
        # 実行中のタスクをキャンセル
        self._running = False
        
        # Working Memory をクリア
        self.history.clear()
        self.current_context.clear()
        self.available_tools.clear()
        
        await super().close()
