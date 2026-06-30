import asyncio
import logging
import random
import json
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse, urlencode, urlunparse

from src.core.infra.smart_request import SmartRequest
from src.core.models.finding import Finding
from src.core.models.llm import LLMClient
from src.core.agents.swarm.thought_loop import ThoughtLoop, ThoughtStep, LoopStatus
from src.core.security.ethics_guard import EthicsGuard
from src.tools.browser.playwright_validator import PlaywrightValidator

logger = logging.getLogger(__name__)

class ActorCriticFuzzer(ThoughtLoop):
    """
    LLM Actor-Critic Fuzzing Loop
    コンテキストを節約しつつ、変異ペイロードを自動生成・検証するモジュール
    """
    name = "ActorCriticFuzzer"
    
    SYSTEM_PROMPT = """You are the 'Critic' and 'Generator' of an advanced Actor-Critic Web Fuzzing Loop.
Your goal is to bypass WAFs or input validation by iteratively refining payloads, similar to how human experts fuzz.

You will receive an execution summary (results of 50-100 mutated payloads).
DO NOT read raw HTML. Only look at HTTP status, length, and reflection info.

Commands:
- ACTION: analyze
  INPUT: [Summarize the WAF rules you inferred from the results.]
- ACTION: generate
  INPUT: [Provide a JSON string containing a list of 'strategy' and base payloads. Example: `[{"strategy": "url_encode", "payload": "<svg onload=alert(1)>"}, {"strategy": "lower_upper", "payload": "<ScRiPt>"}]`]
- ACTION: finish
  INPUT: [Success payload in JSON: `{"payload": "SUCCESSFUL_PAYLOAD"}` or `{"payload": "FAILED"}`]

Thought Process:
1. Review the execution summary.
2. If `200` but blocked via content modification -> The tag/keyword is sanitized.
3. If `403` -> WAF is blocking the signature.
4. If `500` -> The payload caused a backend error (promising!).
5. Use `ACTION: generate` to give the Prober a new list of payloads based on your refined strategy.
6. Use `ACTION: finish` when a payload achieves the goal (e.g., alert trigger reflected without sanitization, or file content read).

Format:
THOUGHT: [Your reasoning]
ACTION: [Command]
INPUT: [Input]
"""

    def __init__(self, target_request: SmartRequest, config: Dict[str, Any] = None):
        super().__init__(max_turns=10)
        self.target_request = target_request
        self.config = config or {}
        self.client = LLMClient(role="actor_critic")
        self.ethics = EthicsGuard()
        self.payloads_queue: List[str] = []
        self.system_prompt = self.SYSTEM_PROMPT

    def _apply_mutation(self, payload: str, strategy: str) -> str:
        """適用する変異戦略に基づきペイロードを変異させる"""
        # 簡易的な変異実装
        if strategy == "url_encode":
            return urlencode({"q": payload})[2:] # ?q= の q=を削る簡易エンコード
        elif strategy == "double_url_encode":
             return urlencode({"q": urlencode({"q": payload})[2:]})[2:]
        elif strategy == "lower_upper":
            return "".join(random.choice([k.upper(), k.lower()]) for k in payload)
        elif strategy == "add_null":
            return payload.replace("script", "scr%00ipt").replace("onload", "on%00load")
        elif strategy == "space_to_tab":
             return payload.replace(" ", "%09")
        # 拡張ポイント：様々な変異ロジックを追加
        return payload

    async def _run_prober(self, payloads: List[Dict[str, str]]) -> Dict[str, Any]:
        """Prober: 生成されたペイロードを非同期で実際に送信して結果を集計する（軽量Pythonループ）"""
        results_summary = {
            "total_sent": len(payloads),
            "status_codes": {},
            "promising": [],
            "baseline_diffs": {}
        }
        
        # SmartRequestからURLを取得する
        url_target = getattr(self.target_request, "target_url", getattr(self.target_request, "url", "http://localhost"))

        if not self.ethics.check_scope(url_target):
            logger.warning(f"[Prober] Target out of scope: {url_target}")
            return {"error": "Target out of scope"}

        # 1. カナリアを含むベースラインリクエストの送信
        canary = f"shigoku_canary_{random.randint(1000, 9999)}"
        baseline_resp = await self.target_request.request(
            method=getattr(self.target_request, "method", "GET"),
            url=url_target,
            params={"test": canary} if getattr(self.target_request, "method", "GET") == "GET" else None,
            data={"test": canary} if getattr(self.target_request, "method", "GET") != "GET" else None
        )
        
        # コンテキスト分析の簡易実装 (SmartXSSHunterから移植可能)
        reflection_context = "Not reflected"
        if baseline_resp.get("body") and canary in baseline_resp["body"]:
             idx = baseline_resp["body"].find(canary)
             before = baseline_resp["body"][max(0, idx-50):idx].lower()
             if "<script" in before and "</script>" not in before:
                 reflection_context = "JavaScript"
             elif '="' in before or "='" in before:
                 reflection_context = "Attribute"
             else:
                 reflection_context = "HTML Body"
                 
        results_summary["reflection_context"] = reflection_context

        # 2. 並列リクエストの構築
        async def send_payload(item: Dict[str, str]):
             strategy = item.get("strategy", "none")
             base_payload = item.get("payload", "")
             mutated_payload = self._apply_mutation(base_payload, strategy)

             try:
                 # TODO: メソッドやパラメータ挿入位置をより柔軟にする
                 method = getattr(self.target_request, "method", "GET")
                 kwargs = {}
                 if method == "GET":
                     kwargs["params"] = {"test": mutated_payload} # URLエンコードはAsyncNetworkClient等で行われる想定
                 elif method == "POST":
                     # Content-Typeによってjsonかdataか分ける必要があるがここでは一旦data
                     kwargs["data"] = {"test": mutated_payload}

                 resp = await self.target_request.request(
                     method=method,
                     url=url_target,
                     source_agent=self.name,
                     **kwargs
                 )
                 
                 return {
                     "mutated_payload": mutated_payload,
                     "status": resp.get("status", 0),
                     "body": resp.get("body", ""),
                     "diff": resp.get("diff", "")
                 }
             except Exception as e:
                 logger.error(f"[Prober] Request failed for {mutated_payload}: {e}")
                 return {
                     "mutated_payload": mutated_payload,
                     "status": 0,
                     "body": "",
                     "diff": f"Error: {e}"
                 }

        # 3. リクエストの並列実行
        tasks = [send_payload(item) for item in payloads]
        responses = await asyncio.gather(*tasks)

        # 4. 結果の集計
        for resp in responses:
            mutated_payload = resp["mutated_payload"]
            resp_status = resp["status"]
            resp_body = resp["body"]
            resp_diff = resp["diff"]
            resp_len = len(resp_body) if resp_body else 0

            # ステータスと長さでグループ化
            key = f"Status:{resp_status} Length:{resp_len}"
            if key not in results_summary["status_codes"]:
                 results_summary["status_codes"][key] = {"count": 0, "sample_payload": mutated_payload}
            results_summary["status_codes"][key]["count"] += 1

            # Diffの記録 (初出のみ記録してコンテキストを節約)
            diff_key = f"Diff:{resp_diff[:50]}..." # 簡易集約
            if diff_key not in results_summary["baseline_diffs"]:
                 results_summary["baseline_diffs"][diff_key] = {"count": 0, "sample_diff": resp_diff}
            results_summary["baseline_diffs"][diff_key]["count"] += 1

            # 評価ロジック (有望かどうかの判定)
            if resp_status == 500:
                results_summary["promising"].append({"payload": mutated_payload, "reason": "Caused 500 Error"})
            elif resp_status == 200 and resp_len != len(baseline_resp.get("body", "")):
                 results_summary["promising"].append({"payload": mutated_payload, "reason": f"Length Anomaly vs Baseline ({resp_len} vs {len(baseline_resp.get('body', ''))})"})
            elif resp_status == 200 and mutated_payload in resp_body:
                 results_summary["promising"].append({"payload": mutated_payload, "reason": "Reflected Payload in Response"})

        # 長すぎるDiffは制限
        if len(results_summary["baseline_diffs"]) > 5:
             results_summary["baseline_diffs"] = {"info": "Too many different types of diffs, truncated."}

        return results_summary

    def _build_history(self) -> str:
        history_text = ""
        for step in self.history:
            history_text += f"\nTurn {step.turn}:\n"
            history_text += f"Thought: {step.thought}\n"
            history_text += f"Action: {step.action}\n"
            history_text += f"Input: {step.action_input}\n"
            history_text += f"Observation: {step.observation}\n"
        return history_text

    async def decide(self, turn: int) -> tuple[str, str, Any]:
        history_text = self._build_history()
        # Initial context passed through run_loop is stored in self.context
        initial_msg = self.context.get("message", "Start Fuzzing.")
        
        prompt = f"{self.system_prompt}\n\nMESSAGES:\nInitial Context: {initial_msg}\n{history_text}\n\nWhat is your next action?"
        
        response = await self.client.agenerate_thought(prompt)
        
        # Parse logic (simplified, ideally use ThoughtStep.parse if available)
        thought = ""
        action = ""
        action_input = ""
        
        for line in response.split("\n"):
            if line.startswith("THOUGHT:"):
                thought = line[8:].strip()
            elif line.startswith("ACTION:"):
                action = line[7:].strip()
            elif line.startswith("INPUT:"):
                action_input = line[6:].strip()
                
        return thought, action, action_input

    async def act(self, action: str, action_input: Any) -> str:
        if action == "analyze":
            return f"Understood analysis: {action_input}"
        elif action == "generate":
            try:
                # LLMに代わってProber(Pythonのループ)が数十件のリクエストを実行
                payloads = []
                if isinstance(action_input, str):
                    try:
                        import re
                        json_match = re.search(r'\[.*\]', action_input, re.DOTALL)
                        if json_match:
                            payloads = json.loads(json_match.group(0))
                        else:
                            payloads = json.loads(action_input)
                    except json.JSONDecodeError:
                        return f"Error: Invalid JSON format for generation instructions: {action_input}"
                elif isinstance(action_input, list):
                     payloads = action_input
                else:
                     return "Error: Expected JSON array of objects with 'strategy' and 'payload'."

                logger.info(f"[ActorCriticFuzzer] Prober is executing {len(payloads)} payloads...")
                summary = await self._run_prober(payloads)
                
                # 動的検証: 有望なペイロードをPlaywrightでテスト
                validation_results = []
                url_target = getattr(self.target_request, "target_url", getattr(self.target_request, "url", "http://localhost"))
                
                if summary.get("promising"):
                    logger.info(f"[ActorCriticFuzzer] Verifying {len(summary['promising'])} promising payloads with Playwright...")
                    validator = PlaywrightValidator()
                    for promising_item in summary["promising"]:
                        payload = promising_item["payload"]
                        test_url = f"{url_target}?test={urlencode({'q': payload})[2:]}"
                        
                        is_verified = await validator.validate_xss(test_url)
                        if is_verified:
                            validation_results.append({
                                "payload": payload,
                                "verified": True,
                                "url": test_url
                            })
                            # 発火した場合はその時点でループを抜けても良い
                            logger.info(f"[ActorCriticFuzzer] XSS Verified! Payload: {payload}")
                        else:
                            validation_results.append({
                                "payload": payload,
                                "verified": False
                            })
                if validation_results:
                    summary["verified_by_playwright"] = validation_results
                    
                # 結果は「サマリー」だけを返すためコンテキストが肥大しない
                return f"[Prober Results Summary]\n{json.dumps(summary, indent=2)}"
            except Exception as e:
                return f"Error parsing or executing generation: {e}"
        elif action == "finish":
            return f"Fuzzing Loop Finished. Result: {action_input}"
        else:
            return f"Unknown action: {action}"
            
    async def should_stop(self, step) -> bool:
         return step.action == "finish"
         
    async def run(self, initial_observation: str = "") -> Optional[str]:
        # ループ開始
        result_dict = await self.run_loop({"message": f"Initial Target info: {initial_observation}. Start generating payloads."})
        if result_dict.get("status") == LoopStatus.COMPLETED.value:
            history = result_dict.get("history", [])
            if history:
                 return history[-1].get("input", "")
        return None
