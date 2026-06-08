import logging
import random
import string
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from urllib.parse import quote

from src.core.infra.network_client import AsyncNetworkClient, NetworkResponse

logger = logging.getLogger(__name__)

@dataclass
class FuzzResult:
    parameter: str
    vulnerable: bool
    confidence: str # "high", "medium", "low"
    evidence: Dict[str, Any]

class NativeParamFuzzer:
    """
    Shigoku Native Parameter Fuzzer (Fallback)
    
    Arjunが利用できない場合のフォールバックとして機能する。
    高度なヒューリスティックは持たず、基本的なメソッドのみ実装。
    """
    
    def __init__(self, client: AsyncNetworkClient = None):
        self.client = client or AsyncNetworkClient()
        self.max_concurrency = 10
        self._results = []
        # P3-3: self-correcting fuzzing controls
        self.request_timeout_seconds = 10
        self.request_retries = 2
        self.max_mutation_attempts = 3

    def get_summary(self) -> Dict[str, Any]:
        found = [r for r in self._results if r.vulnerable]
        reflected = [r for r in found if r.evidence.get("reason") == "reflection"]
        return {
            "total_tested": len(self._results) if hasattr(self, "_results") else 0, # Note: this is a simplification
            "found": len(found),
            "reflected": len(reflected)
        }

    def get_reflected_params(self):
        # map FuzzResult to expected object for print
        class ReflectedParam:
            def __init__(self, name, type_):
                 self.param_name = name
                 self.reflection_type = type_
        
        class RefType:
             def __init__(self, val): self.value = val

        ret = []
        for r in self._results:
            if r.vulnerable and r.evidence.get("reason") == "reflection":
                ret.append(ReflectedParam(r.parameter, RefType("reflection")))
        return ret


    async def fuzz(self, url: str, method: str = "GET", wordlist: List[str] = None) -> List[FuzzResult]:
        """
        パラメータ探索を実行
        """
        if not wordlist:
            logger.warning("No wordlist provided for native fuzzer.")
            return []
            
        logger.info(f"Starting Native Param Fuzzing for {url} ({len(wordlist)} words)")
        
        # 1. Baseline Request
        baseline = await self.client.request(method, url)
        if not baseline:
            logger.error("Failed to establish baseline connection")
            return []
            
        # 2. Random Parameter Baseline (ノイズ測定)
        rand_param = "".join(random.choices(string.ascii_lowercase, k=8))
        rand_val = "1"
        random_resp = await self._send_request(url, method, {rand_param: rand_val})
        
        # 3. Fuzzing Loop
        results = []
        # バッチ処理などは簡易化のため省略し、単純なループで実装（必要ならセマフォ導入）
        
        chunk_size = 10 # 同時実行数制御
        for i in range(0, len(wordlist), chunk_size):
            chunk = wordlist[i:i+chunk_size]
            
            # 並列実行
            import asyncio
            tasks = [
                self._check_single_param(url, method, param, baseline, random_resp)
                for param in chunk
            ]
            batch_results = await asyncio.gather(*tasks)
            
            # Noneを除外して追加
            for res in batch_results:
                if res:
                    results.append(res)
                    
        self._results = results
        return results

    async def _check_single_param(
        self, 
        url: str, 
        method: str, 
        param: str, 
        baseline: NetworkResponse, 
        random_resp: NetworkResponse
    ) -> Optional[FuzzResult]:
        """単一パラメータの検証（並列実行用）"""
        
        # 反射確認用のランダム値 check
        canary = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        payload = canary
        attempted_payloads: set[str] = set()
        mutation_history: list[dict[str, str]] = []
        last_signal = "initial"
        last_mutation_reason = "initial_probe"

        for attempt in range(1, self.max_mutation_attempts + 1):
            attempted_payloads.add(payload)
            resp = await self._send_request(url, method, {param: payload})
            if not resp:
                signal = "timeout_or_transport"
                mutation_reason = "response_missing"
            else:
                signal, mutation_reason = self._analyze_signal(resp)

                # A. Reflection Check
                if payload in resp.body or canary in resp.body:
                    return FuzzResult(
                        parameter=param,
                        vulnerable=True,
                        confidence="high",
                        evidence={
                            "reason": "reflection",
                            "payload": payload,
                            "attempts": attempt,
                            "mutation_reason": mutation_reason,
                            "mutation_history": mutation_history,
                        },
                    )

                # B. Anomaly Check (Simple)
                # 防御シグナル(403/429等)は即脆弱判定せず、自己修正ミューテーションを優先。
                if (
                    signal == "neutral"
                    and resp.status != baseline.status
                    and resp.status != random_resp.status
                ):
                    return FuzzResult(
                        parameter=param,
                        vulnerable=True,
                        confidence="medium",
                        evidence={
                            "reason": "status_code_diff",
                            "status": resp.status,
                            "attempts": attempt,
                            "mutation_reason": mutation_reason,
                            "mutation_history": mutation_history,
                        },
                    )

                # C. Content Length Anomaly (Diff > 10%)
                diff = abs(len(resp.body) - len(baseline.body))
                if diff > len(baseline.body) * 0.1: # 10%以上の変化
                    rand_diff = abs(len(random_resp.body) - len(baseline.body))
                    if abs(diff - rand_diff) > 50: # ランダム時の変化と有意に異なるか
                        return FuzzResult(
                            parameter=param,
                            vulnerable=True,
                            confidence="low",
                            evidence={
                                "reason": "content_length_diff",
                                "diff": diff,
                                "attempts": attempt,
                                "mutation_reason": mutation_reason,
                                "mutation_history": mutation_history,
                            },
                        )

            if attempt >= self.max_mutation_attempts:
                break

            next_payload, strategy, next_reason = self._adapt_payload(canary, payload, signal)
            last_signal = signal
            last_mutation_reason = next_reason
            if next_payload in attempted_payloads:
                break

            mutation_history.append(
                {
                    "attempt": str(attempt + 1),
                    "strategy": strategy,
                    "reason": next_reason,
                    "payload": next_payload,
                }
            )
            logger.debug(
                "[NativeParamFuzzer] param=%s mutation=%s reason=%s signal=%s",
                param,
                strategy,
                next_reason,
                signal,
            )
            payload = next_payload

        logger.debug(
            "[NativeParamFuzzer] param=%s no finding after %d attempts (last_signal=%s, last_reason=%s)",
            param,
            self.max_mutation_attempts,
            last_signal,
            last_mutation_reason,
        )
        return None

    def _analyze_signal(self, resp: NetworkResponse) -> tuple[str, str]:
        body_lower = (resp.body or "").lower()
        if resp.status in (429,) or "rate limit" in body_lower:
            return "rate_limited", "rate_limit_detected"
        if resp.status in (401, 403, 406) or "blocked" in body_lower or "waf" in body_lower:
            return "blocked", "possible_waf_or_access_control"
        if resp.status >= 500 or "exception" in body_lower or "traceback" in body_lower:
            return "server_error", "server_side_error_response"
        return "neutral", "no_defensive_signal"

    def _adapt_payload(self, base_canary: str, current_payload: str, signal: str) -> tuple[str, str, str]:
        """
        反応シグナルに応じて次のペイロードを選ぶ。
        返り値: (next_payload, strategy_name, reason)
        """
        if signal == "blocked":
            if current_payload == base_canary:
                # base canary is alnum, so plain quote() may be unchanged; force encoded marker.
                return f"{base_canary}%2f", "url_encode", "blocked_response_detected"
            return quote(current_payload, safe=""), "double_url_encode", "still_blocked_after_encoding"

        if signal == "rate_limited":
            return f"{base_canary}rl", "low_noise_suffix", "rate_limit_detected_reduce_entropy"

        if signal == "server_error":
            return base_canary[: max(4, len(base_canary) // 2)], "shorten_payload", "server_error_reduce_payload_size"

        # neutral or timeout_or_transport fallback
        return f"{base_canary}9", "fallback_suffix_probe", "no_signal_try_nearby_variant"

    async def _send_request(self, url: str, method: str, params: Dict[str, str]) -> Optional[NetworkResponse]:
        try:
            kwargs: Dict[str, Any] = {
                "timeout": self.request_timeout_seconds,
                "retries": self.request_retries,
            }
            if method.upper() == "GET":
                kwargs["params"] = params
            else:
                kwargs["data"] = params

            try:
                return await self.client.request(method, url, **kwargs)
            except TypeError:
                # テストモックや旧クライアント互換: timeout/retries未対応時は外して再試行
                kwargs.pop("timeout", None)
                kwargs.pop("retries", None)
                return await self.client.request(method, url, **kwargs)
        except Exception:
            return None

def create_native_param_fuzzer() -> NativeParamFuzzer:
    return NativeParamFuzzer()
