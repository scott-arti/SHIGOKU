import logging
import random
import string
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.core.infra.network_client import AsyncNetworkClient, NetworkResponse

logger = logging.getLogger(__name__)

@dataclass
class FuzzResult:
    parameter: str
    vulnerable: bool
    confidence: str # "high", "medium", "low"
    evidence: Dict[str, Any]

class ParameterFuzzer:
    """
    Shigoku Native Parameter Fuzzer (Fallback)
    
    Arjunが利用できない場合のフォールバックとして機能する。
    高度なヒューリスティックは持たず、基本的なメソッドのみ実装。
    """
    
    def __init__(self, client: AsyncNetworkClient = None):
        self.client = client or AsyncNetworkClient()
        self.max_concurrency = 10
        self._results = []
        self._tested_count = 0

    async def close(self):
        if self.client:
            await self.client.close()

    def get_summary(self) -> Dict[str, Any]:
        found = [r for r in self._results if r.vulnerable]
        reflected = [r for r in found if r.evidence.get("reason") == "reflection"]
        return {
            "total_tested": self._tested_count,
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


    async def fuzz(self, url: str, method: str = "GET", wordlist: List[str] = None, extra_params: Dict[str, Any] = None) -> List[FuzzResult]:
        """
        パラメータ探索を実行
        """
        if not wordlist:
            # Default minimal wordlist if none provided
            wordlist = ["debug", "id", "user", "username", "password", "test", "admin", "q", "search", "query", "redirect", "url", "file"]
            logger.info("Using default minimal wordlist (%d words)", len(wordlist))

            
        logger.info(f"Starting Native Param Fuzzing for {url} ({len(wordlist)} words)")
        
        # 1. Baseline Request
        baseline = await self.client.request(method, url, data=extra_params if method == "POST" else None, params=extra_params if method == "GET" else None)
        if not baseline:
            logger.error("Failed to establish baseline connection")
            return []
            
        # 2. Random Parameter Baseline (ノイズ測定)
        rand_param = "".join(random.choices(string.ascii_lowercase, k=8))
        rand_val = "1"
        random_params = {rand_param: rand_val}
        if extra_params:
            random_params.update(extra_params)
            
        random_resp = await self._send_request(url, method, random_params)
        
        # 3. Fuzzing Loop
        results = []
        # バッチ処理などは簡易化のため省略し、単純なループで実装（必要ならセマフォ導入）
        
        chunk_size = 10 # 同時実行数制御
        for i in range(0, len(wordlist), chunk_size):
            chunk = wordlist[i:i+chunk_size]
            
            # 並列実行
            import asyncio
            tasks = [
                self._check_single_param(url, method, param, baseline, random_resp, extra_params)
                for param in chunk
            ]
            batch_results = await asyncio.gather(*tasks)
            self._tested_count += len(chunk)
            
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
        random_resp: NetworkResponse,
        extra_params: Dict[str, Any] = None
    ) -> Optional[FuzzResult]:
        """単一パラメータの検証（並列実行用）"""
        
        # 反射確認用のランダム値 check
        canary = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        
        params = {param: canary}
        if extra_params:
            params.update(extra_params)
            
        resp = await self._send_request(url, method, params)
        if not resp:
            return None
            
        # A. Reflection Check
        if canary in resp.body:
            return FuzzResult(
                parameter=param,
                vulnerable=True,
                confidence="high",
                evidence={"reason": "reflection", "payload": canary}
            )
        
        # B. Anomaly Check (Simple)
        if resp.status != baseline.status and resp.status != random_resp.status:
             return FuzzResult(
                parameter=param,
                vulnerable=True,
                confidence="medium",
                evidence={"reason": "status_code_diff", "status": resp.status}
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
                    evidence={"reason": "content_length_diff", "diff": diff}
                )
        
        return None

    async def _send_request(self, url: str, method: str, params: Dict[str, str]) -> Optional[NetworkResponse]:
        try:
            if method.upper() == "GET":
                return await self.client.request(method, url, params=params)
            else:
                return await self.client.request(method, url, data=params)
        except Exception:
            return None

def create_param_fuzzer(client: Optional[AsyncNetworkClient] = None) -> ParameterFuzzer:
    return ParameterFuzzer(client=client)

