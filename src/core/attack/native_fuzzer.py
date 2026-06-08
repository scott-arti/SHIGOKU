import asyncio
import logging
import time
from typing import List, Optional

from src.core.infra.network_client import AsyncNetworkClient, NetworkResponse

# TODO(Phase E): Consider migrating to FfufAdapter
# from src.core.adapters.external.ffuf_adapter import FfufAdapter
# from src.core.adapters.external.base_external_adapter import ToolInput
# from src.core.adapters.external.external_tool_executor import get_global_executor
from src.core.models.fuzzing import FuzzResult

logger = logging.getLogger(__name__)

class NativeFuzzer:
    """
    Python Base Fuzzer (AsyncNetworkClient利用)
    ffufがない場合のフォールバック用。
    """
    
    def __init__(self, client: AsyncNetworkClient):
        self.client = client
        
    async def run(
        self,
        base_url: str,
        wordlist_path: str,
        match_codes: List[int] = None,
        concurrency: int = 10,
        delay: float = 0.0
    ) -> List[FuzzResult]:
        """
        URLのFUZZ箇所を置換してリクエスト送信
        """
        if "FUZZ" not in base_url:
            logger.warning("No FUZZ keyword in base_url: %s", base_url)
            return []

        match_codes = match_codes or [200, 204, 301, 302, 307, 401, 403]
        
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error("Wordlist not found: %s", wordlist_path)
            return []

        sem = asyncio.Semaphore(concurrency)
        results = []
        
        async def worker(word: str):
            target_url = base_url.replace("FUZZ", word)
            async with sem:
                if delay:
                    await asyncio.sleep(delay)
                try:
                    resp = await self.client.request(
                        method="GET",
                        url=target_url,
                        retries=1,
                        use_proxy=True
                    )
                    
                    if resp.status in match_codes:
                        results.append(FuzzResult(
                            url=target_url,
                            status=resp.status,
                            length=len(resp.body),
                            words=len(resp.body.split()),
                            lines=len(resp.body.splitlines()),
                            content_type=resp.headers.get("Content-Type", ""),
                            redirect_location=resp.headers.get("Location", "")
                        ))
                except Exception as e:
                    logger.debug("Fuzz request failed for %s: %s", target_url, e)

        chunk_size = 1000
        for i in range(0, len(words), chunk_size):
            chunk = words[i:i + chunk_size]
            tasks = [worker(w) for w in chunk]
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.debug("Processed %d/%d words", min(i + chunk_size, len(words)), len(words))
            
        return results
