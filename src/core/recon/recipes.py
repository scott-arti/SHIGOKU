import asyncio
import logging
from enum import Enum, auto
from abc import ABC, abstractmethod
from typing import Any, List, Optional
from src.core.domain.model.target import TargetAsset

logger = logging.getLogger(__name__)

class ReconMode(Enum):
    """
    SHIGOKU 偵察パターン定義 (7種類)
    """
    WILDCARD_BB = auto()      # 1. ワイルドカードドメイン (Bug Bounty)
    FIXED_DOMAIN_BB = auto()  # 2. 固定ドメイン (Bug Bounty)
    SINGLE_URL_BB = auto()    # 3. シングルURL (Bug Bounty)
    MULTI_URL_BB = auto()     # 4. マルチURL (Bug Bounty)
    SINGLE_URL_CTF = auto()   # 5. シングルURL (CTF)
    SINGLE_URL_TEST = auto()  # 6. テスト環境 (DVWA等)
    FILE_ANALYSIS = auto()    # 7. ファイル調査 (CTF)

class BaseRecipe(ABC):
    """
    全偵察レシピの基底クラス
    """
    def __init__(self, asset: TargetAsset, orchestrator: Any):
        self.asset = asset
        self.orchestrator = orchestrator

    @abstractmethod
    async def execute_fast_phase(self) -> None:
        """
        [同期フェーズ] MC起動前に完了させるべき高速スキャン
        """
        pass

    @abstractmethod
    async def execute_deep_phase(self) -> None:
        """
        [非同期フェーズ] MC起動後にバックグラウンドで回す重いスキャン
        """
        pass

# --- Pattern Implementation ---

class WildcardBBRecipe(BaseRecipe):
    """
    1. ワイルドカードドメイン (Bug Bounty)
    Subfinder -> HTTPX -> Naabu(Fast) -> Katana/GAU (Fast)
    VisualRecon, Permutation, Naabu(Full), DeadSub (Deep)
    """
    async def execute_fast_phase(self) -> None:
        logger.info(f"[*] Fast Phase: WildcardBB for {self.asset.raw_input}")
        # 1. Subdomain Discovery
        subs = await self.orchestrator.run_tool("subfinder", self.asset.raw_input)
        if not subs:
            return
            
        # 2. Live Check
        live_hosts = await self.orchestrator.run_tool("httpx", subs)
        if not live_hosts:
            return
            
        # 3. Fast Port Scan (Top 20) & URL Discovery
        await asyncio.gather(
            self.orchestrator.run_tool("naabu_fast", live_hosts),
            self.orchestrator.run_tool("gau", live_hosts),
            self.orchestrator.run_tool("katana_std", live_hosts)
        )

    async def execute_deep_phase(self) -> None:
        logger.info(f"[*] Deep Phase: WildcardBB for {self.asset.raw_input}")
        # KnowledgeGraphから最新のLiveリスト取得を想定
        live_hosts = self.orchestrator.get_results("httpx") 
        if not live_hosts:
             return

        await asyncio.gather(
            self.orchestrator.run_tool("visual_recon", live_hosts),
            self.orchestrator.run_tool("naabu_full", live_hosts),
            self.orchestrator.run_tool("deadsub_check", self.asset.raw_input)
        )

class FixedDomainBBRecipe(BaseRecipe):
    """
    2. 固定ドメイン (Bug Bounty)
    """
    async def execute_fast_phase(self) -> None:
        await asyncio.gather(
            self.orchestrator.run_tool("naabu_fast", self.asset.raw_input),
            self.orchestrator.run_tool("gau", self.asset.raw_input),
            self.orchestrator.run_tool("katana_std", self.asset.raw_input)
        )

    async def execute_deep_phase(self) -> None:
        await self.orchestrator.run_tool("naabu_full", self.asset.raw_input)

class SingleUrlBBRecipe(BaseRecipe):
    """
    3. シングルURL (Bug Bounty)
    """
    async def execute_fast_phase(self) -> None:
        await asyncio.gather(
            self.orchestrator.run_tool("naabu_fast", self.asset.raw_input),
            self.orchestrator.run_tool("gau", self.asset.raw_input),
            self.orchestrator.run_tool("katana_std", self.asset.raw_input)
        )

    async def execute_deep_phase(self) -> None:
        await self.orchestrator.run_tool("naabu_full", self.asset.raw_input)

class MultiUrlBBRecipe(BaseRecipe):
    """
    4. マルチURL (Bug Bounty)
    """
    async def execute_fast_phase(self) -> None:
        # TODO: assetが複数のURLを持つ場合のループ処理
        await asyncio.gather(
            self.orchestrator.run_tool("naabu_fast", self.asset.raw_input),
            self.orchestrator.run_tool("gau", self.asset.raw_input),
            self.orchestrator.run_tool("katana_std", self.asset.raw_input)
        )

    async def execute_deep_phase(self) -> None:
        await self.orchestrator.run_tool("naabu_full", self.asset.raw_input)

class SingleUrlCTFRecipe(BaseRecipe):
    """
    5. シングルURL (CTF)
    """
    async def execute_fast_phase(self) -> None:
        await asyncio.gather(
            self.orchestrator.run_tool("naabu_fast", self.asset.raw_input),
            self.orchestrator.run_tool("katana_std", self.asset.raw_input) # GAUなし
        )

    async def execute_deep_phase(self) -> None:
        await self.orchestrator.run_tool("naabu_full", self.asset.raw_input)

class SingleUrlTestRecipe(BaseRecipe):
    """
    6. シングルURL (DVWA等テスト環境)
    """
    async def execute_fast_phase(self) -> None:
        await asyncio.gather(
            self.orchestrator.run_tool("naabu_fast", self.asset.raw_input),
            self.orchestrator.run_tool("katana_deep", self.asset.raw_input) # Deep Crawl
        )

    async def execute_deep_phase(self) -> None:
        await self.orchestrator.run_tool("naabu_full", self.asset.raw_input)

class FileAnalysisRecipe(BaseRecipe):
    """
    7. ファイル調査 (CTF)
    """
    async def execute_fast_phase(self) -> None:
        await self.orchestrator.run_tool("static_analysis", self.asset.raw_input)

    async def execute_deep_phase(self) -> None:
        # 将来的に Decompile 等のタスク
        pass
