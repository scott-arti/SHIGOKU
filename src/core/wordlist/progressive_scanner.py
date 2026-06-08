"""
Progressive Scanner

段階的スキャン + 早期終了ロジック
small → medium → high の順でスキャンし、十分な結果が出たら終了
"""

import logging
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field

from src.core.wordlist.wordlist_manager import get_wordlist_manager, WordlistInfo
from src.tools.custom.ffuf import FfufTool

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """スキャン結果"""
    wordlist_name: str
    wordlist_size: str
    discovered: List[str] = field(default_factory=list)
    total_tested: int = 0
    discovery_rate: float = 0.0
    should_continue: bool = True
    reason: str = ""


@dataclass
class ProgressiveScanConfig:
    """段階的スキャン設定"""
    # 早期終了閾値
    min_discoveries: int = 10  # 最低発見数
    target_discovery_rate: float = 0.05  # 目標発見率 5%
    diminishing_returns_threshold: float = 0.5  # 発見率低下閾値
    
    # スキャン設定
    stages: List[str] = field(default_factory=lambda: ["small", "medium", "high"])
    timeout_per_stage: int = 300  # ステージごとのタイムアウト
    max_requests_per_stage: Optional[int] = None  # ステージごとの最大リクエスト数 (リスク緩和)


class ProgressiveScanner:
    """
    段階的スキャナー
    
    効率的なワードリストスキャンを実現:
    1. smallワードリストでクイックスキャン
    2. 発見率評価
    3. 十分なら終了、不十分ならmediumへ
    4. 繰り返し
    """
    
    def __init__(self, config: ProgressiveScanConfig = None):
        self.config = config or ProgressiveScanConfig()
        self.wm = get_wordlist_manager()
        self.results: List[ScanResult] = []
    
    def scan(
        self,
        target: str,
        purpose: str,
        tool: str = "ffuf",
        mode: str = "bugbounty",
        callback: Callable[[ScanResult], None] = None
    ) -> List[ScanResult]:
        """
        段階的スキャン実行
        
        Args:
            target: ターゲットURL/ドメイン
            purpose: ワードリスト用途（subdomain, directory, api）
            tool: 使用ツール（ffuf, gobuster, subfinder）
            mode: ハンティングモード
            callback: 各ステージ完了時のコールバック
        
        Returns:
            各ステージの結果リスト
        """
        self.results = []
        previous_discovery_rate = 0.0
        
        for stage in self.config.stages:
            logger.info("Starting %s stage for %s", stage, target)
            
            # ワードリスト選択
            wordlist = self._select_wordlist(purpose, mode, stage)
            if not wordlist:
                logger.warning("No wordlist found for %s/%s", purpose, stage)
                continue
            
            # スキャン実行
            result = self._execute_scan(target, wordlist, tool)
            self.results.append(result)
            
            # コールバック
            if callback:
                callback(result)
            
            # 早期終了判定
            should_continue, reason = self._should_continue(
                result, previous_discovery_rate
            )
            
            result.should_continue = should_continue
            result.reason = reason
            
            if not should_continue:
                logger.info("Early termination: %s", reason)
                break
            
            previous_discovery_rate = result.discovery_rate
        
        return self.results
    
    def _select_wordlist(
        self,
        purpose: str,
        mode: str,
        size: str
    ) -> Optional[WordlistInfo]:
        """サイズに応じたワードリストを選択"""
        # strategiesマッピング
        strategy_map = {"small": "quick", "medium": "standard", "high": "deep"}
        strategy = strategy_map.get(size, "standard")
        
        return self.wm.select(
            purpose=purpose,
            mode=mode,
            strategy=strategy
        )
    
    def _execute_scan(
        self,
        target: str,
        wordlist: WordlistInfo,
        tool: str
    ) -> ScanResult:
        """
        実際のスキャン実行
        
        Args:
            target: ターゲットURL/ドメイン
            wordlist: 使用するワードリスト情報
            tool: 使用するツール名
        
        Returns:
            スキャン結果
        """
        result = ScanResult(
            wordlist_name=wordlist.name,
            wordlist_size=wordlist.size,
            total_tested=wordlist.lines
        )
        
        logger.info(
            "Scanning %s with %s (%d lines)",
            target, wordlist.name, wordlist.lines
        )
        
        if tool == "ffuf":
            try:
                ffuf_tool = FfufTool()
                
                # FUZZキーワードがない場合は追加
                if "FUZZ" not in target:
                    scan_url = f"{target.rstrip('/')}/FUZZ"
                else:
                    scan_url = target
                
                # ffuf実行 (JSON出力形式)
                output = ffuf_tool.run(
                    url=scan_url,
                    wordlist=str(wordlist.path),
                    match_code="200,201,301,302,307,401,403",
                    fast_mode=True,
                    threads=40,
                    extra_args="-o /tmp/ffuf_output.json -of json -s",  # JSON出力 + silent mode
                )
                
                # 出力をパース
                discovered = self._parse_ffuf_output(output)
                result.discovered = discovered
                result.total_tested = wordlist.lines
                
                # 発見率を計算
                if result.total_tested > 0:
                    result.discovery_rate = len(discovered) / result.total_tested
                
                logger.info(
                    "Ffuf scan complete: %d discovered / %d tested (%.2f%%)",
                    len(discovered), result.total_tested, result.discovery_rate * 100
                )
                
            except FileNotFoundError:
                logger.error("ffuf binary not found. Install ffuf or check FFUF_PATH.")
                result.discovery_rate = 0.0
            except Exception as e:
                logger.error("Ffuf scan failed: %s", e)
                result.discovery_rate = 0.0
        
        else:
            # 他のツール対応は将来実装
            logger.warning("Tool '%s' not yet implemented, skipping scan", tool)
        
        return result
    
    def _parse_ffuf_output(self, output: str) -> List[str]:
        """
        ffufのJSON出力をパースして発見されたパスを抽出
        
        Args:
            output: ffufの出力文字列
        
        Returns:
            発見されたパスのリスト
        """
        import json
        import re
        
        discovered = []
        
        try:
            # JSON出力ファイルを読み込む試行
            try:
                with open("/tmp/ffuf_output.json", "r") as f:
                    data = json.load(f)
                    
                    # ffufのJSON形式: {"results": [{"input": {"FUZZ": "admin"}, "status": 200, ...}, ...]}
                    if "results" in data:
                        for result in data["results"]:
                            if "input" in result and "FUZZ" in result["input"]:
                                discovered.append(result["input"]["FUZZ"])
            except (FileNotFoundError, json.JSONDecodeError):
                # JSON出力ファイルが見つからない場合、stdoutからパース
                # ffufのテキスト出力から発見を抽出 (フォールバック)
                lines = output.split("\n")
                for line in lines:
                    # "[Status: 200, Size: 1234, Words: 56, Lines: 12]" のような形式
                    if "[Status:" in line and "200" in line:
                        # URLからパスを抽出
                        match = re.search(r"https?://[^/]+/(.+?)\s", line)
                        if match:
                            discovered.append(match.group(1))
        
        except Exception as e:
            logger.warning("Failed to parse ffuf output: %s", e)
        
        return discovered
    
    def _should_continue(
        self,
        result: ScanResult,
        previous_rate: float
    ) -> tuple:
        """
        早期終了すべきか判定
        
        Returns:
            (should_continue, reason)
        """
        # 十分な発見がある場合
        if len(result.discovered) >= self.config.min_discoveries:
            if result.discovery_rate >= self.config.target_discovery_rate:
                return False, f"Sufficient discoveries ({len(result.discovered)})"
        
        # 発見率が低下している場合（収穫逓減）
        if previous_rate > 0:
            rate_change = result.discovery_rate / previous_rate
            if rate_change < self.config.diminishing_returns_threshold:
                return False, "Diminishing returns detected"
        
        # 発見がゼロの場合（最初のステージ以外）
        if result.wordlist_size != "small" and len(result.discovered) == 0:
            return False, "No discoveries in this stage"
        
        return True, "Continuing to next stage"
    
    def get_summary(self) -> Dict:
        """スキャン結果サマリー"""
        total_discovered = []
        for r in self.results:
            total_discovered.extend(r.discovered)
        
        return {
            "stages_completed": len(self.results),
            "total_discoveries": len(total_discovered),
            "discovered_paths": list(set(total_discovered)),
            "final_stage": self.results[-1].wordlist_size if self.results else None,
            "termination_reason": self.results[-1].reason if self.results else None,
        }


def create_progressive_scanner(
    config: ProgressiveScanConfig = None
) -> ProgressiveScanner:
    """ProgressiveScanner作成ヘルパー"""
    return ProgressiveScanner(config)
