"""
Wayback Analyzer - 過去URL発見・差分分析ツール

Wayback Machine CDX APIを使用して過去のURLを取得し、
現在存在しない「忘れられた」エンドポイントを発見する。
"""
from typing import Dict, Any, List, Optional, Set
import subprocess
import json
import time
from datetime import datetime
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class WaybackAnalyzerTool(BaseTool):
    """
    WaybackAnalyzer - Time-Travel Attack用ツール
    
    Wayback Machine CDX APIから過去URLを取得し、
    現在のURL一覧と比較して「消失」したURLを特定。
    管理画面やデバッグエンドポイントの発見に有効。
    """
    
    name = "wayback_analyzer"
    description = "Fetch historical URLs from Wayback Machine and find 'forgotten' endpoints."
    
    # Wayback CDX API エンドポイント
    CDX_API = "https://web.archive.org/cdx/search/cdx"
    
    # 除外する拡張子（静的アセット）
    EXCLUDE_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
        ".css", ".woff", ".woff2", ".ttf", ".eot",
        ".mp3", ".mp4", ".avi", ".mov",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    }
    
    # 興味深いパスパターン（優先的に調査）
    INTERESTING_PATTERNS = [
        "admin", "debug", "test", "staging", "dev",
        "api/v", "internal", "private", "backup",
        "config", "setup", "install", "phpinfo",
        "swagger", "graphql", "console", "dashboard",
    ]

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain (e.g., example.com)"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["discover", "compare", "interesting"],
                            "description": (
                                "discover: Get all historical URLs. "
                                "compare: Compare with current URLs (requires current_urls). "
                                "interesting: Filter for potentially interesting endpoints."
                            ),
                            "default": "discover"
                        },
                        "current_urls_file": {
                            "type": "string",
                            "description": "Path to file with current URLs (for compare mode)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum URLs to retrieve",
                            "default": 1000
                        },
                        "from_year": {
                            "type": "integer",
                            "description": "Start year for archive search (e.g., 2015)"
                        },
                        "to_year": {
                            "type": "integer",
                            "description": "End year for archive search (e.g., 2023)"
                        }
                    },
                    "required": ["domain"]
                }
            }
        }

    def run(
        self, 
        domain: str = "", 
        mode: str = "discover",
        current_urls_file: Optional[str] = None,
        limit: int = 1000,
        from_year: Optional[int] = None,
        to_year: Optional[int] = None,
        **kwargs
    ) -> str:
        """
        Wayback Machine から過去URLを取得・分析
        """
        # 入力バリデーション
        if not domain:
            return json.dumps({"error": "Domain is required"})
        
        # ドメインサニタイズ
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        
        if any(c in domain for c in [";", "|", "&", "$", "`", " "]):
            return json.dumps({"error": "Unsafe characters in domain"})
        
        limit = min(max(limit, 10), 10000)  # 10-10000に制限
        
        try:
            # Wayback CDX APIからURL取得
            historical_urls = self._fetch_wayback_urls(
                domain, limit, from_year, to_year
            )
            
            if not historical_urls:
                return json.dumps({
                    "domain": domain,
                    "status": "no_results",
                    "message": "No archived URLs found for this domain"
                })
            
            # 静的アセットを除外
            filtered_urls = self._filter_urls(historical_urls)
            
            if mode == "discover":
                return self._mode_discover(domain, filtered_urls)
            
            elif mode == "compare":
                return self._mode_compare(domain, filtered_urls, current_urls_file)
            
            elif mode == "interesting":
                return self._mode_interesting(domain, filtered_urls)
            
            else:
                return json.dumps({"error": f"Unknown mode: {mode}"})
                
        except Exception as e:
            return json.dumps({"error": f"Analysis failed: {str(e)}"})

    def _fetch_wayback_urls(
        self, 
        domain: str, 
        limit: int,
        from_year: Optional[int],
        to_year: Optional[int]
    ) -> List[str]:
        """
        Wayback CDX APIからURLを取得
        """
        # CDX API パラメータ
        params = [
            f"url=*.{domain}/*",
            "output=text",
            "fl=original",
            "collapse=urlkey",
            f"limit={limit}",
        ]
        
        if from_year:
            params.append(f"from={from_year}")
        if to_year:
            params.append(f"to={to_year}")
        
        url = f"{self.CDX_API}?{'&'.join(params)}"
        
        # curl でフェッチ（レート制限対応）
        cmd = [
            "curl",
            "-s",
            "-m", "60",  # 60秒タイムアウト
            "--retry", "3",
            "--retry-delay", "2",
            url
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )
        
        if result.returncode != 0:
            return []
        
        urls = [
            line.strip() 
            for line in result.stdout.split("\n") 
            if line.strip() and line.startswith("http")
        ]
        
        return urls

    def _filter_urls(self, urls: List[str]) -> List[str]:
        """
        静的アセットを除外し、重複を排除
        """
        filtered: Set[str] = set()
        
        for url in urls:
            # 拡張子チェック
            lower_url = url.lower()
            if any(lower_url.endswith(ext) for ext in self.EXCLUDE_EXTENSIONS):
                continue
            
            # クエリパラメータを除去してユニーク化
            base_url = url.split("?")[0]
            filtered.add(base_url)
        
        return list(filtered)

    def _mode_discover(self, domain: str, urls: List[str]) -> str:
        """
        発見モード: 全URLをリスト化
        """
        # パスでグループ化
        path_groups: Dict[str, List[str]] = {}
        
        for url in urls:
            try:
                # パスの最初の2セグメントでグループ化
                path = url.split(domain)[-1] if domain in url else url
                parts = path.strip("/").split("/")
                group_key = "/" + "/".join(parts[:2]) if len(parts) >= 2 else "/" + parts[0] if parts else "/"
                
                if group_key not in path_groups:
                    path_groups[group_key] = []
                if len(path_groups[group_key]) < 10:  # グループあたり10URLまで
                    path_groups[group_key].append(url)
            except Exception:
                continue
        
        return json.dumps({
            "domain": domain,
            "mode": "discover",
            "total_urls": len(urls),
            "unique_path_groups": len(path_groups),
            "path_groups": path_groups,
            "sample_urls": urls[:50]  # サンプル50件
        }, indent=2)

    def _mode_compare(
        self, 
        domain: str, 
        historical_urls: List[str],
        current_urls_file: Optional[str]
    ) -> str:
        """
        比較モード: 過去と現在のURL差分を抽出
        """
        if not current_urls_file:
            return json.dumps({
                "error": "current_urls_file is required for compare mode"
            })
        
        # 現在のURL読み込み
        try:
            with open(current_urls_file, "r") as f:
                current_urls = {line.strip().split("?")[0] for line in f if line.strip()}
        except FileNotFoundError:
            return json.dumps({"error": f"File not found: {current_urls_file}"})
        except Exception as e:
            return json.dumps({"error": f"Failed to read file: {str(e)}"})
        
        # 正規化
        historical_set = {url.split("?")[0] for url in historical_urls}
        
        # 差分計算
        disappeared = historical_set - current_urls  # 過去にはあったが今はない
        appeared = current_urls - historical_set     # 今あるが過去にはなかった
        
        # 消失URLから興味深いものを抽出
        interesting_disappeared = [
            url for url in disappeared
            if any(pattern in url.lower() for pattern in self.INTERESTING_PATTERNS)
        ]
        
        return json.dumps({
            "domain": domain,
            "mode": "compare",
            "historical_count": len(historical_set),
            "current_count": len(current_urls),
            "disappeared_count": len(disappeared),
            "appeared_count": len(appeared),
            "interesting_disappeared": interesting_disappeared[:30],
            "disappeared_sample": list(disappeared)[:50],
            "appeared_sample": list(appeared)[:20],
            "recommendation": (
                f"Found {len(disappeared)} disappeared URLs. "
                f"{len(interesting_disappeared)} are potentially interesting. "
                "Check if any contain sensitive functionality."
            )
        }, indent=2)

    def _mode_interesting(self, domain: str, urls: List[str]) -> str:
        """
        興味深いエンドポイント抽出モード
        """
        interesting: List[Dict[str, Any]] = []
        
        for url in urls:
            lower_url = url.lower()
            matched_patterns = [
                pattern for pattern in self.INTERESTING_PATTERNS
                if pattern in lower_url
            ]
            
            if matched_patterns:
                interesting.append({
                    "url": url,
                    "matched_patterns": matched_patterns,
                    "priority": "high" if len(matched_patterns) > 1 else "medium"
                })
        
        # 優先度でソート
        interesting.sort(key=lambda x: (x["priority"] != "high", len(x["matched_patterns"])))
        
        return json.dumps({
            "domain": domain,
            "mode": "interesting",
            "total_historical": len(urls),
            "interesting_count": len(interesting),
            "interesting_endpoints": interesting[:100],
            "recommendation": (
                f"Found {len(interesting)} potentially interesting historical endpoints. "
                "Verify their current status with httpx or manual inspection."
            )
        }, indent=2)
