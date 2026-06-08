"""
GAU Integrator

GAU(GetAllUrls)結果からパターンを抽出し、ワードリスト選択を最適化
APIコスト最適化のため、統計サマリーのみを返す
"""

import logging
from typing import List, Dict, Optional
from collections import Counter
from urllib.parse import urlparse
import re

from src.core.adapters.external.base_external_adapter import ToolInput
from src.core.adapters.external.external_tool_executor import get_global_executor
from src.core.adapters.external.gau_adapter import GauAdapter

logger = logging.getLogger(__name__)


class GAUIntegrator:
    """
    GAU統合クラス
    
    GAU(GetAllUrls)を実行してURL収集し、
    パターン分析結果をワードリスト選択に活用
    """
    
    def __init__(self):
        self._executor = get_global_executor()
        self._gau_adapter = GauAdapter()
        self._gau_available: Optional[bool] = None

    async def _ensure_gau_available(self) -> bool:
        if self._gau_available is None:
            self._gau_available = await self._gau_adapter.health_check()
        return self._gau_available
    
    async def fetch_urls(
        self,
        domain: str,
        timeout: int = 60,
        providers: List[str] = None
    ) -> List[str]:
        """
        GAUでURL取得
        
        Args:
            domain: ターゲットドメイン
            timeout: タイムアウト秒
            providers: 使用するプロバイダー（wayback, otx, commoncrawl）
        
        Returns:
            発見されたURL一覧
        """
        if not await self._ensure_gau_available():
            logger.warning("GAU not available")
            return []

        options: Dict[str, object] = {"subs": True}
        if providers:
            options["providers"] = ",".join(providers)

        try:
            result = await self._executor.execute(
                self._gau_adapter,
                ToolInput(target=domain, options=options, timeout_seconds=timeout),
            )
            status_value = str(getattr(result.status, "value", result.status)).lower()
            if status_value != "success":
                logger.warning("GAU adapter status=%s for %s: %s", status_value, domain, result.error_message)
                return []
            urls: List[str] = []
            for item in (result.data or []):
                if isinstance(item, dict):
                    found_url = item.get("url")
                    if found_url:
                        urls.append(found_url)
            logger.info("GAU adapter found %d URLs for %s", len(urls), domain)
            return urls
        except Exception as e:
            logger.error("GAU adapter failed for %s: %s", domain, e)
            return []
    
    def analyze_patterns(self, urls: List[str]) -> Dict:
        """
        URLパターンを分析（AIに渡す統計サマリー生成）
        
        Args:
            urls: URL一覧
        
        Returns:
            パターン分析結果（統計サマリー）
        """
        if not urls:
            return {}
        
        # パス分析
        path_segments = Counter()
        extensions = Counter()
        params = Counter()
        api_patterns = Counter()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                
                # パスセグメント
                path = parsed.path.strip('/')
                if path:
                    segments = path.split('/')
                    for seg in segments[:3]:  # 最初の3セグメントのみ
                        if seg and not seg.isdigit():
                            path_segments[seg] += 1
                
                # 拡張子
                if '.' in path:
                    ext = path.rsplit('.', 1)[-1].lower()
                    if len(ext) <= 5:
                        extensions[ext] += 1
                
                # パラメータ
                if parsed.query:
                    for param in parsed.query.split('&'):
                        if '=' in param:
                            key = param.split('=')[0]
                            if key and len(key) <= 30:
                                params[key] += 1
                
                # APIパターン検出
                if re.search(r'/api/|/v\d+/|/graphql|/rest/', path, re.I):
                    api_patterns['api_detected'] += 1
                if re.search(r'/admin|/backend|/manage', path, re.I):
                    api_patterns['admin_detected'] += 1
                    
            except Exception:
                continue
        
        # 統計サマリー生成（AIに渡す軽量データ）
        return {
            "total_urls": len(urls),
            "top_paths": dict(path_segments.most_common(20)),
            "top_extensions": dict(extensions.most_common(10)),
            "top_params": dict(params.most_common(15)),
            "patterns": {
                "has_api": api_patterns.get('api_detected', 0) > 0,
                "has_admin": api_patterns.get('admin_detected', 0) > 0,
                "api_count": api_patterns.get('api_detected', 0),
                "admin_count": api_patterns.get('admin_detected', 0),
            },
            "recommendations": self._generate_recommendations(
                path_segments, extensions, api_patterns
            )
        }
    
    def _generate_recommendations(
        self,
        paths: Counter,
        extensions: Counter,
        api_patterns: Counter
    ) -> List[str]:
        """ワードリスト推奨を生成"""
        recommendations = []
        
        # API検出
        if api_patterns.get('api_detected', 0) > 5:
            recommendations.append("api")
        
        # GraphQL検出
        if any('graphql' in p.lower() for p in paths.keys()):
            recommendations.append("graphql")
        
        # 拡張子ベース
        if extensions.get('php', 0) > 10:
            recommendations.append("php")
        if extensions.get('asp', 0) > 5 or extensions.get('aspx', 0) > 5:
            recommendations.append("asp")
        if extensions.get('jsp', 0) > 5:
            recommendations.append("jsp")
        
        # 管理画面検出
        if api_patterns.get('admin_detected', 0) > 3:
            recommendations.append("admin")
        
        return recommendations
    
    async def get_summary_for_ai(self, domain: str) -> str:
        """
        AI向けの簡潔なサマリー文字列を生成
        
        APIコスト最適化: ファイル全体ではなくサマリーのみ
        """
        urls = await self.fetch_urls(domain)
        if not urls:
            return f"GAU: {domain} - No URLs found"
        
        analysis = self.analyze_patterns(urls)
        
        summary_lines = [
            f"GAU Analysis for {domain}:",
            f"- Total URLs: {analysis['total_urls']}",
            f"- Top paths: {', '.join(list(analysis['top_paths'].keys())[:5])}",
            f"- Extensions: {', '.join(list(analysis['top_extensions'].keys())[:5])}",
            f"- Has API endpoints: {analysis['patterns']['has_api']}",
            f"- Has admin paths: {analysis['patterns']['has_admin']}",
            f"- Recommended wordlists: {', '.join(analysis['recommendations'])}"
        ]
        
        return '\n'.join(summary_lines)


# シングルトン
_gau_instance = None

def get_gau_integrator() -> GAUIntegrator:
    """GAUIntegratorのシングルトン取得"""
    global _gau_instance
    if _gau_instance is None:
        _gau_instance = GAUIntegrator()
    return _gau_instance
