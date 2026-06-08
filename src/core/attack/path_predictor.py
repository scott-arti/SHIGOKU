"""
PathPredictor: KatanaのReconデータとターゲットのURLコンテキストを利用し、
アップロードされたファイルの「保存先URLの候補」を推測・スコアリングするモジュール。
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Set
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

@dataclass
class SuggestedPath:
    """生成された保存先パスの候補"""
    url: str      # 生成されたURL候補
    tier: int     # 生成元ランク (1: Katana, 2: Endpoint, 3: Fallback)
    reason: str   # 推測理由
    score: int    # 算出されたスコア

class PathPredictor:
    """
    保存先パス推測クラス
    """
    
    # Tier 3 (Fallback) 用の一般的なディレクトリ
    COMMON_DIRS = [
        "uploads/",
        "files/",
        "images/",
        "media/",
        "assets/",
        "storage/",
        "temp/",
        "public/uploads/",
        "static/uploads/",
        "data/",
        "user_data/"
    ]

    # ノイズとして除外するディレクトリの正規表現
    NOISE_DIRS = re.compile(r"/(css|js|fonts?|vendors?|static/(css|js|fonts?|vendors?)|themes?|plugin|node_modules|assets/(css|js|fonts?))/|(\.bundle\.js|favicon\.ico)$", re.IGNORECASE)

    # 静的ファイルの拡張子（パス抽出用）
    STATIC_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.docx', '.zip', '.rar', '.xls', '.xlsx', '.doc', '.txt', '.csv'}

    def __init__(self, katana_urls: Optional[List[str]] = None):
        """
        Args:
            katana_urls: Katana等で収集されたURLのリスト
        """
        self.katana_urls = katana_urls or []

    def predict(self, endpoint_url: str, filename: str) -> List[SuggestedPath]:
        """
        保存先を推測し、スコア順にソートされたリストを返す
        """
        suggestions: List[SuggestedPath] = []
        seen_urls: Set[str] = set()
        
        parsed_endpoint = urlparse(endpoint_url)
        base_url = f"{parsed_endpoint.scheme}://{parsed_endpoint.netloc}"
        
        # Tier 1: Katana Context
        suggestions.extend(self._predict_tier1_katana(endpoint_url, base_url, filename, seen_urls))
        
        # Tier 2: Endpoint Context
        suggestions.extend(self._predict_tier2_endpoint(endpoint_url, base_url, filename, seen_urls))
        
        # Tier 3: Fallback Dictionary
        suggestions.extend(self._predict_tier3_fallback(endpoint_url, base_url, filename, seen_urls))
        
        # スコアで降順ソート
        return sorted(suggestions, key=lambda x: x.score, reverse=True)

    def _predict_tier1_katana(self, endpoint_url: str, base_url: str, filename: str, seen_urls: Set[str]) -> List[SuggestedPath]:
        """Tier 1 (Katana由来の実在パス) の推測"""
        results = []
        dirs: Set[str] = set()

        for url in self.katana_urls:
            parsed = urlparse(url)
            # 同一ドメインのみ対象
            if parsed.netloc != urlparse(base_url).netloc:
                continue
                
            path = parsed.path
            # 静的ファイルのディレクトリを抽出
            if any(path.lower().endswith(ext) for ext in self.STATIC_EXTENSIONS):
                # 最後に/をつける
                dir_path = path.rsplit('/', 1)[0]
                if not dir_path.endswith('/'):
                    dir_path += '/'
                
                # ノイズ除去
                if not self.NOISE_DIRS.search(dir_path):
                    dirs.add(dir_path)

        for d in dirs:
            # 絶対URL化
            full_url = urljoin(base_url, f"{d}{filename}")
            if full_url not in seen_urls:
                score = 50 + self._calculate_similarity_bonus(endpoint_url, full_url)
                results.append(SuggestedPath(
                    url=full_url,
                    tier=1,
                    reason="Found static file directory in Recon data",
                    score=score
                ))
                seen_urls.add(full_url)
                
        return results

    def _predict_tier2_endpoint(self, endpoint_url: str, base_url: str, filename: str, seen_urls: Set[str]) -> List[SuggestedPath]:
        """Tier 2 (EndpointURLからの推測) の推測"""
        results = []
        parsed = urlparse(endpoint_url)
        path_parts = parsed.path.strip('/').split('/')
        
        # エンドポイントの親ディレクトリ階層を候補にする
        current_path = "/"
        for part in path_parts[:-1]:
            current_path = urljoin(current_path, f"{part}/")
            full_url = urljoin(base_url, f"{current_path}{filename}")
            if full_url not in seen_urls:
                score = 30 + self._calculate_similarity_bonus(endpoint_url, full_url)
                results.append(SuggestedPath(
                    url=full_url,
                    tier=2,
                    reason="Parent directory of the upload endpoint",
                    score=score
                ))
                seen_urls.add(full_url)

        # ターゲットURLのディレクトリ + uploads 等
        if path_parts:
            endpoint_dir = parsed.path.rsplit('/', 1)[0]
            if not endpoint_dir.endswith('/'):
                endpoint_dir += '/'
            
            for sub in ["uploads/", "files/", "images/"]:
                full_url = urljoin(base_url, f"{endpoint_dir}{sub}{filename}")
                if full_url not in seen_urls:
                    score = 35 + self._calculate_similarity_bonus(endpoint_url, full_url)
                    results.append(SuggestedPath(
                        url=full_url,
                        tier=2,
                        reason=f"Common sub-directory '{sub}' under endpoint",
                        score=score
                    ))
                    seen_urls.add(full_url)

        return results

    def _predict_tier3_fallback(self, endpoint_url: str, base_url: str, filename: str, seen_urls: Set[str]) -> List[SuggestedPath]:
        """Tier 3 (一般的なFallback辞書) の推測"""
        results = []
        for d in self.COMMON_DIRS:
            full_url = urljoin(base_url, f"/{d}{filename}")
            if full_url not in seen_urls:
                score = 10 + self._calculate_similarity_bonus(endpoint_url, full_url)
                results.append(SuggestedPath(
                    url=full_url,
                    tier=3,
                    reason="Common default upload directory",
                    score=score
                ))
                seen_urls.add(full_url)
        
        # 直下も一応
        root_url = urljoin(base_url, f"/{filename}")
        if root_url not in seen_urls:
            results.append(SuggestedPath(url=root_url, tier=3, reason="Root directory", score=5))
            seen_urls.add(root_url)

        return results

    def _calculate_similarity_bonus(self, endpoint_url: str, candidate_url: str) -> int:
        """パスの類似度（共通プレフィックスの深さ）に応じたボーナス"""
        e_path = urlparse(endpoint_url).path.strip('/')
        c_path = urlparse(candidate_url).path.strip('/')
        
        e_parts = e_path.split('/')
        c_parts = c_path.split('/')
        
        bonus = 0
        min_len = min(len(e_parts), len(c_parts))
        
        for i in range(min_len):
            if e_parts[i] == c_parts[i]:
                # 1階層一致するごとに+10点
                bonus += 10
            else:
                break
        
        return bonus
