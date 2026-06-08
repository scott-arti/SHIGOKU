"""
SubdomainContextLoader

pipeline.py の分類結果 JSON からサブドメイン情報を読み込み、
URL に SubdomainContext を付与する。

Implementation Plan Phase 6 準拠
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from src.core.models.url_context import SubdomainContext

logger = logging.getLogger(__name__)


class SubdomainContextLoader:
    """
    pipeline.py の結果から SubdomainContext を構築し、URL に付与する
    
    使用例:
        loader = SubdomainContextLoader()
        loader.load_pipeline_results("/path/to/workspace/projects/<project>/scans/raw/")
        context = loader.get_context_for_url("https://api.example.com/users")
    """
    
    def __init__(self):
        # subdomain -> SubdomainContext のマップ
        self._context_map: Dict[str, SubdomainContext] = {}
        self._loaded = False
    
    def load_pipeline_results(self, output_dir: str) -> int:
        """
        pipeline.py の出力ディレクトリから分類結果を読み込む
        
        Args:
            output_dir: workspace/projects/<project>/scans/raw/ ディレクトリパス
        
        Returns:
            読み込んだサブドメイン数
        """
        output_path = Path(output_dir)
        
        if not output_path.exists():
            logger.warning("Pipeline output directory not found: %s", output_dir)
            return 0
        
        # 分類カテゴリのマッピング
        CATEGORY_FILES = {
            "live_200": "live_200.json",
            "live_403": "live_403.json",
            "live_401_302": "live_401_302.json",
            "dev_staging": "dev_staging.json",
            "internal_names": "internal_names.json",
            "high_value": "high_value.json",
            "web_ports": "web_ports.json",
            "cloud_aws": "cloud_aws.json",
            "cloud_azure": "cloud_azure.json",
            "cloud_gcp": "cloud_gcp.json",
            "live_uncategorized": "live_uncategorized.json",
        }
        
        total_loaded = 0
        
        for category, filename in CATEGORY_FILES.items():
            file_path = output_path / filename
            if not file_path.exists():
                continue
            
            try:
                entries = json.loads(file_path.read_text())
                if not isinstance(entries, list):
                    continue
                
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    
                    subdomain = entry.get("subdomain", "")
                    if not subdomain:
                        continue
                    
                    # 既存のコンテキストがあれば category_tags を追加
                    if subdomain in self._context_map:
                        existing = self._context_map[subdomain]
                        if category not in existing.category_tags:
                            existing.category_tags.append(category)
                    else:
                        # 新規作成
                        context = SubdomainContext.from_pipeline_entry(entry)
                        context.category_tags = [category]
                        self._context_map[subdomain] = context
                        total_loaded += 1
                
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("Failed to load %s: %s", file_path, e)
        
        self._loaded = True
        logger.info("Loaded %d subdomains from pipeline results", total_loaded)
        return total_loaded
    
    def load_from_dict(self, data: Dict[str, Dict[str, Any]]) -> int:
        """
        step8_return_to_mc 形式の辞書から読み込む
        
        Args:
            data: {category: {file, count, description, tags}} 形式の辞書
        
        Returns:
            読み込んだサブドメイン数
        """
        total_loaded = 0
        
        for category, info in data.items():
            if category.startswith("_"):  # _tech_stack 等はスキップ
                continue
            
            file_path = info.get("file")
            if not file_path:
                continue
            
            try:
                path = Path(file_path)
                if not path.exists():
                    continue
                
                entries = json.loads(path.read_text())
                if not isinstance(entries, list):
                    continue
                
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    
                    subdomain = entry.get("subdomain", "")
                    if not subdomain:
                        continue
                    
                    if subdomain in self._context_map:
                        existing = self._context_map[subdomain]
                        if category not in existing.category_tags:
                            existing.category_tags.append(category)
                    else:
                        context = SubdomainContext.from_pipeline_entry(entry)
                        context.category_tags = [category]
                        self._context_map[subdomain] = context
                        total_loaded += 1
                
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("Failed to load %s: %s", file_path, e)
        
        self._loaded = True
        logger.info("Loaded %d subdomains from dict", total_loaded)
        return total_loaded
    
    def get_context_for_url(self, url: str) -> Optional[SubdomainContext]:
        """
        URL からサブドメインを抽出し、対応する SubdomainContext を返す
        
        Args:
            url: 対象 URL
        
        Returns:
            SubdomainContext または None (見つからない場合)
        """
        parsed = urlparse(url)
        subdomain = parsed.hostname
        
        if not subdomain:
            return None
        
        # 完全一致
        if subdomain in self._context_map:
            return self._context_map[subdomain]
        
        # ワイルドカードマッチング（サブドメインの親ドメイン検索）
        # 例: api.example.com → example.com を検索
        parts = subdomain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._context_map:
                return self._context_map[parent]
        
        return None
    
    def get_all_subdomains(self) -> List[str]:
        """登録されている全サブドメインを取得"""
        return list(self._context_map.keys())
    
    def get_subdomains_by_category(self, category: str) -> List[SubdomainContext]:
        """指定カテゴリのサブドメインを取得"""
        return [
            ctx for ctx in self._context_map.values()
            if category in ctx.category_tags
        ]
    
    @property
    def is_loaded(self) -> bool:
        """データが読み込まれているか"""
        return self._loaded
    
    @property
    def subdomain_count(self) -> int:
        """登録サブドメイン数"""
        return len(self._context_map)
