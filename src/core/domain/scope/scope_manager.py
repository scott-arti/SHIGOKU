from pathlib import Path
from typing import List, Optional
import logging

from src.core.domain.model.target import TargetAsset, TargetType
from src.core.security.scope_parser import load_scope_from_text, ScopeDefinition, get_scope_parser

logger = logging.getLogger(__name__)

class ScopeManager:
    """
    スコープ定義ファイル(scope.txt等)を読み込み、
    1. TargetAssetのリストを生成する (Crawling Seed)
    2. EthicsGuardにスコープを適用する (Access Control)
    """

    def __init__(self, scope_file: str = "scope.txt"):
        self.scope_file = Path(scope_file)
        self.targets: List[TargetAsset] = []
        self.scope_definition: Optional[ScopeDefinition] = None

    def load_scope(self) -> List[TargetAsset]:
        """
        スコープファイルを読み込み、TargetAssetのリストを返す。
        同時にEthicsGuardへの適用も行う。
        """
        if not self.scope_file.exists():
            logger.warning(f"Scope file not found: {self.scope_file}")
            return []

        try:
            content = self.scope_file.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to read scope file: {e}")
            return []

        # 1. EthicsGuardへの適用 (既存のScopeParserを利用)
        parser = get_scope_parser()
        self.scope_definition = load_scope_from_text(content, program_name="Loaded Scope")
        
        # 2. TargetAssetの生成 (In-Scope Domain/IP/URL のみ)
        # 行ごとのパースを行い、Out-of-Scopeセクションはスキップする
        
        raw_lines = content.splitlines()
        assets = []
        is_out_of_scope_section = False
        
        for line in raw_lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue
                
            line_lower = line_stripped.lower()

            # セクション判定 (ScopeParserと同じロジック)
            if any(kw in line_lower for kw in parser.OUT_OF_SCOPE_KEYWORDS):
                is_out_of_scope_section = True
                continue
            
            if "in scope" in line_lower or "in-scope" in line_lower:
                is_out_of_scope_section = False
                continue

            # コメント行自体のスキップ (セクション判定の後に行うことで、 # Out-of-Scope も検知させる)
            if line_stripped.startswith("#"):
                # In-Scopeセクション内のコメントはスキップ
                continue
            
            if is_out_of_scope_section:
                continue

            # TargetAssetを作成
            # ここに来るのは In-Scope セクションの行のみ
            asset = TargetAsset.create(line_stripped)
            
            # EthicsGuardによる追加検証
            # IPアドレスやドメインが許可されているかを念のため確認
            if asset.asset_type in [TargetType.SINGLE_URL_PUBLIC, TargetType.SINGLE_URL_INTERNAL]:
                check_url = asset.raw_input
                if "://" not in check_url:
                    check_url = f"http://{check_url}"
                
                is_allowed, reason = parser.validate_target(check_url)
                if not is_allowed:
                    logger.info(f"Skipping target (Out of Scope by EthicsGuard): {asset.raw_input} Reason: {reason}")
                    continue

            assets.append(asset)
            
        self.targets = assets
        logger.info(f"Loaded {len(self.targets)} targets from {self.scope_file}")
        return self.targets

    @staticmethod
    def load(source: str) -> List[TargetAsset]:
        """
        ファイルパスまたはURL文字列からTargetAssetのリストを生成する便利メソッド。
        
        Args:
            source: スコープファイルへのパス、またはターゲットURL
            
        Returns:
            List[TargetAsset]: 生成されたアセットのリスト
        """
        if "://" in source or source.startswith("www."):
            # Clearly a URL, skip file system check
            return [TargetAsset.from_input(source)]

        try:
            path = Path(source)
            # Only check file system if it's likely a file path (not too long, no weird chars)
            if len(source) < 255 and path.exists() and path.is_file():
                # ファイルパスとして処理
                manager = ScopeManager(str(path))
                return manager.load_scope()
        except OSError:
            # path string might be too long or invalid for OS
             logger.debug(f"Source '{source}' is not a valid file path, treating as target string.")

        # 単一のターゲットとして処理
        # 既に http/https があるか、ドメインのみかを判定してラップ
        return [TargetAsset.from_input(source)]

    def get_targets(self) -> List[TargetAsset]:
        return self.targets
