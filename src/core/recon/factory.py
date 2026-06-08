from typing import Type
from src.core.domain.model.target import TargetAsset, TargetType
from src.core.recon.recipes import (
    ReconMode,
    BaseRecipe,
    WildcardBBRecipe,
    FixedDomainBBRecipe,
    SingleUrlBBRecipe,
    MultiUrlBBRecipe,
    SingleUrlCTFRecipe,
    SingleUrlTestRecipe,
    FileAnalysisRecipe
)

class ReconRecipeFactory:
    """
    ターゲットとモードから最適な偵察レシピを生成する
    """
    
    @staticmethod
    def create(mode: ReconMode, asset: TargetAsset, orchestrator: any) -> BaseRecipe:
        """
        レシピインスタンスの生成
        """
        recipe_map = {
            ReconMode.WILDCARD_BB: WildcardBBRecipe,
            ReconMode.FIXED_DOMAIN_BB: FixedDomainBBRecipe,
            ReconMode.SINGLE_URL_BB: SingleUrlBBRecipe,
            ReconMode.MULTI_URL_BB: MultiUrlBBRecipe,
            ReconMode.SINGLE_URL_CTF: SingleUrlCTFRecipe,
            ReconMode.SINGLE_URL_TEST: SingleUrlTestRecipe,
            ReconMode.FILE_ANALYSIS: FileAnalysisRecipe,
        }
        
        recipe_cls = recipe_map.get(mode)
        if not recipe_cls:
            # デフォルトとしてテスト用を選択
            recipe_cls = SingleUrlTestRecipe
            
        return recipe_cls(asset, orchestrator)
    
    @staticmethod
    def determine_mode(asset: TargetAsset, global_mode: str) -> ReconMode:
        """
        ターゲット資材の種類と実行モードから ReconMode を判定
        """
        # CTF モード
        if global_mode == "CTF":
            if asset.asset_type == TargetType.LOCAL_FILE:
                return ReconMode.FILE_ANALYSIS
            return ReconMode.SINGLE_URL_CTF

        # BugBounty モード
        if global_mode == "BUG_BOUNTY":
            if asset.asset_type == TargetType.WILDCARD_DOMAIN:
                return ReconMode.WILDCARD_BB
            
            if asset.asset_type == TargetType.SINGLE_URL_INTERNAL:
                return ReconMode.SINGLE_URL_TEST # DVWA 等のテスト環境

            # 固定ドメインとシングルURLの判別 (入力形状に依存)
            if asset.asset_type == TargetType.SINGLE_URL_PUBLIC:
                return ReconMode.SINGLE_URL_BB
            
            # TODO: MULTI_URL_BB の対応

        # デフォルト
        return ReconMode.SINGLE_URL_TEST
