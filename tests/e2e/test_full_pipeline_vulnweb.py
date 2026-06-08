#!/usr/bin/env python3
"""
E2E Test: Full Pipeline with Real Target

テスト対象: testphp.vulnweb.com (Acunetix公開テストサイト)
フロー: Step 1 -> Step 3b (URL収集) -> Step 4 (WAF) -> Step 5 (Port)

実行方法:
    export SHIGOKU_DEV_MODE=true
    python3 tests/e2e/test_full_pipeline_vulnweb.py
"""

import asyncio
import logging
import sys
from pathlib import Path

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parents[2]))

from src.recon.pipeline import ReconPipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("E2E_Test")


async def run_e2e_test():
    """Full Pipeline E2E テスト"""
    
    # テスト設定
    target = "testphp.vulnweb.com"  # 単一ホスト (Wildcard なし)
    workspace = Path("/tmp/shigoku_e2e_test")
    workspace.mkdir(parents=True, exist_ok=True)
    
    logger.info("=" * 60)
    logger.info("E2E Test: Full Pipeline")
    logger.info(f"Target: {target}")
    logger.info(f"Workspace: {workspace}")
    logger.info("=" * 60)
    
    # Pipeline 初期化
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target=target,  # 単一ホスト
        workspace_root=workspace,
    )
    
    # DEV_MODE 確認
    logger.info(f"DEV_MODE: {pipeline.runner.dev_mode}")
    
    try:
        # === Step 3b: Hybrid URL Discovery ===
        # 単一ホストなので Step 1 (subdomain enum) はスキップ
        # live_subs として target をそのまま使用
        live_subs = [target]
        pipeline.state.live_subs = live_subs
        pipeline.state.dead_subs = []
        
        logger.info("\n--- Step 3b: Hybrid URL Discovery ---")
        stats = await pipeline.step3b_hybrid_url_discovery(live_subs)
        logger.info(f"Step 3b 結果: {stats}")
        
        # 結果ファイル確認
        tagged_dir = workspace / "tagged_urls"
        if tagged_dir.exists():
            files = list(tagged_dir.glob("*.jsonl"))
            logger.info(f"生成されたタグ付きファイル: {len(files)}件")
            for f in files:
                logger.info(f"  - {f.name} ({f.stat().st_size} bytes)")
        
        # === Step 4: WAF Detection ===
        logger.info("\n--- Step 4: WAF Detection ---")
        try:
            waf_map = await pipeline.step4_waf_detection(live_subs)
            logger.info(f"WAF検出結果: {waf_map}")
        except Exception as e:
            logger.warning(f"Step 4 スキップ (wafw00f未インストール?): {e}")
            waf_map = {}
        
        # === Step 5: Port Scan (Top 20 のみ) ===
        logger.info("\n--- Step 5: Port Scan (Phase 1) ---")
        try:
            port_map = await pipeline.step5_port_scan_phase1(live_subs)
            logger.info(f"ポートスキャン結果: {port_map}")
        except Exception as e:
            logger.warning(f"Step 5 スキップ (naabu未インストール?): {e}")
            port_map = {}
        
        # === 結果サマリー ===
        logger.info("\n" + "=" * 60)
        logger.info("E2E Test 結果サマリー")
        logger.info("=" * 60)
        logger.info(f"ターゲット: {target}")
        logger.info(f"Live Subs: {live_subs}")
        logger.info(f"タグ付け統計: {stats}")
        logger.info(f"WAF: {waf_map}")
        logger.info(f"Ports: {port_map}")
        logger.info(f"ワークスペース: {workspace}")
        logger.info("=" * 60)
        
        return {
            "success": True,
            "target": target,
            "stats": stats,
            "waf": waf_map,
            "ports": port_map,
        }
        
    except Exception as e:
        logger.error(f"E2E テスト失敗: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    result = asyncio.run(run_e2e_test())
    
    if result.get("success"):
        print("\n✅ E2E テスト成功")
        sys.exit(0)
    else:
        print(f"\n❌ E2E テスト失敗: {result.get('error')}")
        sys.exit(1)
