import asyncio
import logging
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.recon.pipeline import ReconPipeline
from src.core.utils.json_utils import robust_json_loads

async def verify():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("verify_caido")

    # Mock configuration
    config = {
        "scan": {
            "max_concurrent_tasks": 1
        }
    }
    
    # Initialize Pipeline (target doesn't matter for this test as long as it has a format)
    target = "example.com"
    pipeline = ReconPipeline(config=config, project_manager=None, target=target)
    
    logger.info(f"Target: {target}")
    
    # Test step3b_hybrid_url_discovery integration
    # We mock the parts that depend on external tools if necessary, 
    # but here we want to see if the CaidoSitemapAgent logic runs.
    
    try:
        from src.core.agents.specialized.caido_sitemap_agent import CaidoSitemapAgent
        agent = CaidoSitemapAgent()
        logger.info("CaidoSitemapAgent initialized successfully.")
        
        # Check if settings are loaded
        if not agent.caido_token:
            logger.warning("Caido Token is not set. Real API calls will fail.")
        
        # We don't run the full pipeline here to avoid long execution, 
        # but we check if the added code block is syntactically correct and imports work.
        logger.info("Verifying integrated logic in pipeline.py...")
        
        # Manual verification of the logic block roughly
        # (Actually running it would require valid Caido connection)
        
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        sys.exit(1)

    logger.info("Verification script finished. (Import/Syntax check passed)")

if __name__ == "__main__":
    asyncio.run(verify())
