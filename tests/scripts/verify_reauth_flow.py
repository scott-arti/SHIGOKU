import asyncio
import logging
import time
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

# プロジェクトルートをパスに追加
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.core.engine.master_conductor import MasterConductor
from src.core.infra.event_bus import get_event_bus, EventType, Event
from src.core.infra.network_client import AsyncNetworkClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("VerifyAutoReauth")

async def verify_flow():
    """自律的再認証のE2Eフローを検証する"""
    event_bus = get_event_bus()
    
    # 1. 成功イベントの待機用 Future
    reauth_success_future = asyncio.get_event_loop().create_future()
    reauth_task_dispatched_future = asyncio.get_event_loop().create_future()

    async def on_reauth_success(event):
        logger.info("🎯 Received REAUTH_SUCCESS event: %s", event.payload)
        if not reauth_success_future.done():
            reauth_success_future.set_result(event.payload)

    event_bus.subscribe(EventType.REAUTH_SUCCESS, on_reauth_success)
    
    # 2. MasterConductor のセットアップ
    # Dispatcher などの DI をモックする
    with patch("src.core.engine.master_conductor_facade.ExecutionContext"), \
         patch("src.core.engine.master_conductor_facade.settings") as mock_settings, \
         patch("src.core.engine.master_conductor_facade.AttackPlanner"), \
         patch("src.core.engine.master_conductor_facade.AsyncDatabaseWriter"), \
         patch("src.core.engine.master_conductor_facade.get_findings_repository"), \
         patch("src.core.engine.master_conductor_facade.get_phase_gate"), \
         patch("src.core.engine.flag_watcher.FlagWatcher") as mock_flag_watcher:
        
        mock_settings.environment = "BUG_BOUNTY"
        mock_settings.ctf_flag_format = "flag{.*}"
        mock_flag_watcher.get_instance.return_value = MagicMock()
        
        mc = MasterConductor()
        
        # 再認証に必要なトークンをプリセット
        mc.accumulated_context.auth_tokens["refresh_token"] = "mock_refresh_token_123"
        
        # 3. 401エラーのシミュレーション
        # AsyncNetworkClient が 401 を受け取ると SESSION_EXPIRED を投げるようになっているか確認
        logger.info("Step 1: Emitting SESSION_EXPIRED event...")
        test_url = "https://target-api.com/v1/user"
        
        await event_bus.emit(Event(
            type=EventType.SESSION_EXPIRED,
            payload={"url": test_url, "status": 401},
            source="TestMock"
        ))
        
        logger.info("Step 2: Waiting for re-auth flow to complete...")
        
        try:
            # 15秒以内に成功イベントが来るか
            result = await asyncio.wait_for(reauth_success_future, timeout=15.0)
            logger.info("✅ Verification SUCCESS: Re-authentication flow triggered and succeeded!")
            logger.info("Final Result Payload: %s", result)
            
            # 再検証: コンテキストが更新されているか
            logger.info("Context Check: auth_tokens['last_auth_error'] = %s", 
                        mc.accumulated_context.auth_tokens.get("last_auth_error"))
            
            if mc.accumulated_context.auth_tokens.get("last_auth_error") == "401_unauthorized":
                logger.info("✅ Context correctly marked as 401.")
            else:
                logger.error("❌ Context 401 mark missing!")

            # 最終的なトークンの確認 (AutoReauthSpecialist が生成した値)
            new_token = mc.accumulated_context.auth_tokens.get("access_token")
            status = mc.accumulated_context.auth_tokens.get("last_auth_status")
            
            if new_token and new_token.startswith("recovered_"):
                logger.info("✅ SUCCESS: Context updated with NEW token: %s", new_token)
            else:
                logger.error("❌ Context token NOT updated! Got: %s", new_token)

            if status == "restored":
                 logger.info("✅ SUCCESS: Status marked as restored.")
            else:
                 logger.error("❌ Status NOT marked as restored! Got: %s", status)
                
        except asyncio.TimeoutError:
            logger.error("❌ Verification FAILED: Re-authentication flow timed out.")
            sys.exit(1)
        finally:
            await event_bus.stop()

if __name__ == "__main__":
    asyncio.run(verify_flow())
