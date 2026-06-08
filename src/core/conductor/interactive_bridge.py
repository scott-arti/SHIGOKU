
"""
Interactive Bridge: CLIとMasterConductorの架け橋

CLIからの入力を受け取り、MasterConductorを初期化・実行する。
"""

import logging
import asyncio
from src.core.engine.master_conductor import MasterConductor, Task, TaskState
from src.core.config_manager import get_config_manager
from src.core.project.project_manager import ProjectManager
from src.commands import print_banner, print_step, print_result

logger = logging.getLogger(__name__)

class InteractiveBridge:
    """CLIとのインタラクティブなセッションを管理する架け橋"""
    
    def __init__(self):
        pass

    @staticmethod
    def ask_for_approval(action_description: str, default: bool = False) -> bool:
        """
        破壊的なアクションなどの実行前にユーザーへ承認を求める
        
        Args:
            action_description: 確認を求めるアクションの内容
            default: デフォルトの選択（ユーザーが何も入力せずにEnterを押した場合）
        """
        import sys
        
        print(f"\n\033[93m[⚠️ REQUIRES APPROVAL]\033[0m")
        print(f"\033[93mThe following high-risk action is requested to run:\033[0m")
        print(f"  > {action_description}")
        
        default_str = "Y/n" if default else "y/N"
        prompt = f"Do you want to allow this action? [{default_str}]: "
        
        # TTYでない（自動化CI環境など）場合は安全側に倒してデフォルト値を返す
        if not sys.stdin.isatty():
            logger.warning(f"Non-interactive environment detected. Auto-resolving approval to: {default}")
            return default
            
        try:
            choice = input(prompt).strip().lower()
            if not choice:
                return default
            return choice in ("y", "yes")
        except (KeyboardInterrupt, EOFError):
            print("\nAction denied.")
            return False

def start_interactive_session(
    mode="bugbounty",
    scope_file=None,
    auto_goal="Reconnaissance",
    auto_target=None,
    dry_run=False,
    cookies=None,
    bearer_token=None,
    live_dashboard=False,
    recipe_file=None,
    profile=None,
    llm_client=None,
    recon_start_step=None,
    recon_end_step=None,
):
    """
    インタラクティブセッションを開始
    
    Args:
        mode: 動作モード (bugbounty/vulntest/ctf)
        scope_file: スコープ定義ファイルパス
        auto_goal: 自動実行するゴール (例: "Reconnaissance", "Crawl")
        auto_target: ターゲットURL/ドメイン
        dry_run: Dry Run モード (攻撃を実行しない)
        cookies: 認証用Cookie文字列
        bearer_token: 認証用Bearerトークン (raw JWT or "Bearer <token>")
        live_dashboard: ダッシュボード表示フラグ
        recipe_file: 実行するRecipeファイルパス
        recon_start_step: recon_master の開始ステップ上書き (1-8)
        recon_end_step: recon_master の終了ステップ上書き (1-8)
    """
    print_banner()
    print_step("🚀", f"Starting session (Mode: {mode})")
    
    # 1. Config初期化 & スコープ読み込み
    cm = get_config_manager()
    if scope_file:
        from src.core.domain.scope.scope_manager import ScopeManager
        sm = ScopeManager(scope_file)
        sm.load_scope()
    
    # モード設定
    cm.config.mode = mode
    if dry_run:
        cm.config.safe_mode = True
        logger.info("Dry run enabled (Safe Mode)")

    normalized_profile = profile
    if not normalized_profile:
        normalized_profile = "ctf" if str(mode).lower() == "ctf" else "bbpt"
    logger.info("Scan profile resolved: %s", normalized_profile)

    # 2. プロジェクト管理初期化
    pm = None
    if auto_target:
        try:
            pm = ProjectManager(auto_target)
            print_step("📂", f"Project Context: {pm.project_name}")
        except Exception as e:
            logger.warning(f"Failed to initialize ProjectManager: {e}")

    # 3. MasterConductor初期化
    mc = MasterConductor(
        project_manager=pm, 
        auto_checkpoint=True,
        llm_client=llm_client
    )

    # 3.5 RequestGuardの初期化 (HITL連携)
    try:
        from src.core.security.request_guard import get_request_guard

        async def hitl_callback(task_info: dict) -> bool:
            """RequestGuardからの認可リクエストをユーザーに尋ねる"""
            prompt = task_info.get("prompt", "承認が必要なリクエストがあります。許可しますか？")
            # 同期メソッド InteractiveBridge.ask_for_approval を非同期スレッドで実行
            return await asyncio.to_thread(InteractiveBridge.ask_for_approval, prompt, default=True)

        mode_val = str(cm.config.mode).lower() if cm.config.mode else "bugbounty"
        get_request_guard(mode=mode_val, hitl_callback=hitl_callback)
        print_step("🛡️", f"RequestGuard initialized (Mode: {mode_val}) with HITL callback")
    except Exception as e:
        logger.warning(f"Failed to initialize RequestGuard: {e}")
    
    # 4. コンテキスト設定
    if cookies:
        mc.context.target_info["cookies"] = cookies
        print_step("🍪", "Cookies loaded into context")

    if bearer_token:
        token = str(bearer_token).strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if token:
            auth_headers = mc.context.target_info.get("auth_headers", {})
            if not isinstance(auth_headers, dict):
                auth_headers = {}
            auth_headers["Authorization"] = f"Bearer {token}"
            if cookies:
                auth_headers["Cookie"] = cookies
            mc.context.target_info["auth_headers"] = auth_headers
            mc.context.target_info["bearer_token"] = token
            print_step("🔐", "Bearer token loaded into context")

    if auto_target:
        mc.context.target_info["target"] = auto_target
    mc.context.target_info["scan_profile"] = normalized_profile
    mc.context.target_info["profile"] = normalized_profile

    if recon_start_step is not None:
        mc.context.target_info["recon_start_step"] = int(recon_start_step)
    if recon_end_step is not None:
        mc.context.target_info["recon_end_step"] = int(recon_end_step)
    if recon_start_step is not None or recon_end_step is not None:
        start = int(mc.context.target_info.get("recon_start_step", 1))
        end = int(mc.context.target_info.get("recon_end_step", 8))
        print_step("⚙️", f"Recon step override enabled: {start}-{end}")
    
    # 5. Recipeロード
    if recipe_file:
        try:
            mc.recipe_loader.load_recipe(recipe_file)
            print_step("📜", f"Loaded Recipe: {recipe_file}")
            
            # Recipeからのタスクを注入
            recipe_tasks = mc._load_recipe_tasks()
            if recipe_tasks:
                mc.task_queue.add_batch(recipe_tasks, source="interactive_bridge_recipe")
                print_step("📝", f"Added {len(recipe_tasks)} tasks from recipe")
            else:
                print_result(False, "Recipe matched no tasks. Check your recipe tags and target context.")
        except Exception as e:
            print_result(False, f"Failed to load recipe {recipe_file}: {e}")
            return

    if auto_target:
        # 既にタスクがある（Recipe由来など）場合は追加しない、なければデフォルトを追加
        if mc.task_queue.is_empty():
            print_step("🎯", f"Planning for target: {auto_target}")
            tasks = mc.plan(auto_goal, auto_target)
            if tasks:
                mc.task_queue.add_batch(tasks, source="interactive_bridge_plan")
            else:
                # Fallback: 手動で1つタスクを追加
                fallback_task = Task(
                    id="manual_start",
                    name=f"{auto_goal}: {auto_target}",
                    agent_type="universal",
                    action="execute",
                    params={"target": auto_target}
                )
                mc.task_queue.add(fallback_task)
    else:
        # 完全インタラクティブモード（プロンプト待機）
        pass

    # 6. 実行
    try:
        if live_dashboard:
            # Dashboard setup
            pass
            
        print_step("⏳", "Executing tasks...")
        mc.execute_with_replan()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user.")
        # mc.close() が finally で呼ばれるのでここではフラグ立てのみで良いが
        # mc 自体がシグナルハンドラを持っているので、そこでも処理される
    except Exception as e:
        logger.exception("Session failed")
        print_result(False, f"Session failed: {e}")
    finally:
        # グレースフルシャットダウン (セッション保存とリソース解放)
        mc.close()
