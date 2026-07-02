"""
Context-Aware Tool Runner: ツール引数の動的最適化

Fingerprinterの結果に基づき、ターゲットの技術スタックに
合わせてツール引数を動的に最適化して実行。

例: WordPressならwpscan、Laravelならphpのwordlistを使用。
"""

from dataclasses import dataclass, field
from typing import Optional, Any, Dict
import subprocess
import shlex


@dataclass
class ToolConfig:
    """ツール設定"""
    name: str
    command_template: str
    tech_specific_args: dict[str, str] = field(default_factory=dict)
    default_args: str = ""


@dataclass
class ExecutionResult:
    """実行結果"""
    success: bool
    output: str
    error: str = ""
    command_used: str = ""
    context_applied: dict = field(default_factory=dict)


class ContextToolRunner:
    """
    Context-Aware Tool Runner
    
    Fingerprinterの結果に基づき、ツールの引数を最適化して実行。
    ターゲットがLaravelだと分かっているのにWordPress用の
    テストを回すのはROIを下げ、WAFに検知されるリスクを高める。
    """
    
    # 技術スタック別のWordlistマッピング
    TECH_WORDLISTS = {
        "wordpress": "/usr/share/wordlists/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "drupal": "/usr/share/wordlists/seclists/Discovery/Web-Content/CMS/drupal.txt",
        "joomla": "/usr/share/wordlists/seclists/Discovery/Web-Content/CMS/joomla.txt",
        "laravel": "/usr/share/wordlists/seclists/Discovery/Web-Content/PHP.fuzz.txt",
        "django": "/usr/share/wordlists/seclists/Discovery/Web-Content/Django.fuzz.txt",
        "rails": "/usr/share/wordlists/seclists/Discovery/Web-Content/Rails.fuzz.txt",
        "spring": "/usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt",
        "nodejs": "/usr/share/wordlists/seclists/Discovery/Web-Content/api-endpoints.txt",
        "default": "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    }
    
    # ツール設定
    TOOL_CONFIGS = {
        "ffuf": ToolConfig(
            name="ffuf",
            command_template="ffuf -u {target}/FUZZ -w {wordlist} {extra_args}",
            tech_specific_args={
                "wordpress": "-e .php,.txt,.log",
                "laravel": "-e .php,.blade.php,.env",
                "django": "-e .py,.html",
                "rails": "-e .rb,.erb,.html",
                "spring": "-e .java,.jsp,.xml",
                "nodejs": "-e .js,.json",
            },
            default_args="-mc 200,301,302,403 -t 50",
        ),
        "nuclei": ToolConfig(
            name="nuclei",
            command_template="nuclei -u {target} -t {templates} {extra_args}",
            tech_specific_args={
                "wordpress": "-tags wordpress",
                "drupal": "-tags drupal",
                "joomla": "-tags joomla",
                "laravel": "-tags laravel,php",
                "spring": "-tags spring",
                "nodejs": "-tags nodejs,javascript",
            },
            default_args="-severity medium,high,critical",
        ),
        "sqlmap": ToolConfig(
            name="sqlmap",
            command_template="sqlmap -u {target} {extra_args}",
            tech_specific_args={
                "mysql": "--dbms=mysql",
                "postgresql": "--dbms=postgresql", 
                "mssql": "--dbms=mssql",
                "oracle": "--dbms=oracle",
            },
            default_args="--batch --level=2 --risk=2",
        ),
    }
    
    def __init__(
        self,
        ethics_guard = None,
        proxy_manager = None,
        guard_context: Optional[Dict[str, Any]] = None,  # Phase 2: SGK-2026-0335
        mode: str = "bugbounty",
    ):
        """
        Args:
            ethics_guard: EthicsGuard instance for action validation
            proxy_manager: ProxyRotationManager for rotating IPs
            guard_context: Optional compiled-guard context dict with
                ``policy`` (LoadedGuardPolicy), ``stage`` (EnforcementStage).
            mode: 動作モード (bugbounty/ctf/vulntest)。shared guard は bugbounty のみ適用
        """
        self.ethics_guard = ethics_guard
        self.proxy_manager = proxy_manager
        self.guard_context = guard_context
        self._mode = mode
        self.execution_history: list[ExecutionResult] = []
    
    def run_tool(
        self,
        tool_name: str,
        target: str,
        context: dict,
        extra_args: Optional[str] = None,
        dry_run: bool = False,
    ) -> ExecutionResult:
        """
        コンテキストに基づいて最適化されたツールを実行
        
        Args:
            tool_name: ツール名（ffuf, nuclei, sqlmap等）
            target: ターゲットURL
            context: {
                "tech_stack": {"framework": "laravel", "server": "nginx", "db": "mysql"},
                "waf": "cloudflare",
                ...
            }
            extra_args: 追加の引数
            dry_run: Trueの場合、コマンドを実行せずに返す
        
        Returns:
            ExecutionResult
        """
        # 0. Compiled guard enforcement (Phase 2: SGK-2026-0335)
        # Always evaluate for bugbounty — shadow mode logs, fail-closed on missing policy.
        # evaluate_at_layer() handles both: policy=None → block, shadow → allow+log.
        if self._mode.lower() == "bugbounty":
            from src.core.security.compiled_guard_models import GuardInput
            from src.core.security.guard_enforcement import (
                EnforcementStage,
                evaluate_at_layer,
                extract_host_from_target,
            )

            gc = self._resolve_guard_context()
            policy = gc.get("policy") if gc else None
            stage = (gc.get("stage") if gc else None) or EnforcementStage.MC_ONLY

            gi = GuardInput(
                bundle_id=getattr(policy, "bundle_id", "") if policy else "",
                policy_id=getattr(policy, "policy_id", "") if policy else "",
                target=target,
                host=extract_host_from_target(target),
                requested_action="external_tool_exec",
                proposed_tool=tool_name,
                enforcement_layer="external",
            )
            decision = evaluate_at_layer(policy=policy, guard_input=gi, layer="external", stage=stage)
            if decision.decision == "block":
                return ExecutionResult(
                    success=False,
                    output="",
                    error=f"Blocked by compiled guard: {decision.reason_code}",
                    command_used="",
                )

        # 1. EthicsGuard でチェック
        if self.ethics_guard:
            from src.core.security.ethics_guard import ActionType, ActionResult
            from src.core.conductor.interactive_bridge import InteractiveBridge
            
            result, reason = self.ethics_guard.check_action(
                ActionType.SHELL_COMMAND,
                f"{tool_name} on {target}",
                {"tool": tool_name, "target": target}
            )
            
            if result == ActionResult.REQUIRES_APPROVAL:
                approved = InteractiveBridge.ask_for_approval(
                    action_description=f"Run tool '{tool_name}' on target '{target}'. Reason: {reason}"
                )
                if not approved:
                    return ExecutionResult(
                        success=False,
                        output="",
                        error="Blocked by user (EthicsGuard REQUIRES_APPROVAL)",
                        command_used="",
                    )
            elif result != ActionResult.ALLOWED:
                return ExecutionResult(
                    success=False,
                    output="",
                    error=f"Blocked by EthicsGuard: {reason}",
                    command_used="",
                )
        
        # 2. ツール設定を取得
        config = self.TOOL_CONFIGS.get(tool_name)
        if not config:
            return ExecutionResult(
                success=False,
                output="",
                error=f"Unknown tool: {tool_name}",
            )
        
        # 3. コンテキストから最適な引数を生成
        optimized_args = self._generate_optimized_args(config, context)
        
        # 4. Wordlistを選択
        wordlist = self._select_wordlist(context)
        
        # 5. コマンドを構築
        command = config.command_template.format(
            target=target,
            wordlist=wordlist,
            templates=self._get_nuclei_templates(context),
            extra_args=f"{config.default_args} {optimized_args} {extra_args or ''}".strip(),
        )
        
        # 6. プロキシ設定を追加
        if self.proxy_manager:
            proxy = self.proxy_manager.get_current_proxy()
            if proxy:
                command = f"HTTPS_PROXY={proxy} HTTP_PROXY={proxy} {command}"
        
        # 7. 実行
        context_applied = {
            "tech_detected": context.get("tech_stack", {}),
            "wordlist_used": wordlist,
            "args_optimized": optimized_args,
        }
        
        if dry_run:
            return ExecutionResult(
                success=True,
                output="[DRY RUN]",
                command_used=command,
                context_applied=context_applied,
            )
        
        try:
            result = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=300,  # 5分タイムアウト
            )
            
            execution_result = ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr,
                command_used=command,
                context_applied=context_applied,
            )
            
        except subprocess.TimeoutExpired:
            execution_result = ExecutionResult(
                success=False,
                output="",
                error="Command timed out after 5 minutes",
                command_used=command,
                context_applied=context_applied,
            )
        except Exception as e:
            execution_result = ExecutionResult(
                success=False,
                output="",
                error=str(e),
                command_used=command,
                context_applied=context_applied,
            )
        
        self.execution_history.append(execution_result)
        return execution_result

    def _resolve_guard_context(self):
        """Resolve guard context at call time (Phase 2: SGK-2026-0335).

        Priority: per-instance > shared module-level (bugbounty mode only).
        """
        if self.guard_context:
            return self.guard_context
        if self._mode.lower() != "bugbounty":
            return None
        from src.core.security.guard_enforcement import get_shared_guard_context
        return get_shared_guard_context()

    def _generate_optimized_args(self, config: ToolConfig, context: dict) -> str:
        """コンテキストから最適化された引数を生成"""
        args_parts = []
        tech_stack = context.get("tech_stack", {})
        
        # フレームワーク特化の引数
        framework = tech_stack.get("framework", "").lower()
        if framework in config.tech_specific_args:
            args_parts.append(config.tech_specific_args[framework])
        
        # DB特化の引数
        db = tech_stack.get("db", "").lower()
        if db in config.tech_specific_args:
            args_parts.append(config.tech_specific_args[db])
        
        # WAF回避モード
        waf = context.get("waf", "").lower()
        if waf:
            if "cloudflare" in waf:
                args_parts.append("-rate 10")  # レート制限
            elif "akamai" in waf:
                args_parts.append("-rate 5")
        
        return " ".join(args_parts)
    
    def _select_wordlist(self, context: dict) -> str:
        """コンテキストから最適なWordlistを選択"""
        tech_stack = context.get("tech_stack", {})
        framework = tech_stack.get("framework", "").lower()
        
        if framework in self.TECH_WORDLISTS:
            return self.TECH_WORDLISTS[framework]
        
        return self.TECH_WORDLISTS["default"]
    
    def _get_nuclei_templates(self, context: dict) -> str:
        """Nuclei用のテンプレートパスを取得"""
        tech_stack = context.get("tech_stack", {})
        framework = tech_stack.get("framework", "").lower()
        
        if framework:
            return f"~/nuclei-templates/technologies/{framework}"
        
        return "~/nuclei-templates/vulnerabilities/"
