import logging
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.core.agents.swarm.base import SwarmManager, Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.models.fuzzing import FuzzResult
from src.core.adapters.external.base_external_adapter import ToolInput
from src.core.adapters.external.ffuf_adapter import FfufAdapter
from src.core.adapters.external.external_tool_executor import get_global_executor
from src.core.adapters.external.tool_providers import ExternalToolProvider
from src.core.attack.native_fuzzer import NativeFuzzer
from src.core.infra.network_client import AsyncNetworkClient
from src.core.infra.observability import get_observability

logger = logging.getLogger(__name__)

_ARJUN_FAILURE_REASONS = {"timeout", "validation_error", "tool_error", "provider_error"}
_FALLBACK_TRIGGER_REASONS = {"arjun_failure", "arjun_empty_success", "arjun_unavailable"}


@dataclass
class _ParamFuzzMetricsContext:
    request_id: str
    arjun_total_recorded: bool = False
    fallback_recorded: bool = False
    fallback_reason: Optional[str] = None
    failure_reason: Optional[str] = None
    empty_success: bool = False


class DirBruteSpecialist(Specialist):
    """ディレクトリ探索スペシャリスト (Default OFF)"""
    
    name = "DirBruteSpecialist"
    description = "Directory Brute-forcing using ffuf or native fuzzer"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, mode: str = "bugbounty"):
        super().__init__(config)
        self._executor = get_global_executor()
        self._ffuf_adapter = FfufAdapter(mode=mode)
        
        # Native Client Initialization
        proxy_manager = None
        try:
            from src.core.infra.proxy_manager import get_proxy_manager
            proxy_manager = get_proxy_manager()
        except ImportError:
            pass
        self.client = AsyncNetworkClient(proxy_manager=proxy_manager, mode=mode)
        self.native_fuzzer = NativeFuzzer(self.client)
        
        # Knowledge Graph Initialization
        self.kg = None
        try:
            from src.core.infra.knowledge_graph import KnowledgeGraph
            self.kg = KnowledgeGraph()
        except (ImportError, RuntimeError, OSError) as e:
            logger.warning("Failed to initialize KnowledgeGraph in FuzzingSwarm: %s", e)
        
        # 辞書のパス
        self.wordlist_path = os.path.join(os.getcwd(), "assets", "wordlists", "common.txt")

    def _should_run(self, task: Task) -> bool:
        """実行ポリシー判定"""
        # 1. force_fuzz タグがあるか
        tags = getattr(task, "tags", []) or task.params.get("tags", [])
        if "force_fuzz" in tags:
            return True
            
        # 2. Configで auto_fuzz が有効か
        auto_fuzz = False
        if isinstance(self.config, dict):
            auto_fuzz = self.config.get("auto_fuzz", False)
        else:
            auto_fuzz = getattr(self.config, "auto_fuzz", False)
            
        if auto_fuzz:
            return True
        
        return False

    async def execute(self, task: Task) -> List[Finding]:
        findings = []
        
        # 安全なターゲット取得
        target_url = getattr(task, "target", "")
        if not target_url:
            target_url = task.params.get("target") or task.params.get("target_url")
            
        if not target_url:
            logger.error("[%s] No target URL specified in task.", self.name)
            return []
        
        # 実行可否判定
        if not self._should_run(task):
            msg = f"Skipping DirBrute for {target_url} (Default OFF Policy). Added to Pending Queue."
            logger.info(msg)
            
            # DBに保存
            if self.kg:
                try:
                    self.kg.save_pending_task(target_url, reason="Default OFF Policy", category="fuzzing")
                except (RuntimeError, OSError, ValueError) as e:
                    logger.error("Failed to save pending task to Neo4j: %s", e)
            # Skip is an execution note, not a security finding.
            return []

        logger.info("Starting DirBrute for %s", target_url)
        
        # URL末尾正規化
        if not target_url.endswith("/"):
            base_url = target_url + "/FUZZ"
        else:
            base_url = target_url + "FUZZ"
            
        # 辞書確認
        if not os.path.exists(self.wordlist_path):
            logger.warning("Wordlist not found at %s. Creating simple one.", self.wordlist_path)
            os.makedirs(os.path.dirname(self.wordlist_path), exist_ok=True)
            with open(self.wordlist_path, "w", encoding="utf-8") as f:
                f.write("admin\nlogin\napi\ndashboard\nconfig\n")

        results: List[FuzzResult] = []
        
        # エンジン実行 (adapter -> native fallback)
        try:
            results = await self._run_with_adapter(base_url)
        except (RuntimeError, OSError, ValueError) as e:
            logger.error("ffuf adapter path failed: %s. Falling back to native.", e)
            results = await self._run_native(base_url)
            
        # 結果変換
        for r in results:
            if r.status in [200, 204]:
                findings.append(Finding(
                    vuln_type=VulnType.OTHER,
                    severity=Severity.INFO,
                    title=f"Discovered Path: {r.url}",
                    description=f"Status: {r.status}, Size: {r.length}, Words: {r.words}",
                    target_url=r.url,
                    evidence=Evidence(
                        request_url=r.url,
                        response_status=r.status,
                        response_body=f"Length: {r.length}\nLines: {r.lines}"
                    ),
                    source_agent=self.name,
                    confidence=1.0,
                    tags=["discovered_path", "fuzz_result"]
                ))
            elif r.status in [401, 403]:
                findings.append(Finding(
                    vuln_type=VulnType.OTHER,
                    severity=Severity.LOW,
                    title=f"Protected Path Discovered: {r.url}",
                    description=f"Status: {r.status} (Access Denied)",
                    target_url=r.url,
                    source_agent=self.name,
                    tags=["discovered_path", "protected_resource"]
                ))

        return findings

    async def _run_native(self, base_url: str) -> List[FuzzResult]:
        return await self.native_fuzzer.run(
            base_url=base_url,
            wordlist_path=self.wordlist_path,
            match_codes=[200, 204, 301, 302, 307, 401, 403],
            concurrency=5,
            delay=0.1
        )

    async def _run_with_adapter(self, base_url: str) -> List[FuzzResult]:
        result = await self._executor.execute(
            self._ffuf_adapter,
            ToolInput(
                target=base_url,
                options={
                    "wordlist": self.wordlist_path,
                    "match_codes": "200,204,301,302,307,401,403",
                    "threads": 40,
                },
            ),
        )
        status_value = str(getattr(result.status, "value", result.status)).lower()
        if status_value != "success":
            raise RuntimeError(f"ffuf adapter execution failed with status={status_value}")

        findings = result.data or []
        parsed: List[FuzzResult] = []
        for item in findings:
            parsed.append(
                FuzzResult(
                    url=item.get("url", ""),
                    status=item.get("status", 0),
                    length=item.get("length", 0),
                    words=item.get("words", 0),
                    lines=item.get("lines", 0),
                    content_type=item.get("content_type", ""),
                    redirect_location=item.get("redirect_location", ""),
                )
            )
        return parsed

class ParamFuzzerSpecialist(DirBruteSpecialist):
    name = "ParamFuzzerSpecialist"
    description = "Hidden Parameter Discovery using Arjun or Native Fuzzer"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, mode: str = "bugbounty"):
        super().__init__(config, mode=mode)
        from src.core.attack.native_param_fuzzer import NativeParamFuzzer
        
        self._external_tools = ExternalToolProvider(mode=mode)
        self._observability = get_observability()
        # NativeFuzzer requires client (initialized in super)
        self.native = NativeParamFuzzer(self.client)
        self.param_wordlist_path = os.path.join(os.getcwd(), "assets", "wordlists", "params.txt")

    async def _inc_counter(self, name: str) -> None:
        await self._observability.metrics.inc_counter(name)

    async def _record_arjun_total_once(self, ctx: _ParamFuzzMetricsContext) -> None:
        if ctx.arjun_total_recorded:
            return
        await self._inc_counter("arjun_scan_total")
        ctx.arjun_total_recorded = True

    async def _record_arjun_failure(self, ctx: _ParamFuzzMetricsContext, reason: str) -> None:
        if reason not in _ARJUN_FAILURE_REASONS:
            reason = "provider_error"
        if ctx.failure_reason is None:
            ctx.failure_reason = reason
            await self._inc_counter(f"arjun_scan_failure_total.reason.{reason}")

    async def _record_empty_success(self, ctx: _ParamFuzzMetricsContext) -> None:
        if ctx.empty_success:
            return
        ctx.empty_success = True
        await self._inc_counter("arjun_scan_empty_success_total")

    async def _record_fallback_once(self, ctx: _ParamFuzzMetricsContext, reason: str) -> None:
        if reason not in _FALLBACK_TRIGGER_REASONS:
            reason = "arjun_failure"
        if ctx.fallback_recorded:
            return
        ctx.fallback_recorded = True
        ctx.fallback_reason = reason
        await self._inc_counter("native_fallback_total")
        await self._inc_counter(f"native_fallback_total.trigger_reason.{reason}")

    async def execute(self, task: Task) -> List[Finding]:
        findings = []
        request_id = str(getattr(task, "id", "") or task.params.get("request_id") or "unknown")
        metrics_ctx = _ParamFuzzMetricsContext(request_id=request_id)
        
        # ターゲット取得
        target_url = getattr(task, "target", "") or task.params.get("target") or task.params.get("target_url")
        if not target_url:
            return []
            
        # タグチェック (has_params または force_fuzz)
        tags = getattr(task, "tags", []) or task.params.get("tags", [])
        if "has_params" not in tags and "force_fuzz" not in tags:
            # Default OFF
            return []

        logger.info("[%s] Starting parameter discovery for %s", self.name, target_url)
        
        # Wordlist準備
        if not os.path.exists(self.param_wordlist_path):
            self._create_default_wordlist()
            
        discovered_params = []
        
        # 1. Arjun Execution via ExternalToolProvider
        has_arjun_scan = self._external_tools.has("arjun_scan")
        if has_arjun_scan:
            await self._record_arjun_total_once(metrics_ctx)
            try:
                results = await self._external_tools.execute(
                    "arjun_scan",
                    target=target_url,
                    options={
                        "method": task.params.get("method", "GET"),
                        "wordlist": self.param_wordlist_path,
                    },
                    timeout_seconds=task.params.get("timeout_seconds", 300),
                )
                status_value = str(getattr(results.status, "value", results.status)).lower()
                if status_value == "success":
                    for item in (results.data or []):
                        param = item.get("param")
                        if param:
                            discovered_params.append(param)
                    if not discovered_params:
                        await self._record_empty_success(metrics_ctx)
                        await self._record_fallback_once(metrics_ctx, "arjun_empty_success")
                else:
                    failure_reason = "tool_error"
                    error_message = (results.error_message or "").lower() if hasattr(results, "error_message") else ""
                    if "timeout" in error_message:
                        failure_reason = "timeout"
                    elif "invalid" in error_message or "validation" in error_message:
                        failure_reason = "validation_error"
                    await self._record_arjun_failure(metrics_ctx, failure_reason)
                    await self._record_fallback_once(metrics_ctx, "arjun_failure")
                    logger.info(
                        "[%s] arjun_scan status=%s, falling back to NativeFuzzer. error=%s",
                        self.name,
                        status_value,
                        results.error_message,
                    )
            except (RuntimeError, OSError, ValueError) as exc:
                await self._record_arjun_failure(metrics_ctx, "provider_error")
                await self._record_fallback_once(metrics_ctx, "arjun_failure")
                logger.warning(
                    "[%s] arjun_scan execution failed (%s). Falling back to NativeFuzzer.",
                    self.name,
                    exc,
                )
        else:
            await self._record_fallback_once(metrics_ctx, "arjun_unavailable")
        
        # 2. Native Fallback
        if not discovered_params:
            logger.info("[%s] No parameters from arjun_scan. Falling back to NativeFuzzer.", self.name)
            # Wordlist読み込み
            with open(self.param_wordlist_path, "r", encoding="utf-8") as f:
                wordlist = [line.strip() for line in f if line.strip()]
                
            results = await self.native.fuzz(
                url=target_url,
                method=task.params.get("method", "GET"),
                wordlist=wordlist
            )
            for r in results:
                discovered_params.append(r.parameter)
        
        # Findings生成
        if discovered_params:
            findings.append(Finding(
                vuln_type=VulnType.OTHER,
                severity=Severity.INFO, # パラメータ発見自体はInfo
                title=f"Hidden Parameters Discovered: {', '.join(discovered_params)}",
                description=f"Discovered {len(discovered_params)} hidden parameters via fuzzing.",
                evidence={"params": discovered_params},
                target_url=target_url,
                source_agent=self.name,
                tags=["has_params", "fuzzing_confirmed"]
            ))
            
        return findings

    def _create_default_wordlist(self):
        """簡易ワードリスト生成"""
        defaults = ["id", "user", "username", "password", "email", "debug", "test", "admin", "admin_id", "key", "token", "q", "search", "query", "file", "path"]
        os.makedirs(os.path.dirname(self.param_wordlist_path), exist_ok=True)
        with open(self.param_wordlist_path, "w", encoding="utf-8") as f:
            f.write("\n".join(defaults))

from src.core.engine.agent_registry import AgentRegistry

@AgentRegistry.register(
    names=["fuzzing", "FuzzingSwarm", "fuzzing_manager"],
    tags=["fuzzing", "dir_brute", "param_fuzz", "force_fuzz"]
)
class FuzzingSwarm(SwarmManager):
    """Fuzzing Swarm: 能動的な総当たり攻撃を担当"""
    
    name = "fuzzing"
    description = "Performs active fuzzing (Directory/File brute-forcing)"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, mode: str = "bugbounty"):
        super().__init__(config)
        self._all_specialists = [
            DirBruteSpecialist(config, mode=mode),
            ParamFuzzerSpecialist(config, mode=mode)
        ]
        
    def get_specialists(self, tags: List[str]) -> List[Specialist]:
        selected = [self._all_specialists[0]]  # DirBrute
        tag_set = {str(t).lower() for t in (tags or [])}
        if {"param_fuzz", "has_params", "force_fuzz"} & tag_set:
            selected.append(self._all_specialists[1])  # ParamFuzzer
        return selected
