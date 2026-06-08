"""
GraphQLNavigator: GraphQL Specialist

Introspects and queries GraphQL endpoints.
"""

import asyncio
import fcntl
import json
import logging
import os
import time
from uuid import uuid4
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from src.core.agents.swarm.base import Specialist, Task
from src.core.agents.swarm.runtime_control_backend import (
    InMemoryRuntimeControlBackend,
    RedisRuntimeControlBackend,
    RuntimeControlBackendUnavailable,
)
from src.core.attack.graphql_analyzer import GraphQLAnalyzer
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)


CONTRACT_VERSION = "1.0.0"


class GraphQLErrorCode:
    NONE = None
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    HTTP_ERROR = "http_error"
    INVALID_RESPONSE = "invalid_response"


class GraphQLEvidence:
    INTROSPECTION_SUCCESS = "introspection_success"
    INTROSPECTION_ERROR_SIGNATURE = "introspection_error_signature"
    GRAPHIQL_UI_MARKER = "graphiql_ui_marker"
    FIELD_SUGGESTION_HINT = "field_suggestion_hint"
    HTTP_STATUS_4XX = "http_status_4xx"
    HTTP_STATUS_5XX = "http_status_5xx"
    TIMEOUT_TRIGGERED = "timeout_triggered"
    CONNECTION_FAILED = "connection_failed"
    INVALID_JSON_PAYLOAD = "invalid_json_payload"
    WAF_HTML_RESPONSE = "waf_html_response"


ALLOWED_ERROR_CATEGORIES = {
    "",
    "capacity_control",
    "host_health",
    "timeout",
    "connectivity",
    "http_status",
    "payload_parse",
    "other",
}


GRAPHQL_PROBE_EVENT_SCHEMA_VERSION = "graphql_probe_event.v1"
GRAPHQL_PROBE_EVENT_REQUIRED_KEYS = {
    "schema_version",
    "event",
    "url",
    "latency_ms",
    "error_code",
    "internal_error_detail",
    "internal_error_category",
    "error_policy_version",
    "introspection_enabled",
    "graphiql_enabled",
    "field_suggestions_enabled",
    "vulnerable",
    "evidence",
    "half_open_trial",
}
GRAPHQL_RUNTIME_CONTROL_POLICY_EVENT = "graphql_runtime_control_policy.v1"
GRAPHQL_RUNTIME_CONTROL_POLICY_REQUIRED_KEYS = {
    "event",
    "request_id",
    "control_decision_id",
    "configured_policy",
    "effective_policy",
    "backend_error_type",
    "stage",
    "timestamp",
}
GRAPHQL_RUNTIME_CONTROL_SHADOW_DIFF_EVENT = "graphql_runtime_control_shadow_diff.v1"
GRAPHQL_RUNTIME_CONTROL_SHADOW_DIFF_REQUIRED_KEYS = {
    "event",
    "request_id",
    "control_decision_id",
    "target_host",
    "old_decision",
    "new_decision",
    "diff_class",
    "timestamp",
}
SHADOW_DIFF_CLASSES = {
    "same",
    "new_reject",
    "missed_reject",
    "reason_mismatch",
    "latency_regression",
    "other",
}

OTHER_CATEGORY_WARNING_RATE = 0.01
OTHER_CATEGORY_CRITICAL_RATE = 0.03
OTHER_CATEGORY_MIN_COUNT = 20
OTHER_CATEGORY_WINDOW_SECONDS = 900.0


@dataclass
class GraphQLRuntimeConfig:
    timeout_seconds: float = 3.0
    total_timeout_seconds: float = 8.0
    parallel_limit: int = 5
    queue_limit: int = 100
    qps_limit: int = 20
    circuit_breaker_threshold: int = 3
    quarantine_seconds: float = 30.0
    alert_cooldown_seconds: float = 300.0
    other_category_log_dir: Optional[str] = None
    runtime_control_backend: str = "inmemory"
    runtime_control_redis_url: Optional[str] = None
    runtime_control_redis_namespace: str = "shigoku:runtime-control:graphql"
    runtime_control_redis_mode: str = "standalone"
    runtime_control_redis_sentinel_nodes: Optional[List[str]] = None
    runtime_control_redis_sentinel_service_name: Optional[str] = None
    runtime_control_redis_cluster_nodes: Optional[List[str]] = None
    backend_unavailable_policy: str = "fail_open"
    fail_open_ttl_seconds: int = 1800
    backend_error_rate_warn_threshold: float = 0.5
    reject_rate_warn_threshold: float = 8.0
    admit_p95_latency_warn_ms: int = 120
    backend_rtt_p95_warn_ms: int = 40
    backend_rtt_p99_warn_ms: int = 80
    mttrecovery_warn_seconds: int = 900
    shadow_mode_enabled: bool = False


class GraphQLNavigator(Specialist):
    """
    GraphQL分析スペシャリスト
    
    機能:
    1. Introspection Query の実行
    2. Schema Dump の取得
    3. `__schema` や `__type` へのアクセス可否確認
    """
    
    name = "GraphQLNavigator"
    description = "Introspects and queries GraphQL endpoints to discover schema."
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._runtime = self._build_runtime_config()
        self._runtime_lock = asyncio.Lock()
        self._control_backend = self._build_runtime_control_backend()
        self._fail_open_started_at = time.time()
        self._runtime_control_policy_counts: Dict[str, int] = {"fail_open": 0, "fail_safe": 0}
        # Backward-compatible handles used by tests and diagnostics.
        if isinstance(self._control_backend, InMemoryRuntimeControlBackend):
            self._qps_timestamps = self._control_backend.qps_timestamps
            self._host_failures = self._control_backend.host_failures
            self._host_quarantine_until = self._control_backend.host_quarantine_until
            self._host_half_open_inflight = self._control_backend.host_half_open_inflight
        else:
            self._qps_timestamps = []
            self._host_failures = {}
            self._host_quarantine_until = {}
            self._host_half_open_inflight = {}
        self._error_category_window: List[Tuple[float, str]] = []
        self._last_alert_level: Optional[str] = None
        self._last_alert_at: float = 0.0

    def _build_runtime_config(self) -> GraphQLRuntimeConfig:
        cfg = self.config if isinstance(self.config, dict) else {}
        project_id = cfg.get("project_id")
        env_log_dir = os.getenv("SHIGOKU_OTHER_CATEGORY_LOG_DIR")
        _repo_root = Path(__file__).resolve().parents[5]
        default_log_dir = (
            str(_repo_root / "workspace" / "projects" / project_id)
            if project_id
            else None
        )
        def _required_float(key: str, default: float) -> float:
            if key in cfg and cfg.get(key) in (None, ""):
                raise ValueError(f"{key}_missing")
            return float(cfg.get(key, default))

        def _required_int(key: str, default: int) -> int:
            if key in cfg and cfg.get(key) in (None, ""):
                raise ValueError(f"{key}_missing")
            return int(cfg.get(key, default))

        return GraphQLRuntimeConfig(
            timeout_seconds=float(cfg.get("graphql_probe_timeout_seconds", 3.0)),
            total_timeout_seconds=float(cfg.get("graphql_probe_total_timeout_seconds", 8.0)),
            parallel_limit=max(1, int(cfg.get("graphql_probe_parallel_limit", 5))),
            queue_limit=max(0, int(cfg.get("graphql_probe_queue_limit", 100))),
            qps_limit=max(1, int(cfg.get("graphql_probe_qps_limit", 20))),
            circuit_breaker_threshold=max(1, int(cfg.get("graphql_probe_circuit_breaker_threshold", 3))),
            quarantine_seconds=float(cfg.get("graphql_probe_quarantine_seconds", 30.0)),
            alert_cooldown_seconds=float(cfg.get("graphql_probe_alert_cooldown_seconds", 300.0)),
            # Priority: explicit config > env override > project-derived default.
            other_category_log_dir=cfg.get(
                "graphql_probe_other_log_dir",
                env_log_dir if env_log_dir else default_log_dir,
            ),
            runtime_control_backend=str(cfg.get("graphql_probe_runtime_control_backend", "inmemory")),
            runtime_control_redis_url=cfg.get("graphql_probe_runtime_control_redis_url"),
            runtime_control_redis_namespace=str(
                cfg.get("graphql_probe_runtime_control_redis_namespace", "shigoku:runtime-control:graphql")
            ),
            runtime_control_redis_mode=str(cfg.get("graphql_probe_runtime_control_redis_mode", "standalone")),
            runtime_control_redis_sentinel_nodes=cfg.get("graphql_probe_runtime_control_redis_sentinel_nodes"),
            runtime_control_redis_sentinel_service_name=cfg.get("graphql_probe_runtime_control_redis_sentinel_service_name"),
            runtime_control_redis_cluster_nodes=cfg.get("graphql_probe_runtime_control_redis_cluster_nodes"),
            backend_unavailable_policy=str(cfg.get("graphql_probe_backend_unavailable_policy", "fail_open")),
            fail_open_ttl_seconds=max(1, int(cfg.get("graphql_probe_fail_open_ttl_seconds", 1800))),
            backend_error_rate_warn_threshold=_required_float(
                "graphql_probe_runtime_control_backend_error_rate_warn_threshold", 0.5
            ),
            reject_rate_warn_threshold=_required_float(
                "graphql_probe_runtime_control_reject_rate_warn_threshold", 8.0
            ),
            admit_p95_latency_warn_ms=max(
                1, _required_int("graphql_probe_runtime_control_admit_p95_latency_warn_ms", 120)
            ),
            backend_rtt_p95_warn_ms=max(
                1, _required_int("graphql_probe_runtime_control_backend_rtt_p95_warn_ms", 40)
            ),
            backend_rtt_p99_warn_ms=max(
                1, _required_int("graphql_probe_runtime_control_backend_rtt_p99_warn_ms", 80)
            ),
            mttrecovery_warn_seconds=max(
                1, _required_int("graphql_probe_runtime_control_mttrecovery_warn_seconds", 900)
            ),
            shadow_mode_enabled=bool(cfg.get("graphql_probe_shadow_mode_enabled", False)),
        )

    def _build_runtime_control_backend(self):
        backend_name = (self._runtime.runtime_control_backend or "inmemory").lower()
        if backend_name == "redis" and self._runtime.runtime_control_redis_url:
            return RedisRuntimeControlBackend(
                self._runtime.runtime_control_redis_url,
                namespace=self._runtime.runtime_control_redis_namespace,
                mode=self._runtime.runtime_control_redis_mode,
                sentinel_nodes=self._runtime.runtime_control_redis_sentinel_nodes or [],
                sentinel_service_name=self._runtime.runtime_control_redis_sentinel_service_name,
                cluster_nodes=self._runtime.runtime_control_redis_cluster_nodes or [],
            )
        if backend_name == "redis" and self._runtime.runtime_control_redis_mode in {"sentinel", "cluster"}:
            return RedisRuntimeControlBackend(
                None,
                namespace=self._runtime.runtime_control_redis_namespace,
                mode=self._runtime.runtime_control_redis_mode,
                sentinel_nodes=self._runtime.runtime_control_redis_sentinel_nodes or [],
                sentinel_service_name=self._runtime.runtime_control_redis_sentinel_service_name,
                cluster_nodes=self._runtime.runtime_control_redis_cluster_nodes or [],
            )
        return InMemoryRuntimeControlBackend()

    @property
    def _inflight(self) -> int:
        if isinstance(self._control_backend, InMemoryRuntimeControlBackend):
            return int(self._control_backend.inflight)
        return 0

    @_inflight.setter
    def _inflight(self, value: int) -> None:
        if isinstance(self._control_backend, InMemoryRuntimeControlBackend):
            self._control_backend.inflight = max(0, int(value))

    async def execute(self, task: Task) -> List[Finding]:
        """Entry point"""
        result = await self.run_as_tool(task.target)
        
        findings = []
        if result.get("introspection_enabled"):
            findings.append(Finding(
                vuln_type=VulnType.OTHER, # TODO: InfoDisclosure
                severity=Severity.MEDIUM,
                title="GraphQL Introspection Enabled",
                description="Introspection query succeeded, exposing schema.",
                target_url=task.target,
                source_agent=self.name,
                evidence=Evidence(
                    request_url=task.target,
                    response_body=str(result.get("schema_snippet", "")[:200])
                )
            ))
        return findings

    async def _admit(self) -> bool:
        return await self._control_backend.admit(self._runtime.parallel_limit, self._runtime.queue_limit)

    async def _release(self) -> None:
        await self._control_backend.release()

    async def _acquire_qps_slot(self) -> None:
        await self._control_backend.acquire_qps_slot(self._runtime.qps_limit)

    async def _host_admission(self, url: str) -> Dict[str, Any]:
        host = (urlparse(url).netloc or url).lower()
        return await self._control_backend.host_admission(host)

    async def _record_outcome(self, url: str, success: bool, half_open_trial: bool = False) -> None:
        host = (urlparse(url).netloc or url).lower()
        await self._control_backend.record_outcome(
            host=host,
            success=success,
            half_open_trial=half_open_trial,
            circuit_breaker_threshold=self._runtime.circuit_breaker_threshold,
            quarantine_seconds=self._runtime.quarantine_seconds,
        )

    def _effective_backend_unavailable_policy(self) -> str:
        policy = (self._runtime.backend_unavailable_policy or "fail_open").lower()
        if policy != "fail_open":
            return policy
        if (time.time() - self._fail_open_started_at) > float(self._runtime.fail_open_ttl_seconds):
            return "fail_safe"
        return "fail_open"

    @staticmethod
    def _extract_backend_error_type(exc: Exception) -> str:
        msg = str(exc).lower()
        if "name or service not known" in msg or "dns" in msg:
            return "connect_unavailable"
        if "timeout" in msg:
            return "timeout"
        if "failover" in msg:
            return "failover"
        if "transaction" in msg or "lua" in msg:
            return "atomic_operation_failed"
        return "backend_unavailable"

    def _backend_unavailable_result(
        self,
        stage: str = "unknown",
        *,
        request_id: str,
        control_decision_id: str,
        backend_error_type: str = "backend_unavailable",
    ) -> Dict[str, Any]:
        configured_policy = (self._runtime.backend_unavailable_policy or "fail_open").lower()
        policy = self._effective_backend_unavailable_policy()
        ttl_remaining = max(0, int(self._runtime.fail_open_ttl_seconds - (time.time() - self._fail_open_started_at)))
        self._runtime_control_policy_counts[policy] = self._runtime_control_policy_counts.get(policy, 0) + 1
        self._emit_structured_event(
            GRAPHQL_RUNTIME_CONTROL_POLICY_EVENT,
            {
                "request_id": request_id,
                "control_decision_id": control_decision_id,
                "stage": stage,
                "configured_policy": configured_policy,
                "effective_policy": policy,
                "backend_error_type": backend_error_type,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "ttl_remaining_seconds": ttl_remaining,
                "fail_open_count": self._runtime_control_policy_counts.get("fail_open", 0),
                "fail_safe_count": self._runtime_control_policy_counts.get("fail_safe", 0),
            },
        )
        if policy == "fail_safe":
            return self._make_contract(
                error_code=GraphQLErrorCode.CONNECTION_ERROR,
                internal_error_detail="not_tested_runtime_control_fail_safe",
                internal_error_category="capacity_control",
                evidence=[GraphQLEvidence.CONNECTION_FAILED],
                logs=["Rejected by runtime control backend fail-safe policy"],
                backend_error_type=backend_error_type,
                effective_policy=policy,
            )
        return self._make_contract(
            error_code=GraphQLErrorCode.NONE,
            internal_error_detail="runtime_control_backend_unavailable_fail_open",
            internal_error_category="other",
            evidence=[],
            logs=["Runtime control backend unavailable, fail-open policy applied"],
            backend_error_type=backend_error_type,
            effective_policy=policy,
        )

    def _make_contract(self, **kwargs: Any) -> Dict[str, Any]:
        base = {
            "contract_version": CONTRACT_VERSION,
            "introspection_enabled": False,
            "graphiql_enabled": False,
            "field_suggestions_enabled": False,
            "error_code": GraphQLErrorCode.NONE,
            "internal_error_detail": "",
            "internal_error_category": "",
            "error_policy_version": "1",
            "evidence": [],
            "latency_ms": None,
            "schema_snippet": "",
            "logs": [],
        }
        base.update(kwargs)
        base["internal_error_category"] = self._normalize_error_category(str(base.get("internal_error_category", "") or ""))
        # evidence dedupe + max 10
        ev = []
        for item in base.get("evidence", []):
            if item not in ev:
                ev.append(item)
            if len(ev) >= 10:
                break
        base["evidence"] = ev
        return base

    def _normalize_error_category(self, category: str) -> str:
        if category in ALLOWED_ERROR_CATEGORIES:
            return category
        return "other"

    @staticmethod
    def evaluate_other_category_alert(other_count: int, total_count: int) -> Optional[str]:
        """
        Return alert severity based on 'other' category ratio.
        - critical: rate > 3% and other_count >= 20
        - warning : rate > 1% and other_count >= 20
        - none    : otherwise
        """
        if total_count <= 0:
            return None
        if other_count < OTHER_CATEGORY_MIN_COUNT:
            return None
        rate = other_count / float(total_count)
        if rate > OTHER_CATEGORY_CRITICAL_RATE:
            return "critical"
        if rate > OTHER_CATEGORY_WARNING_RATE:
            return "warning"
        return None

    def _emit_structured_event(self, event: str, payload: Dict[str, Any]) -> None:
        full = {"event": event, **payload}
        if event == GRAPHQL_RUNTIME_CONTROL_POLICY_EVENT:
            required = GRAPHQL_RUNTIME_CONTROL_POLICY_REQUIRED_KEYS
        elif event == GRAPHQL_RUNTIME_CONTROL_SHADOW_DIFF_EVENT:
            required = GRAPHQL_RUNTIME_CONTROL_SHADOW_DIFF_REQUIRED_KEYS
        else:
            required = GRAPHQL_PROBE_EVENT_REQUIRED_KEYS
        missing = required - full.keys()
        if missing:
            logger.warning("[graphql_probe_event] missing required keys: %s", sorted(missing))
        logger.info("[graphql_probe_event] %s", json.dumps(full, ensure_ascii=True, sort_keys=True))

    @staticmethod
    def _classify_shadow_diff(old_decision: Dict[str, Any], new_decision: Dict[str, Any]) -> str:
        old_allowed = bool(old_decision.get("allowed", False))
        new_allowed = bool(new_decision.get("allowed", False))
        old_reason = str(old_decision.get("reason", "") or "")
        new_reason = str(new_decision.get("reason", "") or "")
        old_latency = old_decision.get("latency_ms")
        new_latency = new_decision.get("latency_ms")
        if old_allowed == new_allowed and old_reason == new_reason:
            if isinstance(old_latency, int) and isinstance(new_latency, int) and new_latency > old_latency:
                if new_latency > 120:
                    return "latency_regression"
            return "same"
        if old_allowed and not new_allowed:
            return "new_reject"
        if not old_allowed and new_allowed:
            return "missed_reject"
        if old_allowed == new_allowed and old_reason != new_reason:
            return "reason_mismatch"
        return "other"

    def _emit_shadow_diff_event(
        self,
        *,
        request_id: str,
        control_decision_id: str,
        target_host: str,
        old_decision: Dict[str, Any],
        new_decision: Dict[str, Any],
    ) -> None:
        diff_class = self._classify_shadow_diff(old_decision, new_decision)
        if diff_class not in SHADOW_DIFF_CLASSES:
            diff_class = "other"
        self._emit_structured_event(
            GRAPHQL_RUNTIME_CONTROL_SHADOW_DIFF_EVENT,
            {
                "request_id": request_id,
                "control_decision_id": control_decision_id,
                "target_host": target_host,
                "old_decision": old_decision,
                "new_decision": new_decision,
                "diff_class": diff_class,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            },
        )

    def _persist_other_category(self, entry: Dict[str, Any]) -> None:
        """other カテゴリのエントリを JSONL ファイルに fcntl.flock で排他追記する。"""
        log_dir = self._runtime.other_category_log_dir
        if not log_dir:
            return
        try:
            log_path = Path(log_dir) / "other_category_log.jsonl"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    fh.write(json.dumps(entry, ensure_ascii=True) + "\n")
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)
        except OSError as exc:
            logger.warning("[graphql_probe] other_category_log write failed: %s", exc)

    async def _record_category_and_maybe_alert(self, category: str) -> Optional[str]:
        now = time.monotonic()
        async with self._runtime_lock:
            self._error_category_window = [
                (ts, cat) for ts, cat in self._error_category_window
                if (now - ts) <= OTHER_CATEGORY_WINDOW_SECONDS
            ]
            self._error_category_window.append((now, category))
            total_count = len(self._error_category_window)
            other_count = sum(1 for _, cat in self._error_category_window if cat == "other")
            alert = self.evaluate_other_category_alert(other_count, total_count)
            if alert is None:
                self._last_alert_level = None
                self._last_alert_at = 0.0
                return None
            cooldown_elapsed = (now - self._last_alert_at) >= self._runtime.alert_cooldown_seconds
            level_escalated = alert != self._last_alert_level
            if level_escalated or cooldown_elapsed:
                self._last_alert_level = alert
                self._last_alert_at = now
                return alert
            return None

    async def _record_other_and_persist(self, url: str, raw_category: str) -> Optional[str]:
        """other カテゴリをウィンドウ記録 + JSONL 永続化し、必要に応じてアラートを返す。"""
        alert = await self._record_category_and_maybe_alert(raw_category)
        if raw_category == "other":
            entry = {
                "ts": datetime.now(tz=timezone.utc).isoformat(),
                "url": url,
                "category": raw_category,
                "alert": alert,
            }
            await asyncio.get_running_loop().run_in_executor(None, self._persist_other_category, entry)
        return alert

    async def _probe(self, url: str) -> Dict[str, Any]:
        analyzer = GraphQLAnalyzer(config={"timeout": self._runtime.timeout_seconds})
        try:
            result = await analyzer.analyze_async(url)
        finally:
            analyzer.close()

        evidence = []
        if result.introspection_enabled:
            evidence.append(GraphQLEvidence.INTROSPECTION_SUCCESS)
        if result.graphiql_enabled:
            evidence.append(GraphQLEvidence.GRAPHIQL_UI_MARKER)
        if result.field_suggestions_enabled:
            evidence.append(GraphQLEvidence.FIELD_SUGGESTION_HINT)

        schema_snippet = ""
        if result.schema:
            try:
                schema_snippet = json.dumps(
                    {
                        "query_type": result.schema.query_type,
                        "mutation_type": result.schema.mutation_type,
                        "types_count": len(result.schema.types),
                    }
                )[:500]
            except Exception:
                schema_snippet = ""

        return self._make_contract(
            introspection_enabled=result.introspection_enabled,
            graphiql_enabled=result.graphiql_enabled,
            field_suggestions_enabled=result.field_suggestions_enabled,
            evidence=evidence,
            schema_snippet=schema_snippet,
            logs=["GraphQL probe completed"],
        )

    async def run_as_tool(self, url: str) -> Dict[str, Any]:
        """
        Managerから呼び出し可能なToolメソッド
        """
        logger.info("[%s] Probing GraphQL endpoint: %s", self.name, url)
        started = time.monotonic()
        request_id = uuid4().hex
        control_decision_id = uuid4().hex
        target_host = (urlparse(url).netloc or url).lower()

        try:
            admitted = await self._admit()
        except RuntimeControlBackendUnavailable as exc:
            logger.warning("[%s] runtime control backend unavailable during admit: %s", self.name, exc)
            result = self._backend_unavailable_result(
                stage="admit",
                request_id=request_id,
                control_decision_id=control_decision_id,
                backend_error_type=self._extract_backend_error_type(exc),
            )
            if result.get("error_code") is not None:
                self._emit_structured_event("graphql_probe_failure", {"url": url, "error_code": result["error_code"], "internal_error_detail": result["internal_error_detail"]})
                return result
            admitted = True
        if not admitted:
            result = self._make_contract(
                error_code=GraphQLErrorCode.CONNECTION_ERROR,
                internal_error_detail="backpressure_rejected",
                internal_error_category="capacity_control",
                evidence=[GraphQLEvidence.CONNECTION_FAILED],
                logs=["Rejected by backpressure"],
            )
            self._emit_structured_event("graphql_probe_failure", {"url": url, "error_code": result["error_code"], "internal_error_detail": result["internal_error_detail"]})
            return result

        try:
            half_open_trial = False
            try:
                admission = await self._host_admission(url)
                half_open_trial = bool(admission.get("half_open_trial", False))
                if not admission.get("allowed", False):
                    result = self._make_contract(
                        error_code=GraphQLErrorCode.CONNECTION_ERROR,
                        internal_error_detail=str(admission.get("detail", "host_quarantined")),
                        internal_error_category="host_health",
                        evidence=[GraphQLEvidence.CONNECTION_FAILED],
                        logs=["Rejected by host quarantine"],
                    )
                    self._emit_structured_event("graphql_probe_failure", {"url": url, "error_code": result["error_code"], "internal_error_detail": result["internal_error_detail"]})
                    return result
                await self._acquire_qps_slot()
            except RuntimeControlBackendUnavailable as exc:
                logger.warning("[%s] runtime control backend unavailable during admission/qps: %s", self.name, exc)
                fallback = self._backend_unavailable_result(
                    stage="admission_or_qps",
                    request_id=request_id,
                    control_decision_id=control_decision_id,
                    backend_error_type=self._extract_backend_error_type(exc),
                )
                if fallback.get("error_code") is not None:
                    self._emit_structured_event("graphql_probe_failure", {"url": url, "error_code": fallback["error_code"], "internal_error_detail": fallback["internal_error_detail"]})
                    return fallback
            try:
                result = await asyncio.wait_for(self._probe(url), timeout=self._runtime.total_timeout_seconds)
            except asyncio.TimeoutError:
                result = self._make_contract(
                    error_code=GraphQLErrorCode.TIMEOUT,
                    internal_error_detail="probe_timeout",
                    internal_error_category="timeout",
                    evidence=[GraphQLEvidence.TIMEOUT_TRIGGERED],
                    logs=["Probe timed out"],
                )
            except Exception as exc:  # pylint: disable=broad-except
                detail = str(exc).lower()
                if "connect" in detail or "name or service not known" in detail:
                    err = GraphQLErrorCode.CONNECTION_ERROR
                    evidence = [GraphQLEvidence.CONNECTION_FAILED]
                    category = "connectivity"
                elif "status" in detail or "http" in detail:
                    err = GraphQLErrorCode.HTTP_ERROR
                    evidence = [GraphQLEvidence.HTTP_STATUS_4XX]
                    category = "http_status"
                else:
                    err = GraphQLErrorCode.INVALID_RESPONSE
                    evidence = [GraphQLEvidence.INVALID_JSON_PAYLOAD]
                    category = "payload_parse"
                result = self._make_contract(
                    error_code=err,
                    internal_error_detail=detail[:200],
                    internal_error_category=category,
                    evidence=evidence,
                    logs=[f"Probe error: {exc}"],
                )

            latency_ms = int((time.monotonic() - started) * 1000)
            result["latency_ms"] = latency_ms
            vulnerable = bool(
                result.get("introspection_enabled")
                or result.get("graphiql_enabled")
                or result.get("field_suggestions_enabled")
            )
            event_name = "graphql_probe_success" if result.get("error_code") is None else "graphql_probe_failure"
            success = result.get("error_code") is None
            try:
                await self._record_outcome(url, success, half_open_trial=half_open_trial)
            except RuntimeControlBackendUnavailable as exc:
                logger.warning("[%s] runtime control backend unavailable during record_outcome: %s", self.name, exc)
            self._emit_structured_event(
                event_name,
                {
                    "schema_version": GRAPHQL_PROBE_EVENT_SCHEMA_VERSION,
                    # v1 compatibility policy:
                    # - required keys must never be removed
                    # - additive optional keys are allowed
                    "url": url,
                    "latency_ms": latency_ms,
                    "error_code": result.get("error_code"),
                    "internal_error_detail": result.get("internal_error_detail", ""),
                    "internal_error_category": result.get("internal_error_category", ""),
                    "error_policy_version": result.get("error_policy_version", "1"),
                    "introspection_enabled": result.get("introspection_enabled"),
                    "graphiql_enabled": result.get("graphiql_enabled"),
                    "field_suggestions_enabled": result.get("field_suggestions_enabled"),
                    "vulnerable": vulnerable,
                    "evidence": result.get("evidence", []),
                    "half_open_trial": half_open_trial,
                },
            )
            if self._runtime.shadow_mode_enabled:
                new_decision = {
                    "allowed": success,
                    "reason": str(result.get("internal_error_detail", "") or ""),
                    "latency_ms": latency_ms,
                }
                # Legacy decision source is not available here; compare against same-shape baseline.
                old_decision = dict(new_decision)
                self._emit_shadow_diff_event(
                    request_id=request_id,
                    control_decision_id=control_decision_id,
                    target_host=target_host,
                    old_decision=old_decision,
                    new_decision=new_decision,
                )
            alert_level = await self._record_other_and_persist(
                url,
                str(result.get("internal_error_category", "") or ""),
            )
            if alert_level:
                self._emit_structured_event(
                    "graphql_probe_alert",
                    {
                        "schema_version": GRAPHQL_PROBE_EVENT_SCHEMA_VERSION,
                        "url": url,
                        "alert_level": alert_level,
                        "reason": "internal_error_category_other_rate_threshold",
                        "window_seconds": int(OTHER_CATEGORY_WINDOW_SECONDS),
                    },
                )
            return result
        finally:
            try:
                await self._release()
            except RuntimeControlBackendUnavailable as exc:
                logger.warning("[%s] runtime control backend unavailable during release: %s", self.name, exc)
