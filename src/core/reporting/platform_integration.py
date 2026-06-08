"""
Bug Bounty Platform Integration for SHIGOKU Phase D
Elegant HackerOne/Bugcrowd API integration for automated reporting
"""
from __future__ import annotations
import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod
from datetime import datetime
from uuid import uuid4
import aiohttp

logger = logging.getLogger(__name__)

_DEFAULT_REPLAY_QUEUE_PATH = Path("workspace/runtime/report_adapter_replay_queue.jsonl")


def emit_report_adapter_degradation_audit(
    *,
    component_status: Dict[str, str],
    degradation_result: Dict[str, Any],
    audit_context: Dict[str, Any],
) -> Dict[str, Any]:
    from src.core.engine.master_conductor import MasterConductor
    from src.core.models.decision_trace import get_decision_tracer
    from src.core.utils.audit_logger import get_audit_logger

    conductor = MasterConductor.__new__(MasterConductor)
    conductor.audit_logger = get_audit_logger()
    conductor.decision_tracer = get_decision_tracer()
    return conductor.emit_degradation_audit_record(
        component_status=component_status,
        degradation_result=degradation_result,
        audit_context=audit_context,
    )


def enqueue_report_adapter_replay(
    *,
    platform: str,
    canonical_payload: Dict[str, Any],
    degradation_result: Dict[str, Any],
    audit_context: Dict[str, Any],
    replay_queue_path: Optional[Path] = None,
) -> Dict[str, Any]:
    validation = ReportDraft.validate_platform_submission_payload(
        platform=platform,
        payload=canonical_payload,
        source="canonical_report_payload",
    )
    if not validation.get("accepted", False):
        raise ValueError(
            "canonical_payload required for replay queue entry: "
            f"{validation.get('reason', 'invalid_payload')}"
        )

    queue_path = Path(replay_queue_path or _DEFAULT_REPLAY_QUEUE_PATH)
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    created_at = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    record = {
        "queue_id": f"replay-{uuid4().hex[:12]}",
        "created_at": created_at,
        "platform": str(platform).strip().lower(),
        "canonical_report_payload": dict(canonical_payload),
        "reason": str(degradation_result.get("reason", "report_adapter_degraded")).strip() or "report_adapter_degraded",
        "replay_status": "pending",
        "correlation_id": str(audit_context.get("correlation_id", "")).strip(),
        "policy_version": str(audit_context.get("policy_version", "")).strip(),
        "degradation_state": str(degradation_result.get("state", "")).strip(),
    }
    with queue_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return record


def load_report_adapter_replay_queue(
    replay_queue_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    queue_path = Path(replay_queue_path or _DEFAULT_REPLAY_QUEUE_PATH)
    if not queue_path.exists():
        return []
    records: List[Dict[str, Any]] = []
    for line in queue_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        records.append(dict(json.loads(line)))
    return records


def store_report_adapter_replay_queue(
    records: List[Dict[str, Any]],
    replay_queue_path: Optional[Path] = None,
) -> None:
    queue_path = Path(replay_queue_path or _DEFAULT_REPLAY_QUEUE_PATH)
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    with queue_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def retry_failed_report_adapter_replay(
    *,
    platform: str,
    replay_queue_path: Optional[Path] = None,
    limit: Optional[int] = None,
    queue_id: Optional[str] = None,
) -> Dict[str, Any]:
    records = load_report_adapter_replay_queue(replay_queue_path)
    reset = 0
    skipped = 0
    normalized_queue_id = str(queue_id or "").strip()
    for record in records:
        if str(record.get("platform", "")).strip().lower() != str(platform).strip().lower():
            skipped += 1
            continue
        if normalized_queue_id and str(record.get("queue_id", "")).strip() != normalized_queue_id:
            skipped += 1
            continue
        if str(record.get("replay_status", "")).strip().lower() != "failed":
            skipped += 1
            continue
        if limit is not None and reset >= int(limit):
            skipped += 1
            continue
        record["replay_status"] = "pending"
        record["retry_requested_at"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        record.pop("replay_error", None)
        record.pop("replay_url", None)
        record.pop("replayed_at", None)
        reset += 1

    store_report_adapter_replay_queue(records, replay_queue_path)
    return {
        "platform": str(platform).strip().lower(),
        "reset": reset,
        "skipped": skipped,
        "queue_id": normalized_queue_id,
        "queue_path": str(Path(replay_queue_path or _DEFAULT_REPLAY_QUEUE_PATH)),
    }


def list_report_adapter_replay_queue(
    *,
    replay_queue_path: Optional[Path] = None,
    platform: Optional[str] = None,
    queue_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    records = load_report_adapter_replay_queue(replay_queue_path)
    normalized_platform = str(platform or "").strip().lower()
    normalized_queue_id = str(queue_id or "").strip()
    normalized_status = str(status or "").strip().lower()
    filtered: List[Dict[str, Any]] = []
    for record in records:
        if normalized_platform and str(record.get("platform", "")).strip().lower() != normalized_platform:
            continue
        if normalized_queue_id and str(record.get("queue_id", "")).strip() != normalized_queue_id:
            continue
        if normalized_status and str(record.get("replay_status", "")).strip().lower() != normalized_status:
            continue
        filtered.append(record)
        if limit is not None and len(filtered) >= int(limit):
            break
    return {
        "count": len(filtered),
        "platform": normalized_platform,
        "queue_id": normalized_queue_id,
        "status": normalized_status,
        "queue_path": str(Path(replay_queue_path or _DEFAULT_REPLAY_QUEUE_PATH)),
        "records": filtered,
    }


@dataclass
class ReportDraft:
    """Bug bounty report draft"""
    title: str
    summary: str
    description: str
    severity: str  # "critical", "high", "medium", "low", "informational"
    evidence: Dict[str, Any]
    reproduction_steps: List[str]

    @classmethod
    def from_canonical_payload(cls, payload: Dict[str, Any]) -> "ReportDraft":
        title = str(payload.get("title", "")).strip()
        severity = str(payload.get("severity", "medium")).strip().lower() or "medium"
        reproduction_steps = [
            str(step).strip()
            for step in payload.get("reproduction_steps", [])
            if str(step).strip()
        ]
        business_impact = str(payload.get("business_impact_sentence", "")).strip()
        victim_impact = str(payload.get("victim_impact", "")).strip()
        summary_parts = [part for part in [business_impact, victim_impact] if part]
        summary = " ".join(summary_parts)
        description_sections = [
            business_impact,
            str(payload.get("boundary_cross_proof", "")).strip(),
            str(payload.get("falsification_result", "")).strip(),
        ]
        description = "\n\n".join(section for section in description_sections if section)
        evidence = {
            "boundary_cross_proof": str(payload.get("boundary_cross_proof", "")).strip(),
            "victim_impact": victim_impact,
            "goal_state_assertions": dict(payload.get("goal_state_assertions", {}) or {}),
            "minimal_success_runbook": list(payload.get("minimal_success_runbook", []) or []),
        }
        return cls(
            title=title,
            summary=summary,
            description=description,
            severity=severity,
            evidence=evidence,
            reproduction_steps=reproduction_steps,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "summary": self.summary,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "reproduction_steps": self.reproduction_steps,
        }

    @staticmethod
    def validate_platform_submission_payload(
        *,
        platform: str,
        payload: Dict[str, Any],
        source: str,
    ) -> Dict[str, Any]:
        if str(source).strip() != "canonical_report_payload":
            return {
                "accepted": False,
                "reason": "canonical_payload_required",
                "missing_fields": [],
                "platform": str(platform).strip().lower(),
            }

        missing_fields: List[str] = []
        required_string_fields = [
            "title",
            "business_impact_sentence",
            "boundary_cross_proof",
            "victim_impact",
            "remediation",
            "falsification_result",
        ]
        for field_name in required_string_fields:
            if not str(payload.get(field_name, "")).strip():
                missing_fields.append(field_name)
        reproduction_steps = payload.get("reproduction_steps", [])
        if not isinstance(reproduction_steps, list) or not any(str(step).strip() for step in reproduction_steps):
            missing_fields.append("reproduction_steps")
        goal_state_assertions = payload.get("goal_state_assertions")
        if not isinstance(goal_state_assertions, dict) or not any(bool(value) for value in goal_state_assertions.values()):
            missing_fields.append("goal_state_assertions")
        return {
            "accepted": not missing_fields,
            "reason": "ok" if not missing_fields else "missing_required_fields",
            "missing_fields": missing_fields,
            "platform": str(platform).strip().lower(),
        }


class PlatformAPI(ABC):
    """Abstract base for bug bounty platform APIs"""
    
    @abstractmethod
    async def create_draft(self, draft: ReportDraft) -> str:
        """
        Create report draft on platform
        
        Returns:
            Platform-specific reference (URL, ID, etc.)
        """
        pass
    
    @abstractmethod
    async def get_programs(self) -> List[Dict[str, Any]]:
        """Get list of accessible programs"""
        pass
    
    @abstractmethod
    async def get_program_scope(self, program_id: str) -> Dict[str, Any]:
        """Get program scope (in-scope/out-of-scope)"""
        pass


class HackerOneAPI(PlatformAPI):
    """
    HackerOne API integration
    
    Supports:
    - Report draft creation
    - Program scope retrieval
    - Severity mapping (CVSS-based)
    
    Note: Uses HackerOne API v1
    """
    
    def __init__(
        self,
        api_token: str,
        username: str,
        base_url: str = "https://api.hackerone.com/v1"
    ):
        self.api_token = api_token
        self.username = username
        self.base_url = base_url.rstrip("/")
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get authenticated session"""
        if self._session is None:
            auth = aiohttp.BasicAuth(self.username, self.api_token)
            self._session = aiohttp.ClientSession(
                base_url=self.base_url,
                auth=auth,
                headers={"Accept": "application/json"}
            )
        return self._session
    
    async def create_draft(self, draft: ReportDraft) -> str:
        """
        Create report draft on HackerOne
        
        Returns:
            Report URL for human review
        """
        session = await self._get_session()
        
        # Map to HackerOne report structure
        report_data = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": draft.title,
                    "vulnerability_information": draft.description,
                    "severity_rating": self._map_severity(draft.severity),
                }
            }
        }
        
        try:
            async with session.post(
                "/reports",
                json=report_data
            ) as response:
                if response.status == 201:
                    data = await response.json()
                    report_id = data.get("data", {}).get("id", "")
                    report_url = f"https://hackerone.com/reports/{report_id}"
                    
                    logger.info(f"Created HackerOne draft: {report_url}")
                    
                    return report_url
                else:
                    error_text = await response.text()
                    logger.error(f"HackerOne API error: {error_text}")
                    raise RuntimeError(f"HackerOne API error: {response.status}")
                    
        except Exception as e:
            logger.error(f"Failed to create HackerOne draft: {e}")
            raise
    
    def _map_severity(self, severity: str) -> int:
        """Map severity string to HackerOne rating"""
        mapping = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "informational": 0,
        }
        return mapping.get(severity.lower(), 2)
    
    async def get_programs(self) -> List[Dict[str, Any]]:
        """Get accessible programs"""
        session = await self._get_session()
        
        try:
            async with session.get("/me/programs") as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("data", [])
                return []
        except Exception as e:
            logger.error(f"Failed to get programs: {e}")
            return []
    
    async def get_program_scope(self, program_id: str) -> Dict[str, Any]:
        """Get program scope"""
        session = await self._get_session()
        
        try:
            async with session.get(
                f"/programs/{program_id}/structured_scopes"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("data", {})
                return {}
        except Exception as e:
            logger.error(f"Failed to get scope: {e}")
            return {}
    
    async def close(self):
        """Cleanup session"""
        if self._session:
            await self._session.close()
            self._session = None


class BugcrowdAPI(PlatformAPI):
    """
    Bugcrowd API integration
    
    Supports:
    - Submission creation (draft)
    - Program enumeration
    - Target scope retrieval
    """
    
    def __init__(
        self,
        api_token: str,
        base_url: str = "https://api.bugcrowd.com"
    ):
        self.api_token = api_token
        self.base_url = base_url.rstrip("/")
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get authenticated session"""
        if self._session is None:
            self._session = aiohttp.ClientSession(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Token {self.api_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/vnd.bugcrowd.v4+json"
                }
            )
        return self._session
    
    async def create_draft(self, draft: ReportDraft) -> str:
        """
        Create submission draft on Bugcrowd
        
        Returns:
            Submission URL for human review
        """
        session = await self._get_session()
        
        # Map to Bugcrowd submission structure
        submission_data = {
            "data": {
                "type": "submission",
                "attributes": {
                    "title": draft.title,
                    "description": draft.description,
                    "severity": self._map_severity(draft.severity),
                }
            }
        }
        
        try:
            async with session.post(
                "/submissions",
                json=submission_data
            ) as response:
                if response.status == 201:
                    data = await response.json()
                    submission_id = data.get("data", {}).get("id", "")
                    submission_url = f"https://bugcrowd.com/submissions/{submission_id}"
                    
                    logger.info(f"Created Bugcrowd draft: {submission_url}")
                    
                    return submission_url
                else:
                    error_text = await response.text()
                    logger.error(f"Bugcrowd API error: {error_text}")
                    raise RuntimeError(f"Bugcrowd API error: {response.status}")
                    
        except Exception as e:
            logger.error(f"Failed to create Bugcrowd draft: {e}")
            raise
    
    def _map_severity(self, severity: str) -> int:
        """Map severity string to Bugcrowd rating (1-5)"""
        mapping = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "informational": 1,
        }
        return mapping.get(severity.lower(), 3)
    
    async def get_programs(self) -> List[Dict[str, Any]]:
        """Get accessible programs"""
        session = await self._get_session()
        
        try:
            async with session.get("/programs") as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("data", [])
                return []
        except Exception as e:
            logger.error(f"Failed to get programs: {e}")
            return []
    
    async def get_program_scope(self, program_id: str) -> Dict[str, Any]:
        """Get program targets (scope)"""
        session = await self._get_session()
        
        try:
            async with session.get(
                f"/programs/{program_id}/targets"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("data", {})
                return {}
        except Exception as e:
            logger.error(f"Failed to get scope: {e}")
            return {}
    
    async def close(self):
        """Cleanup session"""
        if self._session:
            await self._session.close()
            self._session = None


class PlatformIntegrationManager:
    """
    Central platform integration manager
    
    - Multiple platform support
    - Program scope checking
    - Automated draft creation
    """
    
    def __init__(self):
        self._platforms: Dict[str, PlatformAPI] = {}
        self._program_cache: Dict[str, Dict[str, Any]] = {}
    
    def register_platform(self, name: str, api: PlatformAPI):
        """Register a platform API"""
        self._platforms[name] = api
        logger.info(f"Registered platform: {name}")
    
    async def create_draft_on_platform(
        self,
        platform: str,
        draft: ReportDraft,
        *,
        degradation_result: Optional[Dict[str, Any]] = None,
        component_status: Optional[Dict[str, str]] = None,
        audit_context: Optional[Dict[str, Any]] = None,
        canonical_payload: Optional[Dict[str, Any]] = None,
        replay_queue_path: Optional[Path] = None,
        auto_replay_on_recovery: bool = True,
        replay_limit: Optional[int] = None,
    ) -> str:
        """
        Create report draft on specified platform
        
        Returns:
            Platform URL for human review and submission
        """
        if platform not in self._platforms:
            raise ValueError(f"Unknown platform: {platform}")

        normalized_component_status = {
            str(key).strip(): str(value).strip().lower()
            for key, value in dict(component_status or {}).items()
            if str(key).strip()
        }
        normalized_degradation_result = dict(degradation_result or {})
        if (
            normalized_component_status.get("report_adapter") == "degraded"
            and bool(normalized_degradation_result.get("submit_blocked", False))
        ):
            if canonical_payload is None:
                raise ValueError("canonical_payload required before enqueueing report_adapter replay")
            enqueue_report_adapter_replay(
                platform=platform,
                canonical_payload=dict(canonical_payload),
                degradation_result=normalized_degradation_result,
                audit_context=dict(audit_context or {}),
                replay_queue_path=replay_queue_path,
            )
            emit_report_adapter_degradation_audit(
                component_status=normalized_component_status,
                degradation_result=normalized_degradation_result,
                audit_context=dict(audit_context or {}),
            )
            raise RuntimeError("report_adapter_degraded: platform submit blocked until replay is allowed")
        if (
            auto_replay_on_recovery
            and normalized_component_status.get("report_adapter") == "healthy"
        ):
            queue_records = load_report_adapter_replay_queue(replay_queue_path)
            has_pending = any(
                str(record.get("platform", "")).strip().lower() == str(platform).strip().lower()
                and str(record.get("replay_status", "")).strip().lower() == "pending"
                for record in queue_records
            )
            if has_pending:
                await self.replay_pending_submissions(
                    platform,
                    component_status=normalized_component_status,
                    replay_queue_path=replay_queue_path,
                    limit=replay_limit,
                )
        
        api = self._platforms[platform]
        
        # Create draft
        platform_url = await api.create_draft(draft)
        
        logger.info(
            f"Draft created on {platform}: {platform_url}"
        )
        
        return platform_url
    
    async def auto_select_platform(
        self,
        target_domain: str
    ) -> Optional[str]:
        """
        Auto-select platform based on target domain
        
        Checks which platform's programs include the target
        """
        for platform_name, api in self._platforms.items():
            try:
                programs = await api.get_programs()
                
                for program in programs:
                    program_id = program.get("id", "")
                    scope = await api.get_program_scope(program_id)
                    
                    # Check if target is in scope
                    # Simplified check - real implementation would parse scope
                    if self._is_in_scope(target_domain, scope):
                        return platform_name
                        
            except Exception as e:
                logger.warning(f"Failed to check {platform_name}: {e}")
        
        return None
    
    def _is_in_scope(self, target: str, scope: Dict[str, Any]) -> bool:
        """Check if target is in program scope"""
        # Simplified - real implementation would parse scope rules
        scope_str = str(scope).lower()
        return target.lower() in scope_str

    async def replay_pending_submissions(
        self,
        platform: str,
        *,
        component_status: Optional[Dict[str, str]] = None,
        replay_queue_path: Optional[Path] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        if platform not in self._platforms:
            raise ValueError(f"Unknown platform: {platform}")

        normalized_component_status = {
            str(key).strip(): str(value).strip().lower()
            for key, value in dict(component_status or {}).items()
            if str(key).strip()
        }
        if normalized_component_status.get("report_adapter") not in {"", "healthy"}:
            raise RuntimeError("report_adapter replay requires adapter_health_restored")

        records = load_report_adapter_replay_queue(replay_queue_path)
        replayed = 0
        failed = 0
        processed = 0
        api = self._platforms[platform]
        for record in records:
            if str(record.get("platform", "")).strip().lower() != str(platform).strip().lower():
                continue
            if str(record.get("replay_status", "")).strip().lower() != "pending":
                continue
            if limit is not None and processed >= int(limit):
                break

            payload = dict(record.get("canonical_report_payload", {}) or {})
            validation = ReportDraft.validate_platform_submission_payload(
                platform=platform,
                payload=payload,
                source="canonical_report_payload",
            )
            processed += 1
            if not validation.get("accepted", False):
                record["replay_status"] = "failed"
                record["replay_error"] = (
                    "canonical_payload invalid for replay: "
                    f"{validation.get('reason', 'invalid_payload')}"
                )
                failed += 1
                continue

            draft = ReportDraft.from_canonical_payload(payload)
            try:
                replay_url = await api.create_draft(draft)
            except Exception as exc:
                record["replay_status"] = "failed"
                record["replay_error"] = str(exc)
                failed += 1
                continue

            record["replay_status"] = "completed"
            record["replay_url"] = replay_url
            record["replayed_at"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
            replayed += 1

        store_report_adapter_replay_queue(records, replay_queue_path)
        return {
            "platform": str(platform).strip().lower(),
            "processed": processed,
            "replayed": replayed,
            "failed": failed,
            "queue_path": str(Path(replay_queue_path or _DEFAULT_REPLAY_QUEUE_PATH)),
        }
    
    async def submit_to_best_platform(
        self,
        draft: ReportDraft,
        target_domain: str,
        *,
        degradation_result: Optional[Dict[str, Any]] = None,
        component_status: Optional[Dict[str, str]] = None,
        audit_context: Optional[Dict[str, Any]] = None,
        canonical_payload: Optional[Dict[str, Any]] = None,
        replay_queue_path: Optional[Path] = None,
    ) -> Dict[str, str]:
        """
        Submit draft to best matching platform
        
        Returns:
            {"platform": "hackerone", "url": "https://...", "status": "draft_created"}
        """
        # Auto-select platform
        platform = await self.auto_select_platform(target_domain)
        
        if platform is None:
            # Default to first registered platform
            if self._platforms:
                platform = list(self._platforms.keys())[0]
            else:
                raise RuntimeError("No platforms registered")
        
        # Create draft
        url = await self.create_draft_on_platform(
            platform,
            draft,
            degradation_result=degradation_result,
            component_status=component_status,
            audit_context=audit_context,
            canonical_payload=canonical_payload,
            replay_queue_path=replay_queue_path,
        )
        
        return {
            "platform": platform,
            "url": url,
            "status": "draft_created",
            "note": "Human review and submission required"
        }


# Convenience functions

async def create_platform_manager(
    hackerone_token: Optional[str] = None,
    hackerone_username: Optional[str] = None,
    bugcrowd_token: Optional[str] = None,
) -> PlatformIntegrationManager:
    """
    Create platform manager with configured APIs
    
    Usage:
        manager = await create_platform_manager(
            hackerone_token="...",
            hackerone_username="...",
            bugcrowd_token="..."
        )
        
        result = await manager.submit_to_best_platform(draft, "example.com")
        # Returns: {"platform": "hackerone", "url": "https://..."}
    """
    manager = PlatformIntegrationManager()
    
    if hackerone_token and hackerone_username:
        h1 = HackerOneAPI(hackerone_token, hackerone_username)
        manager.register_platform("hackerone", h1)
    
    if bugcrowd_token:
        bc = BugcrowdAPI(bugcrowd_token)
        manager.register_platform("bugcrowd", bc)
    
    return manager


# Global instance
_platform_manager: Optional[PlatformIntegrationManager] = None


async def get_platform_manager() -> PlatformIntegrationManager:
    """Get or create global platform manager"""
    global _platform_manager
    if _platform_manager is None:
        # Create without credentials - must be configured
        _platform_manager = PlatformIntegrationManager()
    return _platform_manager
