"""
FindingNotificationRouter: Unified entry point for all Finding notifications.

Normalizes diverse input formats (Finding objects, dicts, result payloads)
into a canonical FindingNotificationDTO, deduplicates, and dispatches
to the Notifier.

Phase A (SGK-2026-0297): Discord全Finding詳細通知
"""
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import uuid4

from src.core.config.settings import get_settings
from src.core.notifications.notifier import BodyBuildError

logger = logging.getLogger(__name__)


@dataclass
class FindingNotificationDTO:
    """Canonical notification DTO. All finding inputs normalize to this."""

    # Required core fields
    finding_id: str = ""  # finding.id or generated fingerprint
    severity: str = "info"  # normalized: critical/high/medium/low/info
    vuln_type: str = "other"  # vulnerability type string
    title: str = ""  # finding title
    target_url: str = ""  # target URL
    description: str = ""  # description

    # Optional enriched fields
    impact: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    evidence_summary: str = ""  # safe, redacted evidence summary (NOT raw)
    confidence: float = 0.0
    source_agent: str = ""
    source_component: str = ""  # "master_conductor", "hunt", "watch"
    ingress_path: str = ""  # how it entered: "handle_finding", "process_findings"
    discovered_at: str = ""  # ISO 8601
    target_program: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

    # Metadata
    raw_severity: str = ""  # original severity value before normalization
    normalization_warning: str = ""  # set when severity was unknown

    @property
    def fingerprint(self) -> str:
        """Stable dedup fingerprint: vuln_type:title:target_url (empty-safe)."""
        v = (self.vuln_type or "").strip().lower()
        t = (self.title or "").strip().lower()
        u = (self.target_url or "").strip().lower()
        return f"{v}:{t}:{u}"


class FindingNotificationRouter:
    """
    Unified notification router for all Finding ingress paths.

    Responsibilities:
    - Normalize Finding/dict/result-payload → Canonical DTO
    - Run-local deduplication (by finding_id first, fingerprint fallback)
    - Source tagging (source_component, ingress_path)
    - JSONL structured logging

    Does NOT:
    - Build notification body (delegated entirely to Notifier.notify_finding() → JapaneseBodyBuilder)
    - Call notify CLI (delegated to Notifier)
    - Filter by severity (all severities pass through)
    """

    def __init__(self, run_id: str = "", notifier=None):
        self.run_id = run_id or f"run-{uuid4().hex[:8]}"
        self._notifier = notifier  # injected
        self._dedup_ids: set[str] = set()  # sent finding_ids
        self._dedup_fingerprints: set[str] = set()  # sent fingerprints
        self._stats: dict = {
            "total_normalized": 0,
            "total_sent": 0,
            "dedup_skipped": 0,
            "dto_failed": 0,
            "notify_failed": 0,
            "body_build_failures": 0,  # Phase C: body generation failures
        }

    @property
    def notifier(self):
        if self._notifier is None:
            from src.core.notifications.notifier import get_notifier

            self._notifier = get_notifier()
        return self._notifier

    # ================================================================
    # Normalization
    # ================================================================

    def normalize(
        self,
        finding_input,
        source_component: str = "",
        ingress_path: str = "",
    ) -> Optional[FindingNotificationDTO]:
        """
        Normalize any finding input to a FindingNotificationDTO.

        Accepts: Finding object, dict (result payload), dict (finding dict).
        Returns None only when input is completely unusable.
        """
        if finding_input is None:
            logger.debug("[%s] normalize received None input", self.run_id)
            self._stats["dto_failed"] += 1
            return None

        dto: Optional[FindingNotificationDTO] = None

        try:
            # 1. String input → unusable
            if isinstance(finding_input, str):
                logger.warning(
                    "[%s] normalize received string input, cannot process: %.100s",
                    self.run_id,
                    finding_input,
                )
                self._stats["dto_failed"] += 1
                return None

            # 2. Finding object → extract via to_dict()
            if hasattr(finding_input, "to_dict") and not isinstance(finding_input, dict):
                dto = self._normalize_from_finding(
                    finding_input,
                    source_component=source_component,
                    ingress_path=ingress_path,
                )

            # 3. Dict input
            elif isinstance(finding_input, dict):
                # 3a. Dict with 'finding' key → unwrap
                if "finding" in finding_input:
                    inner = finding_input["finding"]
                    if isinstance(inner, dict):
                        return self.normalize(inner, source_component, ingress_path)
                    elif hasattr(inner, "to_dict"):
                        dto = self._normalize_from_finding(
                            inner, source_component, ingress_path
                        )
                # 3b. Dict with 'data' → possibly unwrap findings
                elif "data" in finding_input:
                    data = finding_input["data"]
                    if isinstance(data, dict) and "findings" in data:
                        findings_list = data["findings"]
                        if isinstance(findings_list, list) and findings_list:
                            first = findings_list[0]
                            if isinstance(first, dict):
                                dto = self._normalize_from_dict(
                                    first, source_component, ingress_path
                                )
                            elif hasattr(first, "to_dict"):
                                dto = self._normalize_from_finding(
                                    first, source_component, ingress_path
                                )
                    elif isinstance(data, dict):
                        dto = self._normalize_from_dict(
                            data, source_component, ingress_path
                        )
                # 3c. Dict with 'findings' key → take first element
                elif "findings" in finding_input:
                    findings_list = finding_input["findings"]
                    if isinstance(findings_list, list) and findings_list:
                        first = findings_list[0]
                        if isinstance(first, dict):
                            dto = self._normalize_from_dict(
                                first, source_component, ingress_path
                            )
                        elif hasattr(first, "to_dict"):
                            dto = self._normalize_from_finding(
                                first, source_component, ingress_path
                            )
                # 3d. Plain finding dict → normalize directly
                else:
                    dto = self._normalize_from_dict(
                        finding_input, source_component, ingress_path
                    )

            if dto is not None:
                dto.source_component = source_component
                dto.ingress_path = ingress_path
                self._stats["total_normalized"] += 1

                # Structured log (JSONL)
                log_entry = json.dumps(
                    {
                        "event": "finding_normalized",
                        "run_id": self.run_id,
                        "finding_id": dto.finding_id,
                        "fingerprint": dto.fingerprint,
                        "severity": dto.severity,
                        "raw_severity": dto.raw_severity,
                        "vuln_type": dto.vuln_type,
                        "title": dto.title,
                        "source_component": dto.source_component,
                        "ingress_path": dto.ingress_path,
                        "normalization_warning": dto.normalization_warning,
                    },
                    ensure_ascii=False,
                )
                logger.info("[%s] %s", self.run_id, log_entry)
            else:
                self._stats["dto_failed"] += 1

            return dto

        except Exception:
            logger.exception(
                "[%s] Unexpected error during normalize() for input type=%s",
                self.run_id,
                type(finding_input).__name__,
            )
            self._stats["dto_failed"] += 1
            return None

    def _normalize_from_finding(
        self, finding, source_component="", ingress_path=""
    ) -> FindingNotificationDTO:
        """Normalize from a Finding dataclass object."""
        d = finding.to_dict() if hasattr(finding, "to_dict") else {}
        return self._normalize_from_dict(d, source_component, ingress_path)

    def _normalize_from_dict(
        self, data: dict, source_component="", ingress_path=""
    ) -> FindingNotificationDTO:
        """
        Normalize from a dict (agent output, result.data.findings, etc.).
        Handles field aliases.
        """
        if not isinstance(data, dict):
            data = {}

        # Core fields with alias handling
        finding_id = str(
            data.get("id") or data.get("finding_id") or ""
        )
        vuln_type = str(
            data.get("vuln_type") or data.get("type") or "other"
        )
        title = str(data.get("title") or "")
        description = str(data.get("description") or "")
        target_url = str(
            data.get("target_url") or data.get("target") or data.get("url") or ""
        )

        # Severity normalization
        raw_severity = str(
            data.get("severity") or data.get("raw_severity") or ""
        )
        normalized_severity, normalization_warning = self._normalize_severity(
            raw_severity
        )

        # Optional fields
        impact = str(data.get("impact") or "")
        confidence = _safe_float(data.get("confidence"), 0.0)
        source_agent = str(data.get("source_agent") or "")
        target_program = str(data.get("target_program") or "")
        cwe_id = data.get("cwe_id")
        cvss_score = _safe_float(data.get("cvss_score"), None)

        # discovered_at: ensure ISO string
        discovered_at_raw = data.get("discovered_at", "")
        discovered_at = _normalize_iso(discovered_at_raw)

        # Evidence → safe summary (no raw bodies/headers)
        evidence_summary = _build_evidence_summary(data.get("evidence"))

        # Reproduction steps: normalize to list
        reproduction_steps = _normalize_reproduction_steps(
            data.get("reproduction_steps")
        )

        dto = FindingNotificationDTO(
            finding_id=finding_id,
            severity=normalized_severity,
            vuln_type=vuln_type,
            title=title,
            target_url=target_url,
            description=description,
            impact=impact,
            reproduction_steps=reproduction_steps,
            evidence_summary=evidence_summary,
            confidence=confidence,
            source_agent=source_agent,
            source_component=source_component,
            ingress_path=ingress_path,
            discovered_at=discovered_at,
            target_program=target_program,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            raw_severity=raw_severity,
            normalization_warning=normalization_warning,
        )

        # If finding_id is empty, generate one from fingerprint
        if not dto.finding_id:
            import hashlib

            fp = dto.fingerprint
            dto.finding_id = f"gen-{hashlib.md5(fp.encode()).hexdigest()[:12]}"

        return dto

    def _normalize_severity(self, raw: str) -> tuple:
        """
        Normalize severity string. Returns (normalized, warning).

        Valid: critical/high/medium/low/info.
        Unknown → "info" with warning.
        """
        valid_severities = frozenset({"critical", "high", "medium", "low", "info"})

        if not raw or not raw.strip():
            return ("info", "Empty severity; normalized to info")

        cleaned = raw.strip().lower()

        if cleaned in valid_severities:
            return (cleaned, "")

        # Common aliases
        alias_map = {
            "severe": "critical",
            "urgent": "critical",
            "important": "high",
            "moderate": "medium",
            "minor": "low",
            "informational": "info",
            "notice": "info",
        }
        if cleaned in alias_map:
            normalized = alias_map[cleaned]
            return (
                normalized,
                f"Severity alias '{raw}' normalized to '{normalized}'",
            )

        return ("info", f"Unknown severity '{raw}' normalized to info")

    # ================================================================
    # Deduplication
    # ================================================================

    def should_send(self, dto: FindingNotificationDTO) -> bool:
        """
        Check if this DTO should be sent (not a duplicate).
        Returns True if new.

        Dedup order: finding_id first, then fingerprint fallback.
        """
        if not dto:
            return False

        if dto.finding_id and dto.finding_id in self._dedup_ids:
            return False

        if dto.fingerprint in self._dedup_fingerprints:
            return False

        return True

    def _mark_sent(self, dto: FindingNotificationDTO) -> None:
        """Record this DTO as sent for future dedup."""
        if dto.finding_id:
            self._dedup_ids.add(dto.finding_id)
        self._dedup_fingerprints.add(dto.fingerprint)

    # ================================================================
    # Batch Processing
    # ================================================================

    def process_batch(
        self,
        findings: list,
        source_component: str = "",
        ingress_path: str = "",
    ) -> list[FindingNotificationDTO]:
        """
        Process a batch: normalize all → dedup → return DTOs ready to send.
        Does NOT send notifications or mark as sent.
        Callers must iterate results and call route_and_notify() or notify
        directly to actually send.
        """
        dtos: list[FindingNotificationDTO] = []
        for raw in findings:
            dto = self.normalize(raw, source_component, ingress_path)
            if dto is None:
                self._stats["dto_failed"] += 1
                continue
            self._stats["total_normalized"] += 1
            if not self.should_send(dto):
                self._stats["dedup_skipped"] += 1
                continue
            dtos.append(dto)  # do NOT mark_sent here
        return dtos

    # ================================================================
    # Single-finding pipeline
    # ================================================================

    def route_and_notify(
        self,
        finding_input,
        source_component: str = "",
        ingress_path: str = "",
    ) -> dict:
        """
        Full single-finding pipeline: normalize → dedup → notify.

        Returns result dict with status information.
        """
        result = {
            "finding_id": None,
            "fingerprint": None,
            "normalized": False,
            "dedup_skipped": False,
            "notified": False,
            "error": None,
        }

        # Step 1: Normalize (skip re-normalization if input is already a DTO)
        if isinstance(finding_input, FindingNotificationDTO):
            dto = finding_input
            # Ensure source tagging
            if source_component and not dto.source_component:
                dto.source_component = source_component
            if ingress_path and not dto.ingress_path:
                dto.ingress_path = ingress_path
        else:
            dto = self.normalize(finding_input, source_component, ingress_path)
        if dto is None:
            result["error"] = "normalization_failed"
            return result

        result["finding_id"] = dto.finding_id
        result["fingerprint"] = dto.fingerprint
        result["normalized"] = True

        # Step 2: Dedup
        if not self.should_send(dto):
            result["dedup_skipped"] = True
            self._stats["dedup_skipped"] += 1
            logger.debug(
                "[%s] Dedup skipped: id=%s fp=%s",
                self.run_id,
                dto.finding_id,
                dto.fingerprint,
            )
            return result

        # Step 3: Check kill switch / dry run
        try:
            feat = get_settings().feature_notifications
        except Exception:
            feat = None

        kill_switch = False
        dry_run = False
        if feat is not None:
            kill_switch = getattr(feat, "notify_kill_switch", False)
            dry_run = getattr(feat, "notify_dry_run", False)

        if kill_switch:
            logger.warning(
                "[%s] notify_kill_switch active; blocking send for id=%s",
                self.run_id,
                dto.finding_id,
            )
            result["error"] = "kill_switch_active"
            return result

        # Step 4: Send via Notifier.notify_finding() (unified primary path)
        try:
            # If provider allowlist is set, explicitly pass the first allowed provider
            provider = None
            if self.notifier.provider_allowlist:
                provider = self.notifier.provider_allowlist[0]
            
            success = self.notifier.notify_finding(
                dto,
                run_id=self.run_id,
                source_component=dto.source_component or source_component,
                ingress_path=dto.ingress_path or ingress_path,
                provider=provider,
            )
            
            if success:
                result["notified"] = True
                self._mark_sent(dto)
                self._stats["total_sent"] += 1
                logger.info(
                    "[%s] Notified via notify_finding: id=%s title='%s' severity=%s",
                    self.run_id,
                    dto.finding_id,
                    dto.title,
                    dto.severity,
                )
            else:
                result["error"] = "notify_send_failed"
                self._stats["notify_failed"] += 1
                logger.warning(
                    "[%s] notify_finding failed for id=%s",
                    self.run_id,
                    dto.finding_id,
                )
        
        except BodyBuildError as e:
            result["error"] = f"body_build_failed:{e}"
            self._stats["body_build_failures"] += 1
            logger.error(
                "[%s] Body build failed for id=%s: %s",
                self.run_id,
                dto.finding_id,
                e,
            )
        except Exception as e:
            result["error"] = f"notify_exception:{e}"
            self._stats["notify_failed"] += 1
            logger.exception(
                "[%s] Exception during notify_finding for id=%s",
                self.run_id,
                dto.finding_id,
            )
        
        return result

    # ================================================================
    # Summary
    # ================================================================

    def get_summary(self) -> dict:
        """Return notification summary statistics for this run."""
        return {
            "run_id": self.run_id,
            **self._stats,
            "dedup_ids_count": len(self._dedup_ids),
            "dedup_fingerprints_count": len(self._dedup_fingerprints),
        }

    def get_kpi(self) -> dict:
        """
        Compute KPI metrics for this run.
        
        Returns dict with:
        - dedup_rate: dedup_skipped / (total_sent + dedup_skipped) as percentage
        - delivery_failure_rate: notify_failed / (total_sent + notify_failed) as percentage
        - body_build_failures: count of body generation failures
        - total_attempted: total_sent + notify_failed
        - total_normalized: total_normalized
        - dto_failures: dto_failed count
        
        KPI thresholds (plan SGK-2026-0297):
        - dedup_rate <= 5%: OK
        - delivery_failure_rate <= 10%: OK
        - redaction_leaks: 0 (must be zero - tracked via tests)
        - body_build_failures: 0 (must be zero)
        """
        total_sent = self._stats.get("total_sent", 0)
        dedup_skipped = self._stats.get("dedup_skipped", 0)
        notify_failed = self._stats.get("notify_failed", 0)
        total_normalized = self._stats.get("total_normalized", 0)
        dto_failed = self._stats.get("dto_failed", 0)
        body_build_failures = self._stats.get("body_build_failures", 0)
        
        # Dedup rate: dedup_skipped / (sent + dedup_skipped)
        total_through_dedup = total_sent + dedup_skipped
        dedup_rate = (dedup_skipped / total_through_dedup * 100) if total_through_dedup > 0 else 0.0
        
        # Delivery failure rate: notify_failed / (sent + notify_failed)
        total_delivery_attempts = total_sent + notify_failed
        delivery_failure_rate = (notify_failed / total_delivery_attempts * 100) if total_delivery_attempts > 0 else 0.0
        
        return {
            "run_id": self.run_id,
            "total_normalized": total_normalized,
            "total_sent": total_sent,
            "dedup_skipped": dedup_skipped,
            "dedup_rate_pct": round(dedup_rate, 2),
            "notify_failed": notify_failed,
            "delivery_failure_rate_pct": round(delivery_failure_rate, 2),
            "dto_failed": dto_failed,
            "body_build_failures": body_build_failures,
        }
    
    def check_kpi_thresholds(self) -> dict:
        """
        Check KPI metrics against plan thresholds.
        
        Returns dict with pass/fail status for each KPI.
        """
        kpi = self.get_kpi()
        issues = []
        
        # Dedup rate check (> 5% is a warning, > 20% is critical)
        if kpi["dedup_rate_pct"] > 20:
            issues.append({
                "kpi": "dedup_rate",
                "status": "critical",
                "value": kpi["dedup_rate_pct"],
                "threshold_pct": 20,
                "message": f"Dedup rate {kpi['dedup_rate_pct']}% exceeds critical threshold 20%",
            })
        elif kpi["dedup_rate_pct"] > 5:
            logger.warning(
                "[%s] KPI: dedup_rate=%.1f%% exceeds 5%% threshold (%d dedup'd of %d total)",
                self.run_id, kpi["dedup_rate_pct"], kpi["dedup_skipped"],
                kpi["total_sent"] + kpi["dedup_skipped"],
            )
        
        # Delivery failure check (> 10% is critical)
        if kpi["delivery_failure_rate_pct"] > 10:
            issues.append({
                "kpi": "delivery_failure_rate",
                "status": "critical",
                "value": kpi["delivery_failure_rate_pct"],
                "threshold_pct": 10,
                "message": f"Delivery failure rate {kpi['delivery_failure_rate_pct']}% exceeds threshold 10%",
            })
            logger.warning(
                "[%s] KPI: delivery_failure_rate=%.1f%% exceeds 10%% threshold (%d failed of %d attempted)",
                self.run_id, kpi["delivery_failure_rate_pct"], kpi["notify_failed"],
                kpi["total_sent"] + kpi["notify_failed"],
            )
        
        # Body build failures (must be 0)
        if kpi["body_build_failures"] > 0:
            issues.append({
                "kpi": "body_build_failures",
                "status": "critical",
                "value": kpi["body_build_failures"],
                "threshold": 0,
                "message": f"Body build failures: {kpi['body_build_failures']} (must be zero)",
            })
        
        # DTO failures
        if kpi["dto_failed"] > 0:
            logger.warning(
                "[%s] KPI: dto_failed=%d - some findings could not be normalized",
                self.run_id, kpi["dto_failed"],
            )
        
        return {
            "run_id": self.run_id,
            "kpi": kpi,
            "passed": len(issues) == 0,
            "issues": issues,
        }

    def reset_dedup(self):
        """Clear dedup state (for testing)."""
        self._dedup_ids.clear()
        self._dedup_fingerprints.clear()


# ================================================================
# Module-level helpers
# ================================================================


def _safe_float(value, default):
    """Safely convert value to float, returning default on failure."""
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_iso(value) -> str:
    """Normalize a datetime value to ISO 8601 string."""
    if not value:
        return ""
    if isinstance(value, str):
        return value
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    return str(value)


def _build_evidence_summary(evidence) -> str:
    """
    Build a safe evidence summary from evidence data.
    Does NOT include raw request/response bodies or headers.
    """
    if evidence is None:
        return ""

    # Evidence can be a dict or an Evidence dataclass
    if isinstance(evidence, dict):
        d = evidence
    elif hasattr(evidence, "to_dict"):
        d = evidence.to_dict()
    else:
        return ""

    parts = []
    req_url = d.get("request_url", "") or d.get("url", "")
    req_method = d.get("request_method", "") or d.get("method", "")
    resp_status = d.get("response_status", "") or d.get("status", "")

    if req_method and req_url:
        parts.append(f"{req_method} {req_url}")
    elif req_url:
        parts.append(req_url)

    if resp_status:
        parts.append(f"→ HTTP {resp_status}")

    # Include screenshot path if present
    screenshot = d.get("screenshot_path", "")
    if screenshot:
        parts.append(f"📸 {screenshot}")

    return " | ".join(parts) if parts else ""


def _normalize_reproduction_steps(steps) -> List[str]:
    """Normalize reproduction_steps to a list of strings."""
    if steps is None:
        return []
    if isinstance(steps, list):
        return [str(s) for s in steps if s]
    if isinstance(steps, str):
        # Split on newlines, keep non-empty lines
        return [s.strip() for s in steps.split("\n") if s.strip()]
    return []


def _severity_icon(severity: str) -> str:
    """Return emoji icon for severity level."""
    icons = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "🔵",
    }
    return icons.get(severity, "⚪")
